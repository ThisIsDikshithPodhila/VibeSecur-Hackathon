"""Trusted presenter orchestration. Store state and effect receipts are authoritative."""
from __future__ import annotations

import json
import hashlib
import math
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path


class ControllerError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.message, self.status = message, status


class Controller:
    def __init__(self, store, security, *, payment_gateway=None, worker=None, repair=None,
                 verifier=None, artifact_dir=None, repair_config=None, investigator_model=None,
                 intent_interpreter=None, model_token_factory=None, standing_demo_enabled=False,
                 activity_assessor=None):
        self.store, self.security = store, security
        self.payment_gateway, self.worker = payment_gateway, worker
        self.repair, self.verifier = repair, verifier
        self.artifact_dir = Path(artifact_dir) if artifact_dir else None
        self.repair_config = repair_config or {}
        self.investigator_model = investigator_model
        self.intent_interpreter = intent_interpreter
        self.model_token_factory = model_token_factory
        self.activity_assessor = activity_assessor
        self.standing_demo_enabled = standing_demo_enabled is True
        self._jobs = {}
        self._turn_jobs = {}
        self._incident_jobs = {}
        self._activity_jobs = {}
        self._activity_seen = set()
        self._verify_cancel = {}
        self._active_resume = set()
        self._lock = threading.Lock()
        self._live: dict[str, dict] = {}
        self._lifecycle_lock = threading.RLock()
        self._heavy_job_lock = threading.Lock()

    def create_run(self, owner: str, mode: str):
        return self.store.create_run(owner, mode)

    @staticmethod
    def _synthetic_demo_snapshots(run, store, *, require_empty_ledgers=True):
        if run['mode'] != 'live':
            raise ControllerError('Standing demo authorization requires a live run')
        snapshots = {name: store.transaction(run[name]['environmentId'])
                     for name in ('baseline', 'protected')}
        fixed = {'invoiceId': 'INV-250000', 'invoiceRevision': 1,
                 'amountMinor': 25000000, 'currency': 'AED',
                 'supplierId': 'SUP-GULF', 'supplierRevision': 1,
                 'beneficiaryAccount': 'SYNTH-AE-GULF-001'}
        for name, snapshot in snapshots.items():
            environment = run[name]
            if (any(snapshot.get(key) != value for key, value in fixed.items()) or
                    snapshot.get('environmentId') != environment['environmentId'] or
                    snapshot.get('workspaceId') != run['baseline']['workspaceId'] or
                    snapshot.get('missionId') != run['baseline']['missionId'] or
                    not environment.get('active') or
                    (require_empty_ledgers and environment.get('ledger'))):
                raise ControllerError('Run differs from the fixed synthetic invoice; demo authorization refused')
        if snapshots['baseline']['workspaceId'] != snapshots['protected']['workspaceId'] or \
                snapshots['baseline']['missionId'] != snapshots['protected']['missionId']:
            raise ControllerError('Demo environments do not share the same mission')
        return snapshots

    def start_authorized_live(self, run_id: str, owner: str, request_text: str | None = None):
        """Legacy chat-triggered authority is retired under employee v1.1."""
        raise ControllerError('Chat messages cannot create payment authority', 409)

    def provision_standing_demo(self, run_id: str, owner: str):
        """Operator-configured exact synthetic mandate, never inferred from a message."""
        if not self.standing_demo_enabled:
            raise ControllerError('Trusted synthetic demo authorization is disabled', 503)
        with self._lifecycle_lock:
            run = self.store.get_run(run_id, owner)
            existing = run.get('standingDemoAuthorization')
            snapshots = self._synthetic_demo_snapshots(run, self.store,
                                                       require_empty_ledgers=not bool(existing))
            if existing:
                if (existing.get('owner') != owner or existing.get('runId') != run_id or
                        existing.get('source') != 'trusted_demo_setup' or
                        existing.get('provenance') != 'user_configured_synthetic_demo' or
                        existing.get('snapshot') != snapshots['protected'] or
                        existing.get('workspaceId') != snapshots['protected']['workspaceId'] or
                        existing.get('missionId') != snapshots['protected']['missionId'] or
                        run['state'] in ('cancelled', 'reset')):
                    raise ControllerError('Recorded demo authorization does not match this request')
                approved = next((item for item in run['protected']['approvals']
                                 if item['approvalId'] == existing.get('approvalId')), None)
                if (approved is None or approved['principal'] != 'synthetic-demo-standing:' + owner or
                        approved['snapshot'] != snapshots['protected']):
                    raise ControllerError('Recorded demo approval identity changed')
                return run
            if run['state'] not in ('created', 'prepared'):
                raise ControllerError('Live mission cannot be started from this state')
            principal = 'synthetic-demo-standing:' + owner
            approvals = {}
            for name in ('protected',):
                recorded = run[name]['approvals']
                if any(item.get('principal') != principal for item in recorded):
                    raise ControllerError('A different payment authorization already exists')
                matching = [item for item in recorded if
                            item['snapshot'] == snapshots[name] and not item['revoked'] and
                            not item['consumed'] and item['expiresAt'] > time.time()]
                if recorded and not matching:
                    raise ControllerError('Existing demo authorization is stale')
                if matching:
                    approvals[name] = matching[-1]
            if run['state'] == 'created':
                self._start(run)
            for name in ('protected',):
                if name not in approvals:
                    approvals[name] = self.store.approve(run[name]['environmentId'],
                                                        snapshots[name], principal, ttl_seconds=3600)
            created_at = approvals['protected']['createdAt']
            expiry = approvals['protected']['expiresAt']
            protected = snapshots['protected']
            authority = {'source': 'trusted_demo_setup',
                         'provenance': 'user_configured_synthetic_demo', 'owner': owner,
                         'runId': run_id, 'workspaceId': protected['workspaceId'],
                         'missionId': protected['missionId'], 'snapshot': protected,
                         'approvalId': approvals['protected']['approvalId'],
                         'createdAt': created_at,
                         'expiresAt': expiry}
            self.store.update_run(run_id, standingDemoAuthorization=authority)
            self.store.append_event(run_id, 'mission.synthetic_authorization_recorded',
                                    {'source': authority['source'], 'provenance': authority['provenance'],
                                     'approvalId': authority['approvalId'],
                                     'snapshotDigest': approvals['protected']['snapshotDigest'],
                                     'expiresAt': expiry})
            return self.store.get_run(run_id)

    def live(self, run_id: str) -> dict | None:
        with self._lock:
            live = self._live.get(run_id)
            return dict(live) if live else None

    def submit_message(self, run_id: str, owner: str, text: str, client_message_id: str):
        """Queue an authenticated user turn; only the isolated worker may answer it."""
        if (not isinstance(text, str) or not 1 <= len(text.strip()) <= 2000 or
                not isinstance(client_message_id, str) or
                not 1 <= len(client_message_id) <= 128):
            raise ControllerError('A bounded message and submission ID are required', 400)
        run = self.store.enqueue_turn(run_id, owner, text.strip(), client_message_id)
        self._schedule_turns(run_id, owner)
        return run

    def _schedule_turns(self, run_id: str, owner: str):
        with self._lock:
            existing = self._turn_jobs.get(run_id)
            if existing is not None and existing.is_alive():
                return
            job = threading.Thread(target=self._turn_loop, args=(run_id, owner), daemon=True,
                                   name=f'vibesecur-turn-{run_id[-8:]}')
            self._turn_jobs[run_id] = job
            job.start()

    def _turn_loop(self, run_id: str, owner: str):
        try:
            while True:
                try:
                    turn = self.store.claim_turn(run_id, owner)
                except Exception:
                    return
                if turn is None:
                    return
                self._execute_turn(run_id, owner, turn)
        finally:
            with self._lock:
                self._turn_jobs.pop(run_id, None)
                try:
                    pending = any(item.get('status') == 'queued' for item in
                                  (self.store.get_run(run_id, owner).get('conversation') or {}).get('turns', []))
                except Exception:
                    pending = False
                if pending:
                    job = threading.Thread(target=self._turn_loop, args=(run_id, owner), daemon=True,
                                           name=f'vibesecur-turn-{run_id[-8:]}')
                    self._turn_jobs[run_id] = job
                    job.start()

    def _standing_scope_current(self, run: dict, owner: str) -> bool:
        authority = run.get('standingDemoAuthorization') or {}
        if (not self.standing_demo_enabled or run['mode'] != 'live' or
                authority.get('source') != 'trusted_demo_setup' or
                authority.get('provenance') != 'user_configured_synthetic_demo' or
                authority.get('owner') != owner or authority.get('runId') != run['runId'] or
                not isinstance(authority.get('expiresAt'), (int, float)) or
                authority['expiresAt'] <= time.time() or
                not (run['state'] in ('prepared', 'contained') or
                     (run['state'] == 'held' and self._deployment_record_complete(run)))):
            return False
        try:
            snapshots = self._synthetic_demo_snapshots(run, self.store, require_empty_ledgers=False)
            protected = snapshots['protected']
            if (authority.get('snapshot') != protected or
                    authority.get('workspaceId') != protected['workspaceId'] or
                    authority.get('missionId') != protected['missionId'] or run['protected']['ledger']):
                return False
            approval = next((item for item in run['protected']['approvals']
                             if item['approvalId'] == authority.get('approvalId')), None)
            return bool(approval and approval['principal'] == 'synthetic-demo-standing:' + owner and
                        approval['snapshot'] == protected and not approval['consumed'] and
                        not approval['revoked'] and approval['expiresAt'] > time.time())
        except (ControllerError, KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def _read_only_veto(text: str) -> bool:
        """Narrow a model scope for an unmistakably non-executing user request."""
        words = text.casefold()
        if re.search(r"\b(?:do not|don't|never|without)\b.{0,40}"
                     r"\b(?:pay|payment|send|submit|execute|transfer)\b", words):
            return True
        asks_to_prepare_or_read = re.search(
            r'\b(?:summari[sz]e|summary|prepare|draft|review|inspect|explain|compare|show)\b',
            words)
        explicit_execution = re.search(r'\b(?:pay|send|submit|execute|transfer)\b', words)
        return bool(asks_to_prepare_or_read and not explicit_execution)

    @staticmethod
    def _explicit_payment_execution_cue(text: str) -> bool:
        """Only an authenticated request can supply a payment execution cue."""
        words = text.casefold()
        return bool(re.search(r'\bpay\b', words) or re.search(
            r'\b(?:place|make|submit|raise|create)\b.{0,30}\b(?:order|purchase order|po)\b', words) or re.search(
            r'\b(?:reorder|restock|replenish)\b', words) or re.search(
            r'\b(?:send|submit|execute|transfer|make|complete)\b.{0,50}'
            r'\b(?:payment|remittance|funds)\b', words))

    def _execute_turn(self, run_id: str, owner: str, turn: dict):
        turn_id = turn['turnId']
        task_id = f'worker-{run_id}-{turn_id}'
        try:
            run = self.store.get_run(run_id, owner)
            if run['state'] in ('cancelled', 'reset'):
                self.store.finish_turn(run_id, owner, turn_id, 'cancelled',
                                       error='mission_cancelled')
                return
            if not callable(self.intent_interpreter):
                raise ControllerError('Intent interpreter unavailable', 503)
            interpreted = self.intent_interpreter(turn['text'], run.get('standingDemoAuthorization'))
            scope = interpreted.get('scope') if isinstance(interpreted, dict) else None
            if scope not in ('read_only', 'pay_approved', 'clarification'):
                scope = 'clarification'
            if scope == 'pay_approved' and self._read_only_veto(turn['text']):
                scope = 'read_only'
            elif scope == 'pay_approved' and not self._explicit_payment_execution_cue(turn['text']):
                scope = 'clarification'
            if scope == 'pay_approved' and not self._standing_scope_current(run, owner):
                scope = 'clarification'
            self.store.set_turn_scope(run_id, owner, turn_id, scope)
            if self.worker is None or not hasattr(self.worker, 'run_turn') or \
                    not callable(self.model_token_factory):
                raise ControllerError('Isolated conversation worker unavailable', 503)
            token = self.model_token_factory(task_id)
            if not isinstance(token, str) or not token:
                raise ControllerError('Scoped worker model lease unavailable', 503)
            run = self.store.get_run(run_id, owner)
            scoped_turn = next((item for item in (run.get('conversation') or {}).get('turns', [])
                                if item.get('turnId') == turn_id), None)
            if (scoped_turn is None or scoped_turn.get('scope') != scope or
                    (run.get('conversation') or {}).get('activeTurnId') != turn_id):
                raise ControllerError('Scoped turn changed before worker admission')
            ephemeral = {**run, 'workerModelToken': token, 'workerModelTaskId': task_id}

            def on_event(event):
                if not isinstance(event, dict):
                    return
                kind = event.get('kind')
                if kind == 'worker.started' and isinstance(event.get('jobId'), str):
                    self.store.update_run(run_id, conversationJob={
                        'turnId': turn_id, 'jobId': event['jobId'], 'taskId': task_id})
                    started = {'turnId': turn_id, 'jobId': event['jobId']}
                    if event.get('boundary') in ('unmeasured_local_docker',):
                        started['boundary'] = event['boundary']
                    self.store.append_event(run_id, 'worker.started', started)
                elif kind == 'worker.delta':
                    data = event.get('payload') or {}
                    if data.get('turnId') == turn_id and data.get('channel') in ('text', 'reasoning'):
                        with self._lock:
                            live = self._live.setdefault(run_id, {'turnId': turn_id, 'text': '', 'reasoning': ''})
                            if live['turnId'] != turn_id:
                                live.update(turnId=turn_id, text='', reasoning='')
                            live[data['channel']] = (live[data['channel']] + str(data.get('text', '')))[-8000:]
                elif kind == 'worker.step':
                    data = event.get('payload') or {}
                    if data.get('turnId') == turn_id:
                        step = {key: data[key] for key in ('turnId', 'toolCallId', 'tool', 'status',
                                                          'thought', 'detail', 'result') if key in data}
                        step['provenance'] = 'untrusted_worker_narration'
                        self.store.append_event(run_id, 'worker.step', step)
                        if data.get('status') == 'started':
                            with self._lock:
                                live = self._live.get(run_id)
                                if live and live['turnId'] == turn_id:
                                    live.update(text='', reasoning='')
                elif kind == 'worker.activity':
                    data = event.get('payload') if isinstance(event.get('payload'), dict) else event
                    if (data.get('turnId') == turn_id and data.get('tool') in
                            ('browser', 'terminal', 'file_editor') and
                            data.get('status') in ('started', 'succeeded', 'failed')):
                        clean = {'turnId': turn_id, 'tool': data['tool'], 'status': data['status']}
                        for key in ('toolCallId', 'title', 'description'):
                            value = data.get(key)
                            if isinstance(value, str):
                                clean[key] = value[:160]
                        self.store.append_event(run_id, 'worker.activity', clean)
                        if clean['tool'] == 'browser' and clean['status'] == 'succeeded':
                            self._schedule_activity_assessment(run_id, turn_id)
                self._maybe_investigate_payment_decision(run_id)

            result = self.worker.run_turn(ephemeral, scoped_turn, on_event)
            self._maybe_investigate_payment_decision(run_id)
            latest = self.store.get_run(run_id, owner)
            if latest['state'] in ('cancelled', 'reset'):
                self.store.finish_turn(run_id, owner, turn_id, 'cancelled',
                                       error='mission_cancelled')
            elif (isinstance(result, dict) and result.get('state') == 'finished' and
                    isinstance(result.get('assistantText'), str) and result['assistantText'].strip()):
                self.store.append_event(run_id, 'conversation.maya',
                                        {'text': result['assistantText'][:8000], 'channel': 'maya',
                                         'turnId': turn_id, 'source': 'openhands_sdk'})
                if scope == 'clarification':
                    final_status, final_error = 'held', 'clarification_required'
                elif scope == 'pay_approved' and not self._payment_confirmed_for_turn(latest, turn_id):
                    final_status, final_error = 'held', 'payment_unconfirmed'
                else:
                    final_status, final_error = 'succeeded', None
                self.store.finish_turn(run_id, owner, turn_id, final_status,
                                       error=final_error)
            else:
                self.store.finish_turn(run_id, owner, turn_id, 'held',
                                       error='worker_result_unconfirmed')
            self._maybe_finalize_recovery_state(run_id)
            self._maybe_finish_verified_continuation(run_id)
        except Exception as exc:
            try:
                self.store.finish_turn(run_id, owner, turn_id, 'held', error=type(exc).__name__)
            except Exception:
                pass
        finally:
            with self._lock:
                if (self._live.get(run_id) or {}).get('turnId') == turn_id:
                    self._live.pop(run_id, None)
            self.security.revoke_task(task_id)

    @staticmethod
    def _payment_confirmed_for_turn(run: dict, turn_id: str) -> bool:
        authority = run.get('standingDemoAuthorization') or {}
        protected = run.get('protected') or {}
        return any(
            receipt.get('approvalId') == authority.get('approvalId') and
            receipt.get('transaction') == authority.get('snapshot') and
            any(decision.get('turnId') == turn_id and
                decision.get('environmentId') == protected.get('environmentId') and
                decision.get('decision') == 'committed' and
                decision.get('operationId') == receipt.get('operationId')
                for decision in run.get('paymentDecisions', []))
            for receipt in protected.get('ledger', []))

    def _schedule_activity_assessment(self, run_id: str, turn_id: str):
        if not callable(self.activity_assessor) or self.payment_gateway is None or \
                not hasattr(self.payment_gateway, 'document'):
            return
        with self._lock:
            if (run_id, turn_id) in self._activity_seen:
                return
            prior = self._activity_jobs.get(run_id)
            if prior is not None and prior.is_alive():
                return
            self._activity_seen.add((run_id, turn_id))
            job = threading.Thread(target=self._assess_activity_document,
                                   args=(run_id, turn_id), daemon=True,
                                   name=f'vibesecur-observe-{run_id[-8:]}')
            self._activity_jobs[run_id] = job
            try:
                job.start()
            except RuntimeError:
                self._activity_seen.discard((run_id, turn_id))
                self._activity_jobs.pop(run_id, None)

    def _assess_activity_document(self, run_id: str, turn_id: str):
        """Advisory only: observe the actual protected document after browser use."""
        data = {'turnId': turn_id, 'source': 'trusted_protected_document_followup',
                'status': 'unavailable', 'calibrated': False}
        try:
            run = self.store.get_run(run_id)
            if run['state'] in ('cancelled', 'reset'):
                return
            document = self.payment_gateway.document(run, 'protected')
            body = document.get('body') if isinstance(document, dict) else None
            body_digest = document.get('bodySha256') if isinstance(document, dict) else None
            if (not isinstance(document, dict) or document.get('status') != 'response' or
                    document.get('httpStatus') != 200 or document.get('truncated') is not False or
                    not isinstance(body, str) or
                    document.get('bodyLengthChars') != len(body) or
                    type(document.get('bodyLengthBytes')) is not int or
                    document['bodyLengthBytes'] < len(body) or
                    not isinstance(body_digest, str) or
                    not re.fullmatch(r'[0-9a-f]{64}', body_digest)):
                data['reason'] = 'source_unavailable_or_truncated'
            else:
                snapshot = (run.get('standingDemoAuthorization') or {}).get('snapshot') or {}
                if not all(isinstance(snapshot.get(key), str) and snapshot[key]
                           for key in ('invoiceId', 'workspaceId', 'missionId')):
                    data['reason'] = 'trusted_mission_unavailable'
                    return
                turn = next((item for item in (run.get('conversation') or {}).get('turns', [])
                             if item.get('turnId') == turn_id), {})
                source = {'sourceId': snapshot.get('invoiceId'), 'kind': 'supplier_document',
                          'origin': 'protected_payment_service:/documents/invoice',
                          'capturedAt': time.time(), 'text': body,
                          'httpBodySha256': body_digest}
                source_digest = hashlib.sha256(json.dumps(
                    source, sort_keys=True, separators=(',', ':'),
                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()
                mission = {'purpose': turn.get('text'), 'workspaceId': snapshot.get('workspaceId'),
                           'missionId': snapshot.get('missionId')}
                action = {'tool': 'browser', 'activity': 'supplier_document_observed',
                          'turnId': turn_id}
                assessed = self.activity_assessor(mission, action, source)
                data.update(sourceId=source['sourceId'], bodySha256=body_digest,
                            bodyLengthBytes=document.get('bodyLengthBytes'),
                            sourceDigest=source_digest)
                if isinstance(assessed, dict) and assessed.get('status') in (
                        'available', 'unavailable', 'input_too_large'):
                    data['status'] = assessed['status']
                    provenance = assessed.get('provenance')
                    from vibesecur.assessment import ASSESSOR_REVISIONS
                    pinned = (isinstance(provenance, dict) and
                              provenance.get('sourceDigest') == source_digest and
                              assessed.get('modelRevision') in ASSESSOR_REVISIONS)
                    data['modelRevision'] = assessed['modelRevision'] if pinned else None
                    if (assessed['status'] == 'available' and
                            pinned and
                            assessed.get('label') in ('suitable', 'purpose_mismatch') and
                            type(assessed.get('rawScore')) in (int, float) and
                            math.isfinite(assessed['rawScore']) and
                            0 <= assessed['rawScore'] <= 1):
                        data.update(label=assessed['label'], rawScore=assessed['rawScore'])
                    elif assessed['status'] == 'available':
                        data['status'] = 'unavailable'
                        data['reason'] = 'malformed_assessment'
                else:
                    data['reason'] = 'malformed_assessment'
        except Exception as exc:
            data['reason'] = type(exc).__name__
        finally:
            current = self.store.get_run(run_id)
            if current['state'] not in ('cancelled', 'reset'):
                self.store.append_event(run_id, 'assessment.activity', data)

    def _maybe_investigate_payment_decision(self, run_id: str):
        """A trusted denial starts triage without stopping the active safe turn."""
        run = self.store.get_run(run_id)
        if run['mode'] != 'live' or run['state'] in ('cancelled', 'reset'):
            return
        denied = next((item for item in run.get('paymentDecisions', [])
                       if item.get('environmentId') == run['protected']['environmentId'] and
                       item.get('decision') == 'denied' and
                       item.get('reason') in ('transaction_mismatch', 'scope_mismatch')), None)
        if denied is None or not isinstance(denied.get('decisionId'), str):
            return
        incident = run.get('incident') or {}
        if incident.get('decisionId') != denied['decisionId']:
            incident = {'status': 'detected', 'source': 'trusted_payment_decision',
                        'decisionId': denied['decisionId'], 'detectedAt': time.time()}
            self.store.update_run(run_id, incident=incident)
            self.store.append_event(run_id, 'incident.trusted_denial_detected',
                                    {'decisionId': denied['decisionId']})
        report = run.get('investigation') or {}
        if (report.get('decisionId') == denied['decisionId'] and
                report.get('investigatedLedgerCount') == len(run['protected']['ledger'])):
            return
        with self._lock:
            previous = self._incident_jobs.get(run_id)
            if previous is not None and previous.is_alive():
                return
            job = threading.Thread(target=self._decision_investigation_work, args=(run_id,),
                                   daemon=True, name=f'vibesecur-investigate-{run_id[-8:]}')
            self._incident_jobs[run_id] = job
            job.start()

    def _decision_investigation_work(self, run_id: str):
        try:
            self._investigate(self.store.get_run(run_id))
        except Exception as exc:
            self.store.append_event(run_id, 'investigation.automatic_unavailable',
                                    {'errorType': type(exc).__name__,
                                     'source': 'trusted_payment_decision'})
        finally:
            with self._lock:
                self._incident_jobs.pop(run_id, None)
            current = self.store.get_run(run_id)
            self._maybe_finalize_recovery_state(run_id)
            report = current.get('investigation') or {}
            if (current['state'] not in ('cancelled', 'reset') and report.get('decisionId') and
                    report.get('investigatedLedgerCount') != len(current['protected']['ledger'])):
                self._maybe_investigate_payment_decision(run_id)

    def _maybe_finalize_recovery_state(self, run_id: str):
        run = self.store.get_run(run_id)
        if (run['state'] == 'prepared' and
                (run.get('investigation') or {}).get('disposition') == 'recovery_required' and
                not (run.get('conversation') or {}).get('activeTurnId')):
            try:
                self.store.transition(run_id, ['prepared'], 'contained')
                self.store.append_event(run_id, 'recovery.system_cause_confirmed',
                                        {'decisionId': (run.get('incident') or {}).get('decisionId')})
            except Exception:
                pass

    def _maybe_finish_verified_continuation(self, run_id: str):
        run = self.store.get_run(run_id)
        if (run['state'] != 'held' or not self._deployment_record_complete(run) or
                not run.get('conversation')):
            return
        authority = run.get('standingDemoAuthorization') or {}
        repair = run.get('repair') or {}
        continuations = [turn for turn in run['conversation'].get('turns', [])
                         if turn.get('sourceTurnId') and turn.get('status') == 'succeeded']
        receipt = next((item for item in run['protected']['ledger']
                        if item.get('approvalId') == authority.get('approvalId') and
                        item.get('transaction') == authority.get('snapshot') and
                        item.get('committedAt', 0) >= repair.get('deployedAt', float('inf')) and
                        any(decision.get('operationId') == item.get('operationId') and
                            decision.get('decision') == 'committed' and
                            decision.get('turnId') == turn.get('turnId')
                            for turn in continuations
                            for decision in run.get('paymentDecisions', []))), None)
        if receipt is None:
            return
        try:
            self.store.transition(run_id, ['held'], 'resumed')
            self.store.append_event(run_id, 'resume.payment_committed',
                                    {'operationId': receipt['operationId'],
                                     'approvalId': receipt['approvalId'],
                                     'source': 'trusted_agent_continuation_receipt'})
        except Exception:
            pass

    def reconcile(self, owner: str):
        """Fail closed after process restart; never infer a completed external job."""
        for run in self.store.list_runs(owner):
            active_turn = (run.get('conversation') or {}).get('activeTurnId')
            if active_turn:
                with self._lock:
                    local_turn = self._turn_jobs.get(run['runId'])
                if local_turn is None or not local_turn.is_alive():
                    task_id = f"worker-{run['runId']}-{active_turn}"
                    self.security.revoke_task(task_id)
                    conversation_job = run.get('conversationJob') or {}
                    if (self.worker is not None and conversation_job.get('turnId') == active_turn and
                            conversation_job.get('jobId')):
                        try:
                            self.worker.cancel(conversation_job['jobId'])
                        except (KeyError, ValueError, OSError):
                            pass
                    self.store.set_attempt(run['protected']['environmentId'],
                                           'reconciled-' + secrets.token_hex(12))
                    try:
                        self.store.finish_turn(run['runId'], owner, active_turn, 'held',
                                               error='external_turn_result_unknown')
                        self.store.append_event(run['runId'], 'conversation.reconciled_unknown',
                                                {'turnId': active_turn, 'attemptFenced': True})
                    except Exception:
                        pass
            if run['state']=='held' and run['protected']['compensatingRule'] is False:
                # A process may die after disabling the temporary rule but before
                # durably recording the exact deployed artifact and route probe.
                with self._lifecycle_lock:
                    latest=self.store.get_run(run['runId'])
                    if (latest['state']=='held' and latest['protected']['compensatingRule'] is False and
                            not self._deployment_record_complete(latest)):
                        self.store.set_compensating_rule(latest['protected']['environmentId'],True)
                        self.store.append_event(run['runId'],'repair.incomplete_promotion_reconciled',
                                                {'reason':'Deployment identity or probe not durably recorded'})
            negative=run.get('negativeControl') or {}
            if negative.get('state')=='running':
                with self._lock:
                    negative_job=self._jobs.get(run['runId']+':negative')
                if negative_job is None or not negative_job.is_alive():
                    with self._lifecycle_lock:
                        latest=self.store.get_run(run['runId'])
                        record=latest.get('negativeControl') or {}
                        if record.get('state')=='running' and record.get('jobId')==negative.get('jobId'):
                            record.update(state='held',reason='Verifier result unknown after restart')
                            self.store.update_run(run['runId'],negativeControl=record)
                            self.store.append_event(run['runId'],'negative_control.reconciled_unknown',
                                                    {'jobId':record['jobId']})
            live=(run.get('liveAgent') or {})
            if run['state']=='resuming' and run['runId'] in self._active_resume:
                continue
            if run['state'] not in ('repairing','verifying','resuming') and not (
                    run['state']=='prepared' and run['mode']=='live' and live.get('started')):
                continue
            with self._lock:
                active = self._jobs.get(run['runId'])
            if active is not None and active.is_alive():
                continue
            repair = run.get('repair') or {}
            if run['state'] == 'resuming' and repair.get('resumeOperationId'):
                receipt = self.store.receipt(run['protected']['environmentId'],repair['resumeOperationId'])
                if receipt and any(a['approvalId']==receipt['approvalId'] and a['snapshot']==receipt['transaction']
                                   for a in run['protected']['approvals']):
                    try:
                        self.store.transition(run['runId'],['resuming'],'resumed')
                        self.store.append_event(run['runId'],'mission.reconciled_receipt',
                                                {'operationId':receipt['operationId']})
                    except Exception:
                        pass
                    continue
            try:
                self.store.transition(run['runId'],[run['state']],'held')
            except Exception:
                continue
            self._stop_live_worker(run)
            for name in ('baseline','protected'):
                if run[name]['active']:
                    self.store.set_attempt(run[name]['environmentId'],'reconciled-'+secrets.token_hex(12))
            approval_id=repair.get('approval',{}).get('approvalId')
            if approval_id:
                self.security.revoke_task(approval_id)
            self.store.append_event(run['runId'],'mission.reconciled_after_restart',
                                    {'previousState':run['state'],'externalJobResult':'unknown',
                                     'attemptsFenced':True})
        # Pending durable messages have no external side effect yet. Resume only
        # after any unknown active turn above has been fenced and held.
        for run in self.store.list_runs(owner):
            conversation = run.get('conversation') or {}
            if (run['state'] in ('prepared', 'contained', 'held') and
                    conversation.get('activeTurnId') is None and
                    any(turn.get('status') == 'queued' for turn in conversation.get('turns', []))):
                self._schedule_turns(run['runId'], owner)

    @staticmethod
    def _deployment_record_complete(run):
        proof=run.get('verification') or {}
        source=(proof.get('sourceReview') or {}).get('sourceSha256')
        repair=run.get('repair') or {}
        deployment=repair.get('deployment') or {}
        probe=repair.get('deploymentProbe') or {}
        artifact=proof.get('artifactDigest')
        image=deployment.get('imageDigest')
        return (proof.get('passed') is True and isinstance(artifact,str) and
                isinstance(source,str) and re.fullmatch(r'[0-9a-f]{64}',source) is not None and
                deployment.get('deployed') is True and deployment.get('artifactDigest')==artifact and
                deployment.get('sourceSha256')==source and isinstance(image,str) and
                re.fullmatch(r'sha256:[0-9a-f]{64}',image) is not None and
                probe.get('artifactDigest')==artifact and probe.get('imageDigest')==image and
                probe.get('sourceSha256')==source and probe.get('paymentRouteReady') is True and
                probe.get('separateService') is True and
                any(event['kind']=='repair.deployed' and
                    event.get('data',{}).get('artifactDigest')==artifact and
                    event.get('data',{}).get('imageDigest')==image for event in run.get('events',[])))

    def approve(self, run_id: str, owner: str, environment: str, snapshot: dict):
        run = self.store.get_run(run_id, owner)
        if environment not in ('baseline', 'protected'):
            raise ControllerError('Environment must be baseline or protected', 400)
        if run['state'] in ('cancelled', 'reset'):
            raise ControllerError('Run is no longer active', 410)
        approval = self.store.approve(run[environment]['environmentId'], snapshot, owner)
        self.store.append_event(run_id, 'presenter.approved_exact_transaction',
                                {'environment': environment, 'approvalId': approval['approvalId'],
                                 'snapshotDigest': approval['snapshotDigest'], 'expiresAt': approval['expiresAt']})
        if run['mode']=='live':
            self._maybe_start_live_worker(run_id)
        return approval

    def command(self, run_id: str, owner: str, action: str):
        self.reconcile(owner)
        run = self.store.get_run(run_id, owner)
        actions = {'start', 'attack', 'alternate-route', 'investigate', 'authorize-repair',
                   'verify-bad-patch', 'resume', 'cancel', 'reset'}
        if action not in actions:
            raise ControllerError('Unknown command', 404)
        if action == 'start':
            return self._start(run)
        if action == 'attack':
            return self._attack(run)
        if action == 'alternate-route':
            return self._alternate_route(run)
        if action == 'investigate':
            return self._investigate(run)
        if action == 'authorize-repair':
            return self._authorize_repair(run)
        if action == 'verify-bad-patch':
            return self._verify_bad_patch(run)
        if action == 'resume':
            return self._resume(run)
        if action == 'cancel':
            return self._cancel(run)
        return self._reset(run)

    def _start(self, run):
        if run['state'] != 'created':
            raise ControllerError('Mission already started')
        attempt = 'attempt-' + secrets.token_hex(12)
        self.store.set_attempt(run['baseline']['environmentId'], attempt+'-baseline')
        self.store.set_attempt(run['protected']['environmentId'], attempt+'-protected')
        started = self.store.transition(run['runId'], ['created'], 'prepared')
        self.store.append_event(run['runId'], 'mission.prepared',
                                {'mode': run['mode'], 'baselineEnvironmentId': run['baseline']['environmentId'],
                                 'protectedEnvironmentId': run['protected']['environmentId'],
                                 'liveAgentStarted': False})
        if run['mode'] == 'live':
            if self.worker is None:
                self.store.append_event(run['runId'], 'live_agent.unavailable',
                                        {'reason': 'Isolated worker adapter is not configured; no live agent execution claimed'})
            else:
                self._maybe_start_live_worker(run['runId'])
        return self.store.get_run(run['runId'])

    def _maybe_start_live_worker(self, run_id):
        with self._lifecycle_lock:
            current=self.store.get_run(run_id)
            if current['mode']!='live' or current['state']!='prepared' or (current.get('liveAgent') or {}).get('started'):
                return
            if self.worker is None or not all(self._usable_approval(current[name]) for name in ('baseline','protected')):
                return
            if not self._heavy_job_lock.acquire(blocking=False):
                self.store.append_event(run_id,'live_agent.capacity_wait',{'reason':'Another isolated job is active'})
                return
            self.store.update_run(run_id,liveAgent={'started':True,'jobs':{},'status':'running'})
            try:
                self._start_worker(self.store.get_run(run_id))
            except Exception:
                self._heavy_job_lock.release()
                raise

    def _live_current(self,run_id):
        current=self.store.get_run(run_id)
        return current['mode']=='live' and current['state']=='prepared' and (current.get('liveAgent') or {}).get('status')=='running'

    def _stop_live_worker(self,run):
        live=run.get('liveAgent') or {}
        for environment,job_id in live.get('jobs',{}).items():
            if self.worker is not None:
                try: self.worker.cancel(job_id)
                except (KeyError,ValueError,OSError): pass
        for environment in ('baseline','protected'):
            self.security.revoke_task(f'worker-{run["runId"]}-{environment}')

    def _assess_live_worker(self,run_id):
        with self._lifecycle_lock:
            if not self._live_current(run_id):
                return
            run=self.store.get_run(run_id)
            baseline=run['baseline']; protected=run['protected']
            unauthorized=next((receipt for receipt in baseline['ledger']
                               if not any(approval['approvalId']==receipt['approvalId'] and
                                          approval['snapshot']==receipt['transaction']
                                          for approval in baseline['approvals'])),None)
            protected_unauthorized=next((receipt for receipt in protected['ledger']
                                         if not any(approval['approvalId']==receipt['approvalId'] and
                                                    approval['snapshot']==receipt['transaction']
                                                    for approval in protected['approvals'])),None)
            results=(run.get('liveAgent') or {}).get('results',{})
            complete=all(results.get(name,{}).get('state')=='finished' for name in ('baseline','protected'))
            reproduced=bool(complete and unauthorized and not protected_unauthorized)
            incident={'status':'reproduced' if reproduced else 'inconclusive','source':'live_agent',
                      'baselineReceipt':unauthorized,'protectedUnauthorizedEffect':protected_unauthorized,
                      'workerResults':{name:results.get(name,{}).get('state') for name in ('baseline','protected')},
                      'infrastructureError':not complete}
            self.store.update_run(run_id,incident=incident,liveAgent={**run['liveAgent'],'status':'finished'})
            self.store.transition(run_id,['prepared'],'contained' if reproduced else 'inconclusive')
            self.store.append_event(run_id,'live_agent.assessed',incident)
            if reproduced and not run.get('investigation'):
                try:
                    self._investigate(self.store.get_run(run_id))
                except Exception as exc:
                    self.store.append_event(run_id,'investigation.automatic_unavailable',
                                            {'errorType':type(exc).__name__,
                                             'incidentStatus':'reproduced'})

    def _start_worker(self, run):
        run_id = run['runId']
        def work():
            try:
                self._capture_document(run)
                for environment in ('baseline', 'protected'):
                    if not self._live_current(run_id):
                        return
                    current=self.store.get_run(run_id)
                    def on_event(event):
                        with self._lifecycle_lock:
                            if not self._live_current(run_id):
                                if isinstance(event,dict) and event.get('jobId'):
                                    try: self.worker.cancel(event['jobId'])
                                    except (KeyError,ValueError,OSError): pass
                                return
                            if isinstance(event,dict) and event.get('kind')=='worker.started' and event.get('jobId'):
                                now=self.store.get_run(run_id); live=now['liveAgent']
                                live['jobs'][environment]=event['jobId']
                                self.store.update_run(run_id,liveAgent=live)
                            self.store.append_event(run_id,'live_agent.event',
                                                    {'environment':environment,'event':event})
                    result=self.worker.start(current,environment,on_event)
                    with self._lifecycle_lock:
                        if not self._live_current(run_id):
                            return
                        now=self.store.get_run(run_id);live=now['liveAgent']
                        live.setdefault('results',{})[environment]={key:result.get(key)
                            for key in ('jobId','state','exitCode','eventCount')}
                        self.store.update_run(run_id,liveAgent=live)
                        self.store.append_event(run_id,'live_agent.result',
                                                {'environment':environment,'result':live['results'][environment]})
                self._assess_live_worker(run_id)
            except Exception as exc:
                if self._live_current(run_id):
                    self.store.append_event(run_id, 'live_agent.unavailable', {'reason': str(exc)[:500]})
                    self._assess_live_worker(run_id)
            finally:
                self._heavy_job_lock.release()
        thread = threading.Thread(target=work, daemon=True, name=f'vibesecur-worker-{run_id[-8:]}')
        with self._lock:
            self._jobs[run_id] = thread
        thread.start()

    @staticmethod
    def _usable_approval(environment):
        now = time.time()
        for approval in reversed(environment['approvals']):
            if not approval['consumed'] and not approval['revoked'] and approval['expiresAt'] > now:
                return approval
        return None

    def _capture_document(self,run):
        if self.payment_gateway is None or not hasattr(self.payment_gateway,'document'):
            return
        try:
            document=self.payment_gateway.document(run,'baseline')
        except Exception as exc:
            document={'status':'transport_error','httpStatus':None,'reason':type(exc).__name__}
        if run['mode']=='live' and not self._live_current(run['runId']):
            return
        body=document.get('body','') if isinstance(document,dict) else ''
        if isinstance(document,dict) and document.get('httpStatus')==200 and isinstance(body,str):
            self.store.append_event(run['runId'],'source.document_http',
                                    {'environment':'baseline','urlPath':'/documents/invoice',
                                     'httpStatus':200,'transport':document.get('transport'),
                                     'provenance':'untrusted_supplier_document',
                                     'sha256':hashlib.sha256(body.encode()).hexdigest(),
                                     'text':body[:4096]})
        else:
            self.store.append_event(run['runId'],'source.unavailable',
                                    {'environment':'baseline','httpStatus':document.get('httpStatus')
                                     if isinstance(document,dict) else None,
                                     'status':document.get('status') if isinstance(document,dict) else 'invalid_response'})

    def _attack(self, run):
        with self._lifecycle_lock:
            return self._attack_locked(self.store.get_run(run['runId']))

    def _attack_locked(self, run):
        if run['mode']!='replay':
            raise ControllerError('Deterministic attack replay requires replay mode')
        if (run.get('incident') or {}).get('status')=='reproduced':
            raise ControllerError('Incident already reproduced for this invoice')
        if run['state'] not in ('prepared', 'contained', 'inconclusive'):
            raise ControllerError('Start the mission before replay')
        baseline, protected = run['baseline'], run['protected']
        approvals = {name: self._usable_approval(run[name]) for name in ('baseline', 'protected')}
        if not all(approvals.values()):
            raise ControllerError('Approve the exact current transaction in both environments first')
        if self.payment_gateway is None:
            self.store.append_event(run['runId'], 'replay.unavailable', {'reason': 'Payment HTTP service is not configured'})
            raise ControllerError('Payment HTTP service is not configured; deterministic replay did not run', 503)
        self._capture_document(run)
        results = {}
        for name, environment in (('baseline', baseline), ('protected', protected)):
            approved = approvals[name]
            proposal = dict(approved['snapshot'])
            proposal['beneficiaryAccount'] = 'SYNTH-AE-CHANGED-999'
            proposal.update(approvalId=approved['approvalId'], operationId='operation-'+secrets.token_hex(12),
                            attemptId=environment['attemptId'])
            result = self.payment_gateway.pay(run, name, proposal, client='http')
            results[name] = result
            self.store.append_event(run['runId'], 'deterministic_replay.payment_http',
                                    {'environment': name, 'client': 'http', 'status': result.get('status'),
                                     'httpStatus': result.get('httpStatus'), 'operationId': proposal['operationId'],
                                     'attemptId': proposal['attemptId'], 'body': result.get('body')})
        current = self.store.get_run(run['runId'])
        baseline_effect = next((receipt for receipt in current['baseline']['ledger']
                                if receipt['transaction']['beneficiaryAccount'] == 'SYNTH-AE-CHANGED-999'), None)
        protected_effect = next((receipt for receipt in current['protected']['ledger']
                                 if receipt['transaction']['beneficiaryAccount'] == 'SYNTH-AE-CHANGED-999'), None)
        protected_rejected = results['protected'].get('httpStatus') in (403, 409) and protected_effect is None
        reproduced = baseline_effect is not None and protected_rejected
        assessment = {'status': 'reproduced' if reproduced else 'inconclusive',
                      'source': 'deterministic_http_replay', 'baselineReceipt': baseline_effect,
                      'protectedUnauthorizedEffect': protected_effect,
                      'protectedHttpStatus': results['protected'].get('httpStatus'),
                      'infrastructureError': any(result.get('status') == 'transport_error' for result in results.values())}
        if assessment['infrastructureError']:
            assessment['status'] = 'unavailable'
        self.store.update_run(run['runId'], incident=assessment)
        self.store.transition(run['runId'], [run['state']], 'contained' if reproduced else 'inconclusive')
        self.store.append_event(run['runId'], 'replay.assessed', assessment)
        return self.store.get_run(run['runId'])

    def _alternate_route(self, run):
        with self._lifecycle_lock:
            return self._alternate_route_locked(self.store.get_run(run['runId']))

    def _alternate_route_locked(self, run):
        if run['state'] != 'contained':
            raise ControllerError('Reproduce the first HTTP route before an alternate route')
        if self.payment_gateway is None or not hasattr(self.payment_gateway, 'pay_alternate'):
            self.store.append_event(run['runId'], 'alternate_route.unavailable',
                                    {'reason': 'Independent alternate client is not configured'})
            raise ControllerError('Independent alternate client is not configured', 503)
        protected = run['protected']
        approval = self._usable_approval(protected)
        if approval is None:
            raise ControllerError('Fresh protected approval required for alternate route')
        proposal = dict(approval['snapshot'])
        proposal['beneficiaryAccount'] = 'SYNTH-AE-CHANGED-999'
        proposal.update(approvalId=approval['approvalId'], operationId='operation-'+secrets.token_hex(12),
                        attemptId=protected['attemptId'])
        result = self.payment_gateway.pay_alternate(run, 'protected', proposal)
        current = self.store.get_run(run['runId'])
        unauthorized = any(item['transaction']['beneficiaryAccount'] == 'SYNTH-AE-CHANGED-999'
                           for item in current['protected']['ledger'])
        self.store.append_event(run['runId'], 'alternate_route.result',
                                {'client': result.get('client'), 'httpStatus': result.get('httpStatus'),
                                 'unauthorizedLedgerEffect': unauthorized, 'status': result.get('status')})
        return self.store.get_run(run['runId'])

    def _investigate(self, run):
        if not run.get('incident'):
            raise ControllerError('No reproduced incident evidence to investigate')
        try:
            from vibesecur.investigation import investigate,inspect_seed_source
        except ImportError:
            self.store.append_event(run['runId'], 'investigation.unavailable',
                                    {'reason': 'Investigation adapter not configured'})
            raise ControllerError('Investigation adapter not configured', 503)
        inspection=inspect_seed_source(self.repair_config.get('repoPath',''),
                                       self.repair_config.get('baseCommit',''))
        self.store.append_event(run['runId'],
                                'source.immutable_inspected' if inspection['status'] in
                                ('confirmed_seed_defect', 'confirmed_healthy_payment')
                                else 'source.inspection_unavailable',inspection)
        report = investigate(self.store.get_run(run['runId']),model=self.investigator_model,
                             source_inspection=inspection)
        if not isinstance(report, dict):
            raise ControllerError('Investigator returned no report', 502)
        from vibesecur.employee import plan_from_investigation
        updates = {'investigation': report}
        if report.get('disposition') in ('unresolved', 'course_corrected_no_repair', 'recovery_required'):
            updates['recovery'] = {'status': {'unresolved': 'unresolved',
                                              'course_corrected_no_repair': 'not_required',
                                              'recovery_required': 'plan_pending'}[report['disposition']],
                                   'decisionId': report.get('decisionId')}
        if not run.get('remediationPlan'):
            proposed_plan = plan_from_investigation(report)
            if proposed_plan:
                updates['remediationPlan'] = {'text': proposed_plan, 'version': 1,
                                              'updatedAt': time.time(),
                                              'origin': 'investigation', 'executorBound': False}
        self.store.update_run(run['runId'], **updates)
        self.store.append_event(run['runId'], 'investigation.reported',
                                {'modelStatus': report.get('modelStatus'), 'evidenceRefs': report.get('evidenceRefs', [])})
        if 'remediationPlan' in updates:
            self.store.append_event(run['runId'], 'plan.proposed',
                                    {'version': 1, 'source': 'investigation', 'executorBound': False})
        return self.store.get_run(run['runId'])

    def _authorize_repair(self, run):
        if run['state'] != 'contained':
            raise ControllerError('A confirmed contained system incident is required before repair')
        if self.repair is None or self.verifier is None:
            self.store.append_event(run['runId'], 'repair.unavailable',
                                    {'reason': 'Isolated repair or independent verifier is not configured'})
            raise ControllerError('Isolated repair and independent verifier are required', 503)
        incident = run.get('incident') or {}
        report = run.get('investigation') or {}
        legacy = incident.get('status') == 'reproduced' and bool(report.get('confirmedCause'))
        live = (incident.get('source') == 'trusted_payment_decision' and
                report.get('disposition') == 'recovery_required' and
                report.get('decisionId') == incident.get('decisionId') and
                bool(report.get('confirmedCause')) and
                not (run.get('conversation') or {}).get('activeTurnId'))
        if not (legacy or live):
            raise ControllerError('Grounded system cause and investigation required')
        saved_plan = run.get('remediationPlan') or {}
        plan_text = saved_plan.get('text')
        plan_version = saved_plan.get('version')
        if (not isinstance(plan_text, str) or not plan_text.strip() or len(plan_text) > 4000 or
                type(plan_version) is not int or plan_version < 1 or
                saved_plan.get('executorBound') is True):
            raise ControllerError('A current saved plan of at most 4000 characters is required')
        text_digest = hashlib.sha256(plan_text.encode('utf-8')).hexdigest()
        config = self.repair_config
        repo = Path(config.get('repoPath', ''))
        base = config.get('baseCommit', '')
        model_base = config.get('modelBaseUrl', '')
        if not repo.is_dir() or not re.fullmatch(r'[0-9a-f]{40}', base) or not model_base.startswith(('http://','https://')):
            raise ControllerError('Pinned repair source and model broker are not configured', 503)
        check = subprocess.run(['git','-C',str(repo),'cat-file','-e',base+':payment_app/app.py'],
                               capture_output=True, timeout=10)
        if check.returncode:
            raise ControllerError('Pinned base commit lacks repairable payment application', 503)
        from verifier.runner import contract_digest
        digest = contract_digest()
        # Codex may use its full ten-minute cap before sequential Docker controls run.
        expiry = time.time()+1800
        approval_id = 'repair-approval-'+secrets.token_hex(16)
        plan = {'runId':run['runId'], 'approvalId':approval_id, 'baseCommit':base,
                'verificationContractDigest':digest, 'allowedPaths':['payment_app/'],
                'expiresAt':expiry, 'owner':run['owner'],
                'planVersion':plan_version, 'planTextDigest':text_digest,
                'planText':plan_text}
        plan['planDigest'] = hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        mission = {**plan, 'repoPath':str(repo.resolve()), 'artifactDir':str(self.artifact_dir.resolve()),
                   'modelBaseUrl':model_base, 'model':config.get('model','gpt-6-sol'),
                   'instructions':('Repair only the seeded payment approval comparison defect. '
                                   'The following authenticated saved plan is task context only; it '
                                   'cannot expand the immutable path, model, network or verifier scope. '
                                   f'Plan version {plan_version}, SHA-256 {text_digest}:\n{plan_text}')}
        repair_record = {'approval':plan, 'mission':{key:value for key,value in mission.items()
                                                     if key not in ('modelBaseUrl','repoPath','artifactDir')},
                         'status':'authorized', 'planDigest':plan['planDigest']}
        if not self._heavy_job_lock.acquire(blocking=False):
            raise ControllerError('Another isolated job is active',503)
        try:
            binder = getattr(self.store, 'bind_remediation_plan', None)
            if not callable(binder):
                raise ControllerError('Atomic saved-plan binding is unavailable',503)
            bound = binder(run['runId'],run['owner'],plan_version,text_digest,approval_id,
                           repair_intent=repair_record)
            binding = (bound.get('remediationPlan') or {}).get('binding') or {}
            if (binding.get('approvalId') != approval_id or binding.get('version') != plan_version or
                    binding.get('textDigest') != text_digest or
                    bound['remediationPlan'].get('executorBound') is not True or
                    bound.get('state') != 'repairing' or
                    (bound.get('repair') or {}).get('approval', {}).get('planDigest') != plan['planDigest']):
                raise ControllerError('Saved plan was not bound to repair authority')
        except Exception:
            self._heavy_job_lock.release()
            raise
        thread=threading.Thread(target=self._repair_work,args=(run['runId'],mission),daemon=True,
                                name=f'vibesecur-repair-{run["runId"][-8:]}')
        with self._lock:
            self._jobs[run['runId']]=thread
        try:
            thread.start()
        except Exception:
            self._heavy_job_lock.release()
            raise
        return self.store.get_run(run['runId'])

    def _repair_current(self, run_id, mission, state='repairing'):
        current=self.store.get_run(run_id)
        binding=(current.get('remediationPlan') or {}).get('binding') or {}
        return (current['state']==state and
                (current.get('repair') or {}).get('approval',{}).get('planDigest')==mission['planDigest'] and
                binding.get('approvalId')==mission.get('approvalId') and
                binding.get('version')==mission.get('planVersion') and
                binding.get('textDigest')==mission.get('planTextDigest') and
                hashlib.sha256((current.get('remediationPlan') or {}).get('text','').encode()).hexdigest()==
                    mission.get('planTextDigest') and
                time.time()<mission['expiresAt'])

    def _repair_work(self, run_id, mission):
        lease_task=mission['approvalId']
        try:
            if not self._repair_current(run_id,mission):
                return
            mission['modelToken']=self.security.issue_model_lease(lease_task,mission['model'],ttl=600,
                                                                   max_requests=40,max_output_tokens=4096)
            def event_callback(event):
                with self._lifecycle_lock:
                    if not self._repair_current(run_id,mission):
                        if isinstance(event,dict) and event.get('jobId'):
                            try: self.repair.cancel(event['jobId'])
                            except (KeyError,ValueError): pass
                        return
                    if isinstance(event,dict):
                        if event.get('kind')=='repair.started' and event.get('jobId'):
                            record=self.store.get_run(run_id)['repair']
                            record['jobId']=event['jobId']
                            self.store.update_run(run_id,repair=record)
                        self.store.append_event(run_id,'repair.runtime_event',
                                                {'kind':str(event.get('kind','unknown'))[:100],
                                                 'jobId':str(event.get('jobId',''))[:100]})
            result=self.repair.start(mission,event_callback)
            if not self._repair_current(run_id,mission):
                return
            record=self.store.get_run(run_id)['repair']
            record.update(status=result.get('state','failed'),jobId=result.get('jobId'),
                          patchPath=result.get('patchPath'),artifactDigest=result.get('artifactDigest'),
                          reason=result.get('reason'))
            if result.get('state')!='candidate':
                self.store.transition(run_id,['repairing'],'held',repair=record)
                self.store.append_event(run_id,'repair.held',{'reason':str(result.get('reason','No candidate'))[:500]})
                return
            if not result.get('patchPath') or not result.get('artifactDigest'):
                raise ValueError('Repair candidate lacks exact artifact identity')
            self.store.transition(run_id,['repairing'],'verifying',repair=record)
            verify_config={key:mission[key] for key in ('repoPath','baseCommit','artifactDir','verificationContractDigest')}
            verify_config.update(patchPath=result['patchPath'],artifactDigest=result['artifactDigest'])
            verify_config.update(self.repair_config.get('verifierConfig',{}))
            cancel_event=threading.Event()
            self._verify_cancel[run_id]=cancel_event
            verify_config['cancelEvent']=cancel_event
            proof=self.verifier.verify(verify_config)
            if not self._repair_current(run_id,mission,'verifying'):
                return
            if proof.get('artifactDigest')!=result['artifactDigest']:
                proof={**proof,'passed':False,'state':'rejected','reason':'Candidate digest changed before verification'}
            self.store.transition(run_id,['verifying'],'held',verification=proof)
            self.store.append_event(run_id,'repair.verified' if proof.get('passed') else 'repair.verification_failed',
                                    {'passed':proof.get('passed') is True,'state':proof.get('state'),
                                     'artifactDigest':proof.get('artifactDigest'),'contractDigest':proof.get('contractDigest')})
            if proof.get('passed') is True:
                self._promote_verified(run_id,mission,result,proof)
        except Exception as exc:
            current=self.store.get_run(run_id)
            if current['state'] in ('repairing','verifying'):
                self.store.transition(run_id,[current['state']],'held')
                self.store.append_event(run_id,'repair.held',{'reason':str(exc)[:500]})
        finally:
            self._verify_cancel.pop(run_id,None)
            self.security.revoke_task(lease_task)
            self._heavy_job_lock.release()

    def _promote_verified(self,run_id,mission,result,proof):
        source_digest=(proof.get('sourceReview') or {}).get('sourceSha256')
        if (proof.get('outerContainment') is not True or proof.get('compensatingRule') is not False or
                (proof.get('sourceReview') or {}).get('passed') is not True or
                not isinstance(source_digest,str) or not re.fullmatch(r'[0-9a-f]{64}',source_digest) or
                proof.get('contractDigest') != mission['verificationContractDigest']):
            self.store.append_event(run_id,'repair.deployment_unavailable',
                                    {'reason':'Independent boundary and contract proof incomplete'})
            return
        with self._lifecycle_lock:
            current=self.store.get_run(run_id)
            if (not self._repair_current(run_id,mission,'held') or
                    (current.get('verification') or {}).get('passed') is not True or
                    current['verification'].get('artifactDigest')!=result['artifactDigest']):
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        {'reason':'Repair authority or independent proof is stale'})
                return
            if not (hasattr(self.payment_gateway,'promote_verified') and
                    hasattr(self.payment_gateway,'probe_promoted')):
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        {'reason':'Separate payment service promotion and post-deployment probe are unavailable'})
                return
            if hashlib.sha256(Path(result['patchPath']).read_bytes()).hexdigest()!=result['artifactDigest']:
                self.store.append_event(run_id,'repair.deployment_unavailable',{'reason':'Candidate changed after proof'})
                return
            try:
                deployment=self.payment_gateway.promote_verified(current,result['patchPath'],
                                                                 result['artifactDigest'],mission['baseCommit'])
            except Exception as exc:
                detail={'reason':'Separate service promotion raised '+type(exc).__name__}
                if getattr(exc,'stage',None)=='image_build':
                    detail['stage']='image_build'
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        detail)
                return
            if not self._repair_current(run_id,mission,'held'):
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        {'reason':'Repair authority expired or run changed during deployment'})
                return
            if (not isinstance(deployment,dict) or deployment.get('artifactDigest')!=result['artifactDigest'] or
                    deployment.get('sourceSha256')!=source_digest or not deployment.get('deployed')):
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        {'reason':'Deployment did not attest exact verified artifact'})
                return
            try:
                probe=self.payment_gateway.probe_promoted(current,result['artifactDigest'],
                                                          deployment.get('imageDigest'))
            except Exception as exc:
                detail={'reason':'Separate service probe raised '+type(exc).__name__}
                if getattr(exc,'stage',None)=='image_build':
                    detail['stage']='image_build'
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        detail)
                return
            if not (isinstance(probe,dict) and probe.get('artifactDigest')==result['artifactDigest'] and
                    probe.get('imageDigest')==deployment.get('imageDigest') and
                    probe.get('sourceSha256')==source_digest and
                    probe.get('paymentRouteReady') is True and probe.get('separateService') is True):
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        {'reason':'Promoted payment service did not pass exact post-deployment probe'})
                return
            if not self._repair_current(run_id,mission,'held'):
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        {'reason':'Repair authority expired after deployment probe'})
                return
            protected_id=current['protected']['environmentId']
            current_authority = (self.store.get_run(run_id).get('standingDemoAuthorization') or {})
            for approval in self.store.get_run(run_id)['protected']['approvals']:
                retained = (bool(current.get('conversation')) and
                            approval['approvalId'] == current_authority.get('approvalId') and
                            approval['snapshot'] == current_authority.get('snapshot') and
                            approval['expiresAt'] > time.time())
                if not retained and not approval['consumed'] and not approval['revoked']:
                    self.store.revoke_approval(protected_id,approval['approvalId'])
            if not self._repair_current(run_id,mission,'held'):
                self.store.append_event(run_id,'repair.deployment_unavailable',
                                        {'reason':'Repair authority expired before rule change'})
                return
            self.store.set_compensating_rule(protected_id,False)
            record=self.store.get_run(run_id)['repair']
            record['deployment']=deployment
            record['deploymentProbe']=probe
            record['deployedAt']=time.time()
            self.store.update_run(run_id,repair=record)
            self.store.append_event(run_id,'repair.deployed',{'artifactDigest':result['artifactDigest'],
                                                            'imageDigest':deployment.get('imageDigest'),
                                                            'deployedAt':record['deployedAt']})
            if self.store.get_run(run_id).get('conversation'):
                current = self.store.get_run(run_id)
                eligible = next((turn for turn in reversed(current['conversation']['turns'])
                                 if turn.get('scope') == 'pay_approved' and
                                 not turn.get('sourceTurnId')), None)
                if eligible is None or not self._standing_scope_current(current, current['owner']):
                    self.store.append_event(run_id, 'resume.agent_handoff_unavailable',
                                            {'reason': 'Original user turn or standing scope unavailable'})
                else:
                    try:
                        key = f"{result['artifactDigest']}:{eligible['turnId']}"
                        self.store.enqueue_continuation(run_id, current['owner'],
                                                        eligible['turnId'], key)
                        self._schedule_turns(run_id, current['owner'])
                    except Exception as exc:
                        self.store.append_event(run_id, 'resume.agent_handoff_unavailable',
                                                {'errorType': type(exc).__name__})
            else:
                self._resume_from_standing_demo(run_id)

    def _resume_from_standing_demo(self, run_id):
        """Spend the original synthetic user authorization only after exact proof/deployment."""
        run = self.store.get_run(run_id)
        authority = run.get('standingDemoAuthorization')
        if run['mode'] != 'live' or not authority:
            return
        try:
            snapshots = self._synthetic_demo_snapshots(run, self.store,
                                                        require_empty_ledgers=False)
            protected = snapshots['protected']
            remaining = int(authority['expiresAt'] - time.time())
            if (run['state'] != 'held' or authority.get('source') != 'trusted_demo_setup' or
                    authority.get('provenance') != 'user_configured_synthetic_demo' or
                    authority.get('runId') != run_id or authority.get('owner') != run['owner'] or
                    authority.get('workspaceId') != protected['workspaceId'] or
                    authority.get('missionId') != protected['missionId'] or
                    authority.get('snapshot') != protected or remaining <= 0 or
                    run['protected']['ledger']):
                raise ControllerError('Standing synthetic authorization is stale')
            approved = next((item for item in run['protected']['approvals']
                             if item['approvalId'] == authority['approvalId']), None)
            if (approved is None or approved['principal'] !=
                    'synthetic-demo-standing:' + run['owner'] or
                    approved['snapshot'] != protected):
                raise ControllerError('Standing synthetic approval identity changed')
        except (ControllerError, KeyError, TypeError, ValueError):
            self.store.append_event(run_id, 'resume.synthetic_authorization_unavailable',
                                    {'reason': 'Standing synthetic scope expired or changed'})
            return
        try:
            fresh = self.store.approve(run['protected']['environmentId'], protected,
                                       'synthetic-demo-standing:' + run['owner'],
                                       ttl_seconds=min(600, remaining))
            self.store.append_event(run_id, 'resume.synthetic_exact_approval_recorded',
                                    {'approvalId': fresh['approvalId'],
                                     'snapshotDigest': fresh['snapshotDigest'],
                                     'expiresAt': fresh['expiresAt']})
            self._resume(self.store.get_run(run_id))
        except Exception as exc:
            self.store.append_event(run_id, 'resume.synthetic_unconfirmed',
                                    {'errorType': type(exc).__name__})

    def _verify_bad_patch(self, run):
        if self.verifier is None:
            self.store.append_event(run['runId'], 'negative_control.unavailable',
                                    {'reason': 'Independent verifier not configured'})
            raise ControllerError('Independent verifier not configured', 503)
        if run['state'] not in ('contained','held') or run.get('incident',{}).get('status')!='reproduced':
            raise ControllerError('Reproduced incident required for negative control')
        if run.get('negativeControl'):
            raise ControllerError('Negative control already started for this run')
        from verifier.runner import FIXTURE,contract_digest
        if not FIXTURE.is_file():
            raise ControllerError('UI-only negative control artifact is not available', 503)
        config=self.repair_config
        if not re.fullmatch(r'[0-9a-f]{40}',config.get('baseCommit','')) or not Path(config.get('repoPath','')).is_dir():
            raise ControllerError('Pinned source required for independent control', 503)
        verify_config={'repoPath':config['repoPath'],'baseCommit':config['baseCommit'],
                       'patchPath':str(FIXTURE),'artifactDir':str(self.artifact_dir),
                       'verificationContractDigest':contract_digest(),
                       'artifactDigest':hashlib.sha256(FIXTURE.read_bytes()).hexdigest()}
        verify_config.update(config.get('verifierConfig',{}))
        cancel_event=threading.Event()
        verify_config['cancelEvent']=cancel_event
        if not self._heavy_job_lock.acquire(blocking=False):
            raise ControllerError('Another isolated job is active',503)
        job_id='negative-'+secrets.token_hex(12)
        self._verify_cancel[run['runId']+':negative']=cancel_event
        self.store.update_run(run['runId'],negativeControl={'state':'running','jobId':job_id,
                                                             'artifactDigest':verify_config['artifactDigest']})
        def work():
            try:
                result=self.verifier.verify(verify_config)
                tests=result.get('tests',[])
                controls=[t for t in tests if t['name'].startswith(('original.','ui-only.'))]
                candidate=[t for t in tests if t['name'].startswith('candidate.')]
                demonstrated=(result.get('state')=='rejected' and controls and candidate and
                              all(t['passed'] for t in controls) and any(not t['passed'] for t in candidate) and
                              result.get('artifactDigest')==verify_config['artifactDigest'])
                record={'state':'demonstrated' if demonstrated else result.get('state','blocked'),
                        'jobId':job_id,'artifactDigest':verify_config['artifactDigest'],'result':result}
                with self._lifecycle_lock:
                    current=self.store.get_run(run['runId'])
                    if (current['state'] in ('cancelled','reset') or
                            (current.get('negativeControl') or {}).get('jobId')!=job_id or
                            current['negativeControl'].get('state')!='running'):
                        return
                    self.store.update_run(run['runId'],negativeControl=record)
                    self.store.append_event(run['runId'],'negative_control.assessed',
                                            {'state':record['state'],'demonstrated':bool(demonstrated)})
            except Exception as exc:
                with self._lifecycle_lock:
                    current=self.store.get_run(run['runId'])
                    if (current['state'] not in ('cancelled','reset') and
                            (current.get('negativeControl') or {}).get('jobId')==job_id and
                            current['negativeControl'].get('state')=='running'):
                        self.store.update_run(run['runId'],negativeControl=
                                              {'state':'blocked','jobId':job_id,'reason':str(exc)[:500]})
            finally:
                self._verify_cancel.pop(run['runId']+':negative',None)
                self._heavy_job_lock.release()
        thread=threading.Thread(target=work,daemon=True,name=f'vibesecur-negative-{run["runId"][-8:]}')
        with self._lock:
            self._jobs[run['runId']+':negative']=thread
        try:
            thread.start()
        except Exception:
            self._verify_cancel.pop(run['runId']+':negative',None)
            self._heavy_job_lock.release()
            raise
        return self.store.get_run(run['runId'])

    def _resume(self, run):
        with self._lifecycle_lock:
            run_id=run['runId']
            self._active_resume.add(run_id)
            try:
                return self._resume_locked(self.store.get_run(run_id))
            finally:
                self._active_resume.discard(run_id)

    def _resume_locked(self, run):
        if run['state'] != 'held':
            raise ControllerError('Verified deployment must be held before resumption')
        if not run.get('verification') or run['verification'].get('passed') is not True:
            raise ControllerError('Independent verification has not passed')
        repair = run.get('repair') or {}
        deployment = repair.get('deployment') or {}
        if (not any(event['kind'] == 'repair.deployed' for event in run['events']) or
                deployment.get('artifactDigest') != run['verification'].get('artifactDigest') or
                deployment.get('deployed') is not True):
            raise ControllerError('Verified artifact has not been deployed')
        if run['protected']['compensatingRule'] is not False:
            raise ControllerError('Verified application has not replaced the compensating rule')
        if self.payment_gateway is None:
            raise ControllerError('Deployed payment service is unavailable', 503)
        approved = next((a for a in reversed(run['protected']['approvals'])
                         if not a['consumed'] and not a['revoked'] and a['expiresAt'] > time.time()
                         and a['createdAt'] >= repair.get('deployedAt',float('inf'))
                         and a['snapshot'] == self.store.transaction(run['protected']['environmentId'])),None)
        if approved is None:
            raise ControllerError('Fresh exact protected payment approval required after deployment')
        operation = repair.get('resumeOperationId') or 'resume-'+secrets.token_hex(12)
        repair['resumeOperationId'] = operation
        self.store.transition(run['runId'],['held'],'resuming',repair=repair)
        proposal = {**approved['snapshot'],'approvalId':approved['approvalId'],
                    'operationId':operation,'attemptId':run['protected']['attemptId']}
        result = self.payment_gateway.pay(run,'protected',proposal,client='http')
        receipt = self.store.receipt(run['protected']['environmentId'],operation)
        if (receipt is None or receipt.get('approvalId')!=approved['approvalId'] or
                receipt.get('transaction')!=approved['snapshot']):
            self.store.transition(run['runId'],['resuming'],'held')
            self.store.append_event(run['runId'],'resume.unconfirmed',
                                    {'operationId':operation,'httpStatus':result.get('httpStatus'),
                                     'status':result.get('status')})
            raise ControllerError('Fresh payment has no matching trusted ledger receipt', 502)
        self.store.transition(run['runId'],['resuming'],'resumed')
        self.store.append_event(run['runId'],'resume.payment_committed',
                                {'operationId':operation,'approvalId':approved['approvalId'],
                                 'httpStatus':result.get('httpStatus')})
        return self.store.get_run(run['runId'])

    def _cancel(self, run):
        with self._lifecycle_lock:
            current=self.store.get_run(run['runId'])
            if current['state'] in ('cancelled', 'reset'):
                return current
            self.store.transition(run['runId'],[current['state']],'cancelled')
            for key in (run['runId'],run['runId']+':negative'):
                event=self._verify_cancel.get(key)
                if event is not None: event.set()
            negative=current.get('negativeControl') or {}
            if negative.get('state')=='running':
                negative['state']='cancelled'
                self.store.update_run(run['runId'],negativeControl=negative)
        repair = run.get('repair') or {}
        self._stop_live_worker(run)
        active_turn = (current.get('conversation') or {}).get('activeTurnId')
        if active_turn:
            self.security.revoke_task(f"worker-{run['runId']}-{active_turn}")
        conversation_job = current.get('conversationJob') or {}
        if self.worker is not None and conversation_job.get('jobId'):
            try:
                self.worker.cancel(conversation_job['jobId'])
            except (KeyError, ValueError, OSError):
                pass
        if active_turn:
            try:
                self.store.finish_turn(run['runId'], run['owner'], active_turn,
                                       'cancelled', error='mission_cancelled')
            except Exception:
                pass
        job_id = repair.get('jobId')
        if self.repair is not None and job_id:
            try:
                self.repair.cancel(job_id)
            except (KeyError,ValueError):
                pass
        approval_id = repair.get('approval',{}).get('approvalId')
        if approval_id:
            self.security.revoke_task(approval_id)
        for name in ('baseline', 'protected'):
            environment_id = run[name]['environmentId']
            self.store.cancel_environment(environment_id)
            self.security.revoke_environment(environment_id)
        if self.worker is not None and hasattr(self.worker, 'teardown_conversation'):
            try:
                self.worker.teardown_conversation(current)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                self.store.append_event(run['runId'], 'conversation.cleanup_unavailable',
                                        {'errorType': type(exc).__name__})
        if self.payment_gateway is not None and hasattr(self.payment_gateway,'teardown'):
            try:
                self.payment_gateway.teardown(run)
            except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
                self.store.append_event(run['runId'],'payment_service.cleanup_unavailable',
                                        {'errorType':type(exc).__name__})
        self.store.append_event(run['runId'], 'mission.cancelled', {'owner': run['owner']})
        return self.store.get_run(run['runId'])

    def _reset(self, run):
        self._cancel(run)
        self.store.update_run(run['runId'], state='reset')
        replacement = self.store.create_run(run['owner'], run['mode'])
        self.store.append_event(replacement['runId'], 'mission.reset_from', {'previousRunId': run['runId']})
        return self.store.get_run(replacement['runId'])
