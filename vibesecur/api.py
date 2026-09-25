"""Authenticated presenter HTTP surface and environment-scoped trusted effect API."""
from __future__ import annotations

import hashlib
import asyncio
import io
import json
import os
from pathlib import Path
import sqlite3
import zipfile
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient

from vibesecur.auth import SecurityError, SecurityStore
from vibesecur.controller import Controller, ControllerError
from vibesecur.employee import message_intent, plan_from_investigation
from vibesecur.issue_connectors import IssueConnectorError, connection_status, create_issue
from vibesecur.model_broker import ModelBroker
from vibesecur.store import Store, StoreError

EXPORTS = {'incident.md', 'evidence.jsonl', 'mission.json', 'verification-contract.json', 'reproduction.zip', 'patch.diff'}
ROOT = Path(__file__).resolve().parent.parent


class LocalPaymentGateway:
    """In-process HTTP replay adapter; its calls still cross payment_app's API."""

    def __init__(self, effect_app, security):
        self.effect_app, self.security = effect_app, security

    def pay(self, run, environment, command, client='http'):
        from payment_app.app import create_app as create_payment_app
        environment_id = run[environment]['environmentId']
        token = self.security.issue_service_token(environment_id, ttl=300)
        with TestClient(self.effect_app) as internal:
            payment_app = create_payment_app(environment_id, 'http://testserver', token, client=internal)
            with TestClient(payment_app) as payment:
                try:
                    response = payment.post('/api/payments', json=command)
                except Exception as exc:
                    return {'status': 'transport_error', 'httpStatus': None, 'body': {'error': type(exc).__name__},
                            'transport': 'local_asgi_http'}
        return {'status': 'response', 'httpStatus': response.status_code, 'body': response.json(),
                'transport': 'local_asgi_http'}

    def pay_alternate(self, run, environment, command):
        result = self.pay(run, environment, command, client='independent_asgi_http')
        result['client'] = 'independent_asgi_http'
        return result

    def document(self, run, environment):
        from payment_app.app import create_app as create_payment_app
        environment_id = run[environment]['environmentId']
        token = self.security.issue_service_token(environment_id, ttl=300)
        with TestClient(self.effect_app) as internal:
            payment_app = create_payment_app(environment_id, 'http://testserver', token, client=internal)
            with TestClient(payment_app) as payment:
                try:
                    response = payment.get('/documents/invoice')
                except Exception as exc:
                    return {'status':'transport_error','httpStatus':None,'body':type(exc).__name__,
                            'transport':'local_asgi_http'}
        body = response.text
        return {'status':'response','httpStatus':response.status_code,'body':body[:16384],
                'transport':'local_asgi_http', 'truncated':len(body)>16384,
                'bodyLengthChars':len(body), 'bodyLengthBytes':len(response.content),
                'bodySha256':hashlib.sha256(response.content).hexdigest()}


def _json_digest(path: str, body: bytes) -> str:
    try:
        canonical = json.dumps(json.loads(body or b'{}'), sort_keys=True, separators=(',', ':')).encode()
    except (ValueError, TypeError):
        raise ControllerError('Invalid JSON body', 400)
    return hashlib.sha256(path.encode()+b'\0'+canonical).hexdigest()


def create_app(*, data_dir: str | None = None, access_code: str | None = None,
               public_origin: str | None = None, store=None, security=None, controller=None,
               payment_gateway=None, worker=None, repair=None, verifier=None,
               repair_config=None, investigator_model=None, intent_interpreter=None,
               standing_demo_enabled: bool | None = None, assessor=None) -> FastAPI:
    data = Path(data_dir or os.environ.get('VIBESECUR_DATA_DIR', './data')).resolve()
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    code = access_code if access_code is not None else os.environ.get('PRESENTER_ACCESS_CODE', '')
    origin = public_origin if public_origin is not None else os.environ.get('PUBLIC_ORIGIN', 'http://127.0.0.1:8000')
    parsed = urlparse(origin)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('PUBLIC_ORIGIN must be an HTTP(S) origin')
    if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', 'testserver'):
        raise ValueError('Non-local presenter origin must use HTTPS')
    allowed_origins = {origin.rstrip('/')}
    if parsed.hostname in ('localhost', '127.0.0.1', 'testserver'):
        allowed_origins |= {'http://127.0.0.1:8000', 'http://localhost:8000',
                            'http://127.0.0.1:5173', 'http://localhost:5173', 'http://testserver'}
    cookie_secure = parsed.scheme == 'https'
    trusted_proxies = {item.strip() for item in
                       os.environ.get('VIBESECUR_TRUSTED_PROXIES', '').split(',') if item.strip()}

    def login_source(request: Request) -> str:
        peer = request.client.host if request.client else 'unknown'
        forwarded = request.headers.get('x-forwarded-for', '')
        if peer in trusted_proxies and forwarded:
            return forwarded.split(',')[-1].strip()[:64] or peer
        return peer
    store = store or Store(str(data/'effects.sqlite'))
    security = security or SecurityStore(str(data/'security.sqlite'))
    if payment_gateway is None and (os.environ.get('VIBESECUR_PAYMENT_IMAGE') or
                                    os.environ.get('VIBESECUR_PAYMENT_NETWORK')) and not os.environ.get('PAYMENT_URL_TEMPLATE'):
        raise ValueError('Payment URL template is required with payment service provisioning')
    if payment_gateway is None and os.environ.get('PAYMENT_URL_TEMPLATE'):
        from vibesecur.worker import PaymentGateway
        image=os.environ.get('VIBESECUR_PAYMENT_IMAGE','')
        network=os.environ.get('VIBESECUR_PAYMENT_NETWORK','')
        if bool(image)!=bool(network):
            raise ValueError('Payment service image and network must be configured together')
        provisioner=None
        if image:
            from vibesecur.worker import PaymentServiceProvisioner
            provisioner=PaymentServiceProvisioner({'image':image,'network':network},security)
        payment_gateway = PaymentGateway(os.environ['PAYMENT_URL_TEMPLATE'],provisioner=provisioner)
    if worker is None and os.environ.get('VIBESECUR_WORKER_RUNTIME') == 'local-docker':
        from vibesecur.local_runtime import local_runtime_from_env
        from vibesecur.worker import PaymentGateway
        worker, local_services = local_runtime_from_env(security)
        if payment_gateway is None:
            payment_gateway = PaymentGateway('http://{environmentId}.invalid', provisioner=local_services)
    worker_env = {
        'runtime': 'VIBESECUR_WORKER_RUNTIME',
        'image': 'VIBESECUR_WORKER_IMAGE',
        'imageRef': 'VIBESECUR_WORKER_IMAGE_REF',
        'network': 'VIBESECUR_WORKER_NETWORK',
        'networkVerified': 'VIBESECUR_WORKER_NETWORK_VERIFIED',
        'boundaryEvidencePath': 'VIBESECUR_WORKER_BOUNDARY_EVIDENCE',
        'policyTemplatePath': 'VIBESECUR_WORKER_POLICY_TEMPLATE',
        'artifactDir': 'VIBESECUR_WORKER_ARTIFACT_DIR',
        'applicationUrl': 'VIBESECUR_WORKER_APP_URL_TEMPLATE',
        'modelBaseUrl': 'VIBESECUR_WORKER_MODEL_BASE_URL',
        'model': 'VIBESECUR_WORKER_MODEL',
        'openshellCli': 'VIBESECUR_WORKER_OPENSHELL_CLI',
    }
    if worker is None and any(os.environ.get(name) for name in worker_env.values()):
        if payment_gateway is None or (os.environ.get('PAYMENT_URL_TEMPLATE') and
                not (os.environ.get('VIBESECUR_PAYMENT_IMAGE') and
                     os.environ.get('VIBESECUR_PAYMENT_NETWORK'))):
            raise ValueError('Live worker requires a separate provisioned payment gateway')
        missing = [name for name in worker_env.values() if not os.environ.get(name)]
        if missing:
            raise ValueError('Incomplete live worker configuration: ' + ', '.join(missing))
        if (os.environ[worker_env['runtime']] != 'openshell' or
                os.environ[worker_env['networkVerified']] != '1'):
            raise ValueError('Live worker requires measured OpenShell boundary verification')
        from vibesecur.worker import WorkerAdapter
        worker_config = {key: os.environ[name] for key,name in worker_env.items()}
        worker_config['networkVerified'] = True
        worker_config['reasoningEffort'] = os.environ.get('VIBESECUR_WORKER_REASONING', 'low')
        worker_config['leaseFactory'] = lambda task_id: security.issue_model_lease(
            task_id, worker_config['model'].removeprefix('openai/'), ttl=600,
            max_requests=40, max_output_tokens=4096)
        worker = WorkerAdapter(worker_config)
    if repair_config is None:
        repair_config = {'repoPath': os.environ.get('VIBESECUR_REPAIR_REPO_PATH',''),
                         'baseCommit': os.environ.get('VIBESECUR_REPAIR_BASE_COMMIT',''),
                         'modelBaseUrl': os.environ.get('VIBESECUR_MODEL_BASE_URL',''),
                         'verifierConfig': {
                             'applicationImage':os.environ.get('VIBESECUR_VERIFIER_APP_IMAGE',''),
                             'trustedImage':os.environ.get('VIBESECUR_VERIFIER_TRUSTED_IMAGE',''),
                             'verifierNetwork':os.environ.get('VIBESECUR_VERIFIER_NETWORK',''),
                             'verifierBoundaryEvidencePath':os.environ.get('VIBESECUR_VERIFIER_BOUNDARY_EVIDENCE','')}}
    if repair is None and os.environ.get('VIBESECUR_REPAIR_IMAGE'):
        from vibesecur.repair import RepairExecutor
        repair = RepairExecutor({'image':os.environ['VIBESECUR_REPAIR_IMAGE'],
                                 'network':os.environ.get('VIBESECUR_REPAIR_NETWORK',''),
                                 'networkVerified':os.environ.get('VIBESECUR_REPAIR_NETWORK_VERIFIED')=='1',
                                 'boundaryEvidencePath':os.environ.get('VIBESECUR_REPAIR_BOUNDARY_EVIDENCE','')})
    if verifier is None and repair is not None:
        from verifier import runner as verifier
    if (investigator_model is None and os.environ.get('VIBESECUR_INVESTIGATION_MODEL_BASE_URL') and
            os.environ.get('VIBESECUR_CODE_INVESTIGATION') == '1'):
        from vibesecur.code_investigator import CodeInvestigator
        investigator_model = CodeInvestigator(
            security, os.environ['VIBESECUR_INVESTIGATION_MODEL_BASE_URL'],
            os.environ.get('VIBESECUR_INVESTIGATION_MODEL', 'gpt-6-luna'),
            repair_config['repoPath'], repair_config['baseCommit'])
    if investigator_model is None and os.environ.get('VIBESECUR_INVESTIGATION_MODEL_BASE_URL'):
        from vibesecur.investigation import AzureInvestigator
        investigator_model = AzureInvestigator(security,os.environ['VIBESECUR_INVESTIGATION_MODEL_BASE_URL'])
    broker_url = os.environ.get('VIBESECUR_INVESTIGATION_MODEL_BASE_URL', '')
    employee_model = os.environ.get('VIBESECUR_WORKER_MODEL', 'gpt-6-luna').removeprefix('openai/')
    if intent_interpreter is None and broker_url:
        from vibesecur.task_intent import AzureTaskInterpreter
        intent_interpreter = AzureTaskInterpreter(security, broker_url, employee_model)
    if standing_demo_enabled is None:
        standing_demo_enabled = os.environ.get('VIBESECUR_STANDING_DEMO_AUTHORIZED') == '1'
    if assessor is None and broker_url and os.environ.get('VIBESECUR_ASSESSOR') == 'ensemble':
        from vibesecur.assessment import EnsembleAssessment, JevAssessment, LlmAssessment, assess
        members = [LlmAssessment(security, broker_url, employee_model).assess]
        if os.environ.get('OPENROUTER_API_KEY'):
            members.insert(0, JevAssessment(os.environ['OPENROUTER_API_KEY']).assess)
        assessor = EnsembleAssessment(members)
    if assessor is None:
        from vibesecur.assessment import assess
        assessor = assess
    controller = controller or Controller(store, security, payment_gateway=payment_gateway,
                                          worker=worker, repair=repair, verifier=verifier,
                                          artifact_dir=data/'artifacts',repair_config=repair_config,
                                          investigator_model=investigator_model,
                                          intent_interpreter=intent_interpreter,
                                          standing_demo_enabled=standing_demo_enabled,
                                          activity_assessor=assessor,
                                          model_token_factory=lambda task_id: security.issue_model_lease(
                                              task_id, employee_model, ttl=600, max_requests=40,
                                              max_output_tokens=4096))
    app = FastAPI(title='VibeSecur Action Firewall', docs_url=None, redoc_url=None, openapi_url=None)
    if payment_gateway is None and controller.payment_gateway is None:
        controller.payment_gateway = LocalPaymentGateway(app, security)
    app.state.store, app.state.security, app.state.controller = store, security, controller
    app.state.data_dir = data
    results_db = data/'api-idempotency.sqlite'
    with sqlite3.connect(results_db) as db:
        db.execute('CREATE TABLE IF NOT EXISTS results (owner TEXT NOT NULL, key TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(owner,key))')

    @app.exception_handler(SecurityError)
    async def security_error(_, error: SecurityError):
        return JSONResponse({'detail': error.message}, status_code=error.status)

    @app.exception_handler(StoreError)
    async def store_error(_, error: StoreError):
        body = {'detail': error.message, 'code': error.code}
        if error.code == 'transaction_mismatch':
            body['nextStep'] = ('This payment was not executed because it does not match the '
                                'authorized transaction. Recheck the trusted supplier record in '
                                '/api/context, then submit a corrected proposal with a new '
                                'operationId. The blocked attempt did not consume its approval.')
            correction = error.correction
            if correction:
                body['correction'] = correction
                body['nextStep'] = ('VibeSecur blocked this payment. Do this next: resubmit with ' +
                                    ', '.join(f"{item['field']}={json.dumps(item['authorized'])} "
                                              f"(you sent {json.dumps(item['sent'])})"
                                              for item in correction) +
                                    ', keep every other field, and use a new operationId. '
                                    'These values come from the trusted workspace record in '
                                    '/api/context; the supplier document cannot change them.')
        return JSONResponse(body, status_code=error.status)

    @app.exception_handler(ControllerError)
    async def controller_error(_, error: ControllerError):
        return JSONResponse({'detail': error.message}, status_code=error.status)

    @app.exception_handler(IssueConnectorError)
    async def issue_connector_error(_, error: IssueConnectorError):
        return JSONResponse({'detail': str(error), 'code': error.code},
                            status_code=409 if error.code == 'not_connected' else 502)

    def origin_check(request: Request):
        if request.headers.get('origin', '').rstrip('/') not in allowed_origins:
            raise SecurityError('Untrusted request origin', 403)

    def key_check(request: Request) -> str:
        key = request.headers.get('idempotency-key', '')
        if not 1 <= len(key) <= 128:
            raise SecurityError('Idempotency-Key must contain 1 to 128 characters', 400)
        return key

    def presenter(request: Request, *, mutation=False) -> dict:
        token = request.cookies.get('vibesecur_session', '')
        row = security.session(token)
        if mutation:
            origin_check(request)
            security.check_csrf(token, request.headers.get('x-csrf-token'))
            key_check(request)
        return row

    async def idempotent(request: Request, owner: str, invoke, status_code=200):
        key = key_check(request)
        body = await request.body()
        request_digest = _json_digest(request.url.path, body)
        first = security.claim_request(owner, key, request_digest)
        if not first:
            with sqlite3.connect(results_db) as db:
                row = db.execute('SELECT payload FROM results WHERE owner=? AND key=?', (owner, key)).fetchone()
            if row is None:
                raise ControllerError('Matching request is still in progress or previously failed', 409)
            return JSONResponse(json.loads(row[0]), status_code=status_code)
        value = await asyncio.to_thread(invoke,json.loads(body or b'{}'))
        with sqlite3.connect(results_db) as db:
            db.execute('INSERT INTO results VALUES (?,?,?)', (owner, key, json.dumps(value, separators=(',', ':'))))
        return JSONResponse(value, status_code=status_code)

    @app.get('/health')
    async def health():
        return {'status': 'ok'}

    @app.get('/api/session')
    async def get_session(request: Request):
        try:
            row = security.session(request.cookies.get('vibesecur_session', ''))
        except SecurityError:
            return {'authenticated': False, 'csrfToken': None}
        return {'authenticated': True, 'csrfToken': row['csrf']}

    @app.post('/api/session')
    async def post_session(request: Request):
        origin_check(request)
        key_check(request)
        try:
            payload = await request.json()
        except (ValueError, TypeError):
            raise ControllerError('Invalid JSON body', 400)
        if not isinstance(payload, dict) or not isinstance(payload.get('accessCode'), str):
            raise ControllerError('Access code required', 400)
        security.check_login_rate(login_source(request))
        result = security.login(payload['accessCode'], code)
        response = JSONResponse({'authenticated': True, 'csrfToken': result['csrfToken']})
        response.set_cookie('vibesecur_session', result['token'], httponly=True, secure=cookie_secure,
                            samesite='strict', path='/', max_age=86400)
        return response

    @app.post('/api/logout')
    async def post_logout(request: Request):
        presenter(request, mutation=True)
        security.logout(request.cookies.get('vibesecur_session', ''))
        response = JSONResponse({'authenticated': False})
        response.delete_cookie('vibesecur_session', path='/')
        return response

    @app.get('/api/runs')
    async def get_runs(request: Request):
        row = presenter(request)
        controller.reconcile(row['owner'])
        return store.list_runs(row['owner'])

    @app.post('/api/runs')
    async def post_runs(request: Request):
        row = presenter(request, mutation=True)
        def invoke(payload):
            if not isinstance(payload, dict) or payload.get('mode') not in ('live', 'replay') or set(payload) != {'mode'}:
                raise ControllerError('Mode must be live or replay', 400)
            result = controller.create_run(row['owner'], payload['mode'])
            if payload['mode'] == 'live' and standing_demo_enabled:
                result = controller.provision_standing_demo(result['runId'], row['owner'])
            return result
        return await idempotent(request, row['owner'], invoke)

    @app.get('/api/runs/{run_id}')
    async def get_run(run_id: str, request: Request):
        row = presenter(request)
        controller.reconcile(row['owner'])
        return {**store.get_run(run_id, row['owner']), 'live': controller.live(run_id)}

    @app.get('/api/runs/{run_id}/stream')
    async def stream_run(run_id: str, request: Request):
        row = presenter(request)
        store.get_run(run_id, row['owner'])

        async def frames():
            last, sent = None, 0
            while sent < 2400 and not await request.is_disconnected():
                run = await asyncio.to_thread(store.get_run, run_id, row['owner'])
                body = json.dumps({**run, 'live': controller.live(run_id)}, default=str,
                                  separators=(',', ':'))
                if body != last:
                    last = body
                    yield 'data: ' + body + '\n\n'
                elif sent % 40 == 0:
                    yield ': keepalive\n\n'
                sent += 1
                await asyncio.sleep(0.25)
        return StreamingResponse(frames(), media_type='text/event-stream',
                                 headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

    @app.post('/api/runs/{run_id}/approve-payment')
    async def post_approval(run_id: str, request: Request):
        row = presenter(request, mutation=True)
        def invoke(payload):
            if not isinstance(payload, dict) or set(payload) != {'environment', 'snapshot'}:
                raise ControllerError('Environment and exact snapshot required', 400)
            return controller.approve(run_id, row['owner'], payload['environment'], payload['snapshot'])
        return await idempotent(request, row['owner'], invoke)

    @app.post('/api/runs/{run_id}/commands/{action}')
    async def post_command(run_id: str, action: str, request: Request):
        row = presenter(request, mutation=True)
        def invoke(payload):
            if payload != {}:
                raise ControllerError('Command body must be empty', 400)
            result = controller.command(run_id, row['owner'], action)
            return {'accepted': True, 'run': ensure_investigation_plan(run_id, row['owner'], result)
                    if action == 'investigate' else result}
        return await idempotent(request, row['owner'], invoke)

    def ensure_investigation_plan(run_id: str, owner: str, result: dict) -> dict:
        """Keep the editable presenter proposal beside a saved investigation.

        This grants no repair authority and does not change the executor mission.
        The guard also supports deployed controllers predating this UI addition.
        """
        report = result.get('investigation')
        if (not isinstance(report, dict) or result.get('remediationPlan') or
                report.get('disposition') in ('unresolved', 'course_corrected_no_repair')):
            return result
        proposal = plan_from_investigation(report)
        if not proposal:
            return result
        return store.save_remediation_plan(run_id, owner, proposal, 0)

    @app.post('/api/runs/{run_id}/messages')
    async def post_message(run_id: str, request: Request):
        row = presenter(request, mutation=True)
        def invoke(payload):
            if (not isinstance(payload, dict) or not {'text', 'channel'} <= set(payload) or
                    set(payload) - {'text', 'channel', 'clientMessageId'} or
                    not isinstance(payload['text'], str) or not 1 <= len(payload['text'].strip()) <= 2000 or
                    payload['channel'] not in ('maya', 'control_panel')):
                raise ControllerError('A message and valid conversation channel are required', 400)
            message, channel = payload['text'].strip(), payload['channel']
            if channel == 'maya':
                client_id = payload.get('clientMessageId', key_check(request))
                if not isinstance(client_id, str) or not 1 <= len(client_id) <= 128:
                    raise ControllerError('A bounded client message identity is required', 400)
                result = controller.submit_message(run_id, row['owner'], message, client_id)
                return {'accepted': True, 'run': result}
            run = store.get_run(run_id, row['owner'])
            store.append_event(run_id, 'conversation.user', {'text': message, 'channel': channel})
            intent = message_intent(message)
            if intent == 'fix':
                controller.command(run_id, row['owner'], 'authorize-repair')
                reply = 'The saved plan is authorized for scoped repair. The proposed fix will be checked independently.'
            elif intent == 'investigate':
                result = controller.command(run_id, row['owner'], 'investigate')
                ensure_investigation_plan(run_id, row['owner'], result)
                reply = 'The investigation state is available below.'
            elif intent in ('resume', 'continue'):
                controller.command(run_id, row['owner'], 'resume')
                reply = 'The controller is reconciling the authorized task before continuing.'
            elif intent == 'plan_note':
                current = run.get('remediationPlan') or {}
                if not current.get('text'):
                    raise ControllerError('A grounded investigation and saved plan are required')
                store.save_remediation_plan(run_id, row['owner'],
                    current['text'] + '\n\nAdditional constraint: ' + message, current.get('version', 0))
                reply = 'Your constraint is saved in the plan. Say “Fix it” to authorize this version.'
            else:
                reply = 'You can edit the saved plan, add a constraint, or say “Fix it” when it is ready.'
            store.append_event(run_id, 'conversation.maya', {'text': reply, 'channel': channel,
                                                            'source': 'controller_action_result'})
            return {'accepted': True, 'reply': reply, 'run': store.get_run(run_id, row['owner'])}
        return await idempotent(request, row['owner'], invoke, status_code=202)

    @app.post('/api/runs/{run_id}/remediation-plan')
    async def post_remediation_plan(run_id: str, request: Request):
        row = presenter(request, mutation=True)
        def invoke(payload):
            if not isinstance(payload, dict) or set(payload) != {'text', 'expectedVersion'}:
                raise ControllerError('Plan text and expected version required', 400)
            return store.save_remediation_plan(run_id, row['owner'], payload['text'],
                                               payload['expectedVersion'])
        return await idempotent(request, row['owner'], invoke)

    @app.get('/api/connectors')
    async def get_connectors(request: Request):
        presenter(request)
        return {provider: {'connected': connection_status(provider)['configured'],
                           'configured': connection_status(provider)['configured']}
                for provider in ('linear', 'jira')}

    @app.get('/api/capabilities')
    async def get_capabilities(request: Request):
        presenter(request)
        return {'liveWorker': {'configured': controller.worker is not None},
                'executors': ([{'id': 'codex', 'label': 'Codex', 'connected': True}]
                              if controller.repair is not None else [])}

    @app.post('/api/runs/{run_id}/issues/{provider}')
    async def post_issue(run_id: str, provider: str, request: Request):
        row = presenter(request, mutation=True)
        def invoke(payload):
            run = store.get_run(run_id, row['owner'])
            if not isinstance(run.get('investigation'), dict):
                raise ControllerError('Investigation required before engineering issue creation')
            if not isinstance(payload, dict) or not {'title', 'description'} <= set(payload) or \
                    set(payload) - {'title', 'description', 'nativeFields'}:
                raise ControllerError('Editable title and description required', 400)
            result = create_issue(provider, payload)
            updated = store.record_created_issue(run_id, row['owner'], result)
            return {'issue': result, 'run': updated}
        return await idempotent(request, row['owner'], invoke)

    @app.get('/api/runs/{run_id}/exports/{name}')
    async def get_export(run_id: str, name: str, request: Request):
        row = presenter(request)
        run = store.get_run(run_id, row['owner'])
        if name not in EXPORTS:
            raise ControllerError('Export not found', 404)
        if name == 'evidence.jsonl':
            if not run['events']:
                raise ControllerError('Evidence is not available yet', 404)
            lines = ''.join(json.dumps(event, sort_keys=True, separators=(',', ':'))+'\n' for event in run['events'])
            return Response(lines, media_type='application/x-ndjson',
                            headers={'Content-Disposition': 'attachment; filename="evidence.jsonl"'})
        if name == 'mission.json':
            mission = (run.get('repair') or {}).get('mission') or {
                'runId': run_id, 'mode': run['mode'], 'workspaceId': run['baseline']['workspaceId'],
                'missionId': run['baseline']['missionId'], 'invoice': run['baseline']['invoice'],
                'repairAuthority': None, 'status': 'incident_handoff_only'}
            return JSONResponse(mission, headers={'Content-Disposition': 'attachment; filename="mission.json"'})
        if name == 'verification-contract.json':
            contract = ROOT/'verifier/verification-contract.json'
            if contract.exists():
                return FileResponse(contract, media_type='application/json', filename=name)
        if name == 'incident.md':
            investigation = run.get('investigation')
            if isinstance(investigation, dict) and investigation.get('markdown'):
                return Response(investigation['markdown'], media_type='text/markdown',
                                headers={'Content-Disposition': 'attachment; filename="incident.md"'})
        if name == 'reproduction.zip':
            if not run.get('incident'):
                raise ControllerError('Reproduction is not available yet', 404)
            receipt = run['incident'].get('baselineReceipt')
            if not receipt:
                raise ControllerError('Trusted reproduction receipt is missing', 404)
            source=run['incident'].get('source')
            if source not in ('deterministic_http_replay','live_agent'):
                raise ControllerError('Incident evidence source is unavailable', 404)
            evidence = {'runId': run_id, 'kind': source,
                        'approvedTransaction': next((a['snapshot'] for a in run['baseline']['approvals']
                                                      if a['approvalId'] == receipt['approvalId']), None),
                        'unauthorizedReceipt': receipt, 'protectedLedger': run['protected']['ledger'],
                        'workerResults':run['incident'].get('workerResults') if source=='live_agent' else None,
                        'evidenceEventIds':(run.get('investigation') or {}).get('evidenceRefs',[])}
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for filename, content in (
                    ('README.txt', 'Synthetic invoice '+source+' evidence. Run the trusted verifier for repair acceptance.\n'),
                    ('reproduction.json', json.dumps(evidence, sort_keys=True, indent=2)),
                ):
                    entry = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    entry.create_system = 3
                    entry.external_attr = 0o644 << 16
                    archive.writestr(entry, content)
            return Response(buffer.getvalue(), media_type='application/zip',
                            headers={'Content-Disposition': 'attachment; filename="reproduction.zip"'})
        if name == 'patch.diff':
            path = (run.get('repair') or {}).get('patchPath')
            if path and Path(path).is_file() and Path(path).resolve().is_relative_to(data):
                return FileResponse(path, media_type='text/plain', filename=name)
        raise ControllerError('Export has not been produced', 404)

    @app.get('/internal/verifier/health')
    async def internal_verifier_health():
        ready = controller.verifier is not None
        return JSONResponse({'service': 'vibesecur-verifier', 'configured': ready},
                            status_code=200 if ready else 503)

    @app.get('/internal/environments/{environment_id}')
    async def internal_environment(environment_id: str, request: Request):
        bearer = request.headers.get('authorization', '')
        token = bearer[7:] if bearer.startswith('Bearer ') else ''
        security.authorize_service(token, environment_id)
        return store.environment(environment_id)

    @app.post('/internal/environments/{environment_id}/payments')
    async def internal_payment(environment_id: str, request: Request):
        bearer = request.headers.get('authorization', '')
        token = bearer[7:] if bearer.startswith('Bearer ') else ''
        security.authorize_service(token, environment_id)
        try:
            command = await request.json()
        except (ValueError, TypeError):
            raise ControllerError('Invalid JSON payment command', 400)
        from vibesecur.supervision import supervised_payment
        return await asyncio.to_thread(supervised_payment, store, controller.payment_gateway,
                                       assessor, environment_id, command)

    if os.environ.get('VIBESECUR_MODEL_PROVIDER') == 'openrouter':
        broker = ModelBroker(security, 'https://openrouter.ai/api/v1',
                             os.environ.get('OPENROUTER_API_KEY', ''), provider='openrouter',
                             model_prefix=os.environ.get('VIBESECUR_OPENROUTER_MODEL_PREFIX', 'openai/'))
    else:
        endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT', 'https://unconfigured.openai.azure.com/openai/v1')
        broker = ModelBroker(security, endpoint, os.environ.get('AZURE_OPENAI_API_KEY', ''))
    app.include_router(broker.router)
    static = ROOT/'apps/presenter/dist'
    if static.is_dir():
        app.mount('/', StaticFiles(directory=static, html=True), name='presenter')
    return app


app = create_app()
