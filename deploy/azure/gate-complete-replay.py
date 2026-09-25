#!/usr/bin/env python3
"""Exercise one complete, authenticated synthetic replay on the hosted demo.

The presenter credential comes from the private environment. This gate is an
operator-driven test of the presenter authorization path, not a claim that Kae
has personally approved a live presentation. It never sends financial data to
an external service; the only HTTP origin is the owned demo host.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

import httpx


ORIGIN = 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com'
CHANGED_ACCOUNT = 'SYNTH-AE-CHANGED-999'
ORIGINAL_ACCOUNT = 'SYNTH-AE-GULF-001'
EXPORTS = ('incident.md', 'evidence.jsonl', 'mission.json',
           'reproduction.zip', 'verification-contract.json', 'patch.diff')


def snapshot(environment: dict) -> dict:
    return {key: environment[key] for key in ('environmentId', 'workspaceId', 'missionId')} | {
        **environment['invoice'], **environment['supplier']}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def event(run: dict, kind: str) -> dict | None:
    return next((item for item in reversed(run.get('events', [])) if item.get('kind') == kind), None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path('artifacts/gates'))
    parser.add_argument('--run-id', help='Continue the fresh contained run created for boundary-gate setup')
    parser.add_argument('--setup-artifact', type=Path,
                        help='Passed gate-payment-http artifact for the exact --run-id')
    args = parser.parse_args()
    require(bool(args.run_id) == bool(args.setup_artifact),
            '--run-id and --setup-artifact must be supplied together')
    require(os.environ.get('PUBLIC_ORIGIN', '').rstrip('/') == ORIGIN,
            'PUBLIC_ORIGIN must be the owned HTTPS demo host')
    code = os.environ['PRESENTER_ACCESS_CODE']
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {'schemaVersion': 'vibesecur.complete-replay-gate.v1',
                     'mode': 'deterministic_http_replay', 'status': 'running',
                     'startedAt': time.time(), 'runId': None, 'stages': {},
                     'limitations': ['This tests authenticated deterministic replay, not a live-agent trial.',
                                     'The technical operator exercised the presenter session; Kae tablet rehearsal is separate.']}
    output = output_dir / ('complete-replay-' + uuid.uuid4().hex + '.json')
    try:
        with httpx.Client(base_url=ORIGIN, timeout=45, trust_env=False) as client:
            login = client.post('/api/session', json={'accessCode': code},
                                headers={'Origin': ORIGIN, 'Idempotency-Key': 'gate-login-' + uuid.uuid4().hex})
            login.raise_for_status()
            csrf = login.json()['csrfToken']

            def post(path: str, body: dict | None = None) -> dict:
                response = client.post(path, json=body or {}, headers={
                    'Origin': ORIGIN, 'X-CSRF-Token': csrf,
                    'Idempotency-Key': 'gate-complete-' + uuid.uuid4().hex})
                response.raise_for_status()
                return response.json()

            def get_run(run_id: str) -> dict:
                response = client.get('/api/runs/' + run_id)
                response.raise_for_status()
                return response.json()

            def command(run_id: str, action: str) -> dict:
                return post(f'/api/runs/{run_id}/commands/{action}')['run']

            def wait_for(run_id: str, label: str, done, timeout: int) -> dict:
                deadline = time.monotonic() + timeout
                last = None
                while time.monotonic() < deadline:
                    run = get_run(run_id)
                    progress = (run['state'], (run.get('repair') or {}).get('status'),
                                (run.get('negativeControl') or {}).get('state'),
                                bool(event(run, 'repair.deployed')))
                    if progress != last:
                        print(label + '=' + json.dumps(progress), flush=True)
                        last = progress
                    result = done(run)
                    if result is True:
                        return run
                    if isinstance(result, str):
                        raise RuntimeError(label + ': ' + result)
                    time.sleep(4)
                raise TimeoutError(label + ' timed out')

            if args.run_id:
                require(re.fullmatch(r'run-[0-9a-f]{32}', args.run_id) is not None,
                        'Invalid synthetic run identifier')
                setup = json.loads(args.setup_artifact.read_text(encoding='utf-8'))
                require(setup.get('schemaVersion') == 'vibesecur.payment-http-setup.v1'
                        and setup.get('status') == 'passed'
                        and setup.get('runId') == args.run_id,
                        'Passed setup artifact does not match this run')
                run = get_run(args.run_id)
                require(run.get('mode') == 'replay' and run.get('state') == 'contained',
                        'Existing run is not a contained replay')
                require(type(run.get('createdAt')) in (int, float)
                        and run['createdAt'] == setup.get('createdAt')
                        and 0 <= time.time() - run['createdAt'] <= 2700
                        and 0 <= time.time() - setup.get('finishedAt', -1) <= 2700,
                        'Setup run and artifact must be fresh and contemporaneous')
                events = run.get('events') or []
                require(bool(events) and len(events) == setup.get('eventCount')
                        and events[-1].get('hash') == setup.get('lastEventHash')
                        and events[-1].get('kind') == 'replay.assessed'
                        and sum(item.get('kind') == 'deterministic_replay.payment_http'
                                for item in events) == 2,
                        'Run has changed since the passed setup gate')
                require(not run.get('investigation') and not run.get('negativeControl')
                        and not run.get('repair') and not run.get('verification')
                        and not any(item.get('kind', '').startswith(('alternate_route.',
                                      'investigation.', 'repair.', 'resume.')) for item in events),
                        'Run has already progressed beyond boundary-gate setup')
            else:
                run = post('/api/runs', {'mode': 'replay'})
                run = command(run['runId'], 'start')
                require(run['state'] == 'prepared', 'Replay run did not prepare')
                for environment in ('baseline', 'protected'):
                    post(f"/api/runs/{run['runId']}/approve-payment",
                         {'environment': environment, 'snapshot': snapshot(run[environment])})
                run = command(run['runId'], 'attack')
            run_id = run['runId']
            summary['runId'] = run_id
            print('runId=' + run_id, flush=True)
            baseline = run['baseline']['ledger']
            protected = run['protected']['ledger']
            require(run['state'] == 'contained' and run['incident']['status'] == 'reproduced'
                    and run['incident']['source'] == 'deterministic_http_replay'
                    and run['incident']['infrastructureError'] is False
                    and len(baseline) == 1 and len(protected) == 0
                    and baseline[0]['transaction']['beneficiaryAccount'] == CHANGED_ACCOUNT,
                    'Baseline/protected trusted-ledger reproduction failed')
            summary['stages']['reproduction'] = {
                'status': 'passed', 'baselineOperationId': baseline[0]['operationId'],
                'baselineUnauthorizedEffects': 1, 'protectedUnauthorizedEffects': 0}

            # Boundary gates can outlive the original ten-minute payment approval.
            # Renew only the exact protected transaction when the prior approval is
            # expired or close to expiry; never reuse it to authorize a changed payee.
            protected_snapshot = snapshot(run['protected'])
            require(protected_snapshot['beneficiaryAccount'] == ORIGINAL_ACCOUNT and
                    protected_snapshot['amountMinor'] == 25_000_000 and
                    protected_snapshot['currency'] == 'AED',
                    'Protected current transaction differs from the legitimate synthetic invoice')
            def usable_protected_approval(state: dict) -> bool:
                now = time.time()
                # Match Controller._usable_approval: the newest live approval
                # is the one sent to the payment service for this operation.
                selected = next((approval for approval in reversed(state['protected']['approvals'])
                                 if approval.get('consumed') is False and
                                 approval.get('revoked') is False and
                                 type(approval.get('expiresAt')) in (int, float) and
                                 approval['expiresAt'] > now), None)
                return bool(selected and selected.get('snapshot') == protected_snapshot and
                            selected['expiresAt'] > now + 30)

            refreshed = False
            if not usable_protected_approval(run):
                post(f'/api/runs/{run_id}/approve-payment',
                     {'environment': 'protected', 'snapshot': protected_snapshot})
                run = get_run(run_id)
                refreshed = True
            require(usable_protected_approval(run),
                    'Fresh exact protected approval is unavailable for alternate route')
            summary['stages']['protectedApproval'] = {
                'status': 'passed', 'refreshedAfterBoundaryGates': refreshed}

            run = command(run_id, 'alternate-route')
            alternative = event(run, 'alternate_route.result')
            require(alternative is not None and
                    alternative['data'].get('status') == 'response' and
                    alternative['data'].get('httpStatus') in (403, 409) and
                    alternative['data'].get('unauthorizedLedgerEffect') is False and
                    len(run['protected']['ledger']) == 0,
                    'Alternate owned client path did not confirm an API rejection with no ledger effect')
            summary['stages']['alternateRoute'] = {
                'status': 'passed', 'client': alternative['data'].get('client'),
                'httpStatus': alternative['data'].get('httpStatus')}

            run = command(run_id, 'investigate')
            report = run.get('investigation') or {}
            require(report.get('sourceInspection', {}).get('status') == 'confirmed_seed_defect'
                    and bool(report.get('confirmedCause')) and bool(report.get('evidenceRefs'))
                    and report.get('actualImpact', {}).get('baselineUnauthorizedPayment') is True
                    and report.get('actualImpact', {}).get('protectedUnauthorizedPayment') is False,
                    'Grounded source/ledger investigation is incomplete')
            require(report.get('modelStatus') == 'available',
                    'Azure-assisted investigation did not produce a usable narrative')
            summary['stages']['investigation'] = {
                'status': 'passed', 'modelStatus': report['modelStatus'],
                'sourceSha256': report['sourceInspection']['sourceSha256'],
                'evidenceRefCount': len(report['evidenceRefs'])}

            command(run_id, 'verify-bad-patch')
            run = wait_for(run_id, 'negative-control', lambda state:
                True if (state.get('negativeControl') or {}).get('state') == 'demonstrated' else
                'negative control did not demonstrate API rejection' if
                (state.get('negativeControl') or {}).get('state') in ('blocked', 'failed', 'rejected') else False,
                600)
            summary['stages']['uiOnlyNegativeControl'] = {
                'status': 'passed',
                'artifactDigest': run['negativeControl']['artifactDigest']}

            run = command(run_id, 'authorize-repair')
            require(run['state'] == 'repairing' and bool(event(run, 'repair.authorized')),
                    'Presenter-scoped repair authorization was not persisted')

            def repair_finished(state: dict):
                if event(state, 'repair.deployed') and state['state'] == 'held':
                    return True
                unavailable = event(state, 'repair.deployment_unavailable')
                if unavailable:
                    return 'deployment unavailable: ' + str(unavailable.get('data', {}).get('reason'))
                held = event(state, 'repair.held')
                if held:
                    return 'repair held: ' + str(held.get('data', {}).get('reason'))
                if event(state, 'repair.verification_failed'):
                    return 'independent verification failed'
                return False

            run = wait_for(run_id, 'repair', repair_finished, 1600)
            proof = run.get('verification') or {}
            repair = run.get('repair') or {}
            deployment = repair.get('deployment') or {}
            require(proof.get('passed') is True and proof.get('outerContainment') is True
                    and proof.get('compensatingRule') is False
                    and deployment.get('deployed') is True
                    and deployment.get('artifactDigest') == proof.get('artifactDigest')
                    and run['protected']['compensatingRule'] is False
                    and len(run['protected']['ledger']) == 0,
                    'Verified exact artifact was not safely deployed')
            summary['stages']['repairAndIndependentVerification'] = {
                'status': 'passed', 'artifactDigest': proof['artifactDigest'],
                'imageDigest': deployment.get('imageDigest'),
                'testCount': len(proof.get('tests') or [])}

            post(f'/api/runs/{run_id}/approve-payment',
                 {'environment': 'protected', 'snapshot': snapshot(run['protected'])})
            run = command(run_id, 'resume')
            protected = run['protected']['ledger']
            require(run['state'] == 'resumed' and len(protected) == 1
                    and protected[0]['transaction']['beneficiaryAccount'] == ORIGINAL_ACCOUNT
                    and protected[0]['transaction']['amountMinor'] == 25_000_000
                    and protected[0]['transaction']['currency'] == 'AED'
                    and bool(event(run, 'resume.payment_committed')),
                    'Fresh exact payment did not produce a trusted legitimate receipt')
            summary['stages']['resumption'] = {
                'status': 'passed', 'operationId': protected[0]['operationId'],
                'approvalId': protected[0]['approvalId'], 'ledgerEffects': 1}

            exports = {}
            for name in EXPORTS:
                response = client.get(f'/api/runs/{run_id}/exports/{name}')
                response.raise_for_status()
                require(bool(response.content), 'Empty export: ' + name)
                exports[name] = {'bytes': len(response.content),
                                 'sha256': hashlib.sha256(response.content).hexdigest()}
            summary['stages']['exports'] = {'status': 'passed', 'files': exports}
            summary['status'] = 'passed'
    except Exception as exc:
        summary['status'] = 'blocked'
        summary['reason'] = type(exc).__name__ + ': ' + str(exc)[:300]
    finally:
        summary['finishedAt'] = time.time()
        output.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        print(json.dumps({'status': summary['status'], 'runId': summary['runId'],
                          'reason': summary.get('reason'), 'artifact': str(output)}), flush=True)
    return 0 if summary['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
