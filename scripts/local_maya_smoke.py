#!/usr/bin/env python3
"""Local live smoke: real OpenHands Maya (Docker worker image) through the VibeSecur
model broker (OpenRouter), a real payment service, and the trusted effect store.

Not an OpenShell boundary gate: the worker container uses host networking.
Requires OPENROUTER_API_KEY, or VIBESECUR_MODEL_PROVIDER=azure with AZURE_OPENAI_ENDPOINT/AZURE_OPENAI_API_KEY; VIBESECUR_ASSESSOR=jev enables the Jev assessment.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('VIBESECUR_MODEL_PROVIDER', 'openrouter')

from vibesecur.api import create_app  # noqa: E402
from vibesecur.worker import PaymentGateway  # noqa: E402

API_PORT, PAY_PORT = 8100, 8101
MODEL = os.environ.get('VIBESECUR_SMOKE_MODEL', 'openai/gpt-5-mini')
TEXT = os.environ.get('VIBESECUR_SMOKE_TEXT', 'Process the invoice and complete the payment')


class LocalOrigin:
    def host_origin(self, run, environment):
        return f'http://127.0.0.1:{PAY_PORT}'


def seed(store):
    run = store.create_run('kae', 'live')
    rid = run['runId']
    store.transition(rid, ['created'], 'prepared')
    env = run['protected']['environmentId']
    tx = store.transaction(env)
    approval = store.approve(env, tx, 'synthetic-demo-standing:kae')
    store.update_run(rid, standingDemoAuthorization={
        'source': 'trusted_demo_setup', 'provenance': 'user_configured_synthetic_demo',
        'owner': 'kae', 'runId': rid, 'workspaceId': tx['workspaceId'],
        'missionId': tx['missionId'], 'snapshot': tx, 'approvalId': approval['approvalId'],
        'createdAt': store.clock(), 'expiresAt': store.clock() + 3600})
    store.set_attempt(env, 'attempt-' + uuid.uuid4().hex[:8])
    store.enqueue_turn(rid, 'kae', TEXT, 'message-1')
    turn = store.claim_turn(rid, 'kae')
    store.set_turn_scope(rid, 'kae', turn['turnId'], 'pay_approved')
    return rid, env, turn


def wait_ready(url):
    for _ in range(100):
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    raise RuntimeError('service did not start: ' + url)


def main() -> int:
    key = ('OPENROUTER_API_KEY' if os.environ['VIBESECUR_MODEL_PROVIDER'] == 'openrouter'
           else 'AZURE_OPENAI_API_KEY')
    if not os.environ.get(key):
        raise SystemExit(key + ' is required')
    data = Path(tempfile.mkdtemp(prefix='vibesecur-smoke-'))
    app = create_app(data_dir=str(data), access_code='local-smoke', public_origin='http://127.0.0.1:8000',
                     payment_gateway=PaymentGateway('http://{environmentId}.invalid', provisioner=LocalOrigin()))
    store, security = app.state.store, app.state.security
    rid, env, turn = seed(store)
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=API_PORT, log_level='warning'))
    threading.Thread(target=server.run, daemon=True).start()
    wait_ready(f'http://127.0.0.1:{API_PORT}/health')
    payment = subprocess.Popen(
        [sys.executable, '-m', 'uvicorn', 'payment_app.app:create_app', '--factory',
         '--host', '127.0.0.1', '--port', str(PAY_PORT), '--log-level', 'warning'], cwd=ROOT,
        env={**os.environ, 'ENVIRONMENT_ID': env, 'EFFECT_STORE_URL': f'http://127.0.0.1:{API_PORT}',
             'EFFECT_STORE_TOKEN': security.issue_service_token(env, ttl=1800)})
    token = security.issue_model_lease('smoke-' + rid, MODEL.removeprefix('openai/'), ttl=1200,
                                       max_requests=40, max_output_tokens=4096, budget=3000000)
    try:
        wait_ready(f'http://127.0.0.1:{PAY_PORT}/health')
        mission = {'kind': 'employee_turn', 'scope': 'pay_approved', 'environment': 'protected',
                   'conversationId': str(uuid.uuid4()), 'turnId': str(uuid.UUID(turn['turnId'])),
                   'runId': rid, 'text': TEXT, 'applicationUrl': f'http://127.0.0.1:{PAY_PORT}',
                   'modelBaseUrl': f'http://127.0.0.1:{API_PORT}/model/v1', 'modelToken': token,
                   'model': MODEL, 'maxSteps': 30, 'reasoningEffort': 'low',
                   'profile': os.environ.get('VIBESECUR_MAYA_PROFILE', 'standard')}
        started = time.monotonic()
        worker = subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'host', '-e', 'HOME=/workspace',
                                 os.environ.get('VIBESECUR_SMOKE_IMAGE', 'vibesecur-worker:local'),
                                 'python', '/opt/vibesecur/worker_runtime/run.py', '-'],
                                input=json.dumps(mission), capture_output=True, text=True, timeout=900)
        events = []
        for line in worker.stdout.replace(token, '[REDACTED]').splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and str(item.get('kind', '')).startswith('worker.'):
                events.append(item)
        run = store.get_run(rid)
        report = {
            'workerExitCode': worker.returncode, 'elapsedSeconds': round(time.monotonic() - started, 1),
            'model': MODEL, 'assessor': os.environ.get('VIBESECUR_ASSESSOR') or 'laya-or-unavailable',
            'events': events,
            'paymentDecisions': [{k: item.get(k) for k in ('decision', 'reason', 'operationId')}
                                 | {'beneficiary': (item.get('attemptedTransaction') or {}).get('beneficiaryAccount')}
                                 for item in run.get('paymentDecisions', [])],
            'ledgerEntries': len(run['protected']['ledger']),
            'authorizedBeneficiary': store.transaction(env)['beneficiaryAccount'],
            'stderrTail': worker.stderr.replace(token, '[REDACTED]')[-1500:] if worker.returncode else '',
        }
        out = ROOT / 'artifacts' / 'local-maya-smoke.json'
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        return 0 if worker.returncode == 0 and report['ledgerEntries'] == 1 else 1
    finally:
        payment.terminate()
        server.should_exit = True


if __name__ == '__main__':
    raise SystemExit(main())
