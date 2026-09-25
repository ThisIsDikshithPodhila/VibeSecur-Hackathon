#!/usr/bin/env python3
"""Remeasure live deployment boundaries; publish only complete passing records."""
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from vibesecur.auth import SecurityStore
from vibesecur.store import Store
from vibesecur.worker import PaymentServiceProvisioner
from scripts.gate_boundary import gate
from deploy.repair.gate import gate as repair_gate
from deploy.repair.gate_verifier import gate as verifier_gate


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=120).stdout


def publish(path, report):
    if report.get('passed') is not True:
        path.with_suffix('.failed.json').write_text(json.dumps(report, indent=2))
        raise RuntimeError(str(path.name) + ': ' + str(report.get('reason', report.get('coverage'))))
    temporary = path.with_suffix('.next')
    temporary.write_text(json.dumps(report, indent=2))
    temporary.replace(path)
    print(json.dumps({'gate': path.name, 'passed': True}), flush=True)


def main():
    for line in Path('/srv/vibesecur/.env.private').read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            os.environ[key] = value.strip().strip('"').strip("'")
    data = Path(os.environ['VIBESECUR_DATA_DIR'])
    with sqlite3.connect(data / 'effects.sqlite') as db:
        if db.execute("SELECT 1 FROM runs WHERE json_extract(data, '$.state') IN ('repairing','verifying') LIMIT 1").fetchone():
            print('Boundary refresh deferred until active verification finishes', flush=True)
            return
    output = data / 'gates' 
    output.mkdir(exist_ok=True)
    security = SecurityStore(str(data / 'security.sqlite'))
    store = Store(str(data / 'effects.sqlite'))
    marker = output / 'run-id'
    if marker.exists():
        run = store.get_run(marker.read_text().strip())
    else:
        run = store.create_run('deployment-boundary-probe', 'live')
        marker.write_text(run['runId'])
    services = PaymentServiceProvisioner({'image': os.environ['VIBESECUR_PAYMENT_IMAGE'],
                                         'network': os.environ['VIBESECUR_PAYMENT_NETWORK']}, security)
    services.ensure(run)
    endpoints = {arm: services.worker_endpoint(run, arm) for arm in ('protected', 'baseline')}
    infos = {arm: json.loads(command('docker', 'inspect', 'payment-' + run[arm]['environmentId']))[0]
             for arm in endpoints}
    template = ROOT / 'deploy/policies/openshell-worker.yaml.template'
    network = os.environ['VIBESECUR_WORKER_NETWORK']
    config = {'runtime': 'openshell', 'network': network, 'image': os.environ['VIBESECUR_WORKER_IMAGE'],
              'sandbox': 'vs-release-gate', 'policyTemplatePath': str(template), 'sourceRunId': run['runId']}
    for arm, prefix in [('protected', 'payment'), ('baseline', 'otherPayment')]:
        info = infos[arm]
        config.update({prefix+'Host': 'payment-'+run[arm]['environmentId'], prefix+'Ip': info['NetworkSettings']['Networks'][network]['IPAddress'],
                       prefix+'ContainerId': info['Id'], prefix+'ImageDigest': info['Image'], prefix+'EnvironmentId': run[arm]['environmentId']})
    policy = output / 'worker-policy.yaml'
    policy.write_text(template.read_text().replace('__PAYMENT_IP__', config['paymentIp']))
    cli = os.environ['VIBESECUR_WORKER_OPENSHELL_CLI']
    subprocess.run([cli, 'sandbox', 'delete', config['sandbox']], capture_output=True, timeout=30)
    try:
        command(cli, 'sandbox', 'create', '--name', config['sandbox'], '--from', os.environ['VIBESECUR_WORKER_IMAGE_REF'],
                '--policy', str(policy), '--cpu', '1', '--memory', '1Gi', '--detach', '--', 'sleep', '600')
        for _ in range(60):
            rows = json.loads(command(cli, 'sandbox', 'list', '--output', 'json'))
            if any(row.get('name') == config['sandbox'] and row.get('phase') == 'Ready' for row in rows): break
            time.sleep(1)
        publish(output/'worker.json', gate(config))
    finally:
        subprocess.run([cli, 'sandbox', 'delete', config['sandbox']], capture_output=True, timeout=30)
    repair_config = {'image': os.environ['VIBESECUR_REPAIR_IMAGE'], 'network': os.environ['VIBESECUR_REPAIR_NETWORK'],
                     'uplinkNetwork': 'openshell-docker', 'relayConfigPath': str(ROOT/'deploy/repair/Caddyfile'),
                     'relayImage': 'sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d',
                     'paymentHost': config['paymentHost'], 'artifactDir': str(output)}
    publish(output/'repair.json', repair_gate(repair_config))
    publish(output/'verifier.json', verifier_gate({'network': os.environ['VIBESECUR_VERIFIER_NETWORK'],
                                                 'trustedImage': os.environ['VIBESECUR_VERIFIER_TRUSTED_IMAGE']}))
    pid = command('systemctl', 'show', 'vibesecur-api', '--property=MainPID', '--value').strip()
    if pid.isdigit() and int(pid) and b'VIBESECUR_EMPLOYEE_WORKER_ENABLED=0' in Path('/proc/'+pid+'/environ').read_bytes().split(b'\0'):
        command('sudo', '-n', 'systemctl', 'restart', 'vibesecur-api')

if __name__ == '__main__':
    main()
