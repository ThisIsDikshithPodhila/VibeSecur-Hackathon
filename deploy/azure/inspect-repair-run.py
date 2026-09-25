#!/usr/bin/env python3
"""Print bounded hosted repair and deployment state for one presenter run."""
import json
import os
import uuid

import httpx


def main():
    origin = os.environ['PUBLIC_ORIGIN']
    if origin.rstrip('/') != 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com':
        raise ValueError('Only the owned HTTPS demo origin is allowed')
    run_id = os.environ['VIBESECUR_REPAIR_RUN_ID']
    with httpx.Client(base_url=origin, timeout=45, trust_env=False) as client:
        login = client.post('/api/session', json={'accessCode': os.environ['PRESENTER_ACCESS_CODE']},
                            headers={'Origin': origin, 'Idempotency-Key': 'inspect-login-'+uuid.uuid4().hex})
        login.raise_for_status()
        response = client.get('/api/runs/'+run_id)
        response.raise_for_status()
        run = response.json()
    repair = run.get('repair') or {}
    proof = run.get('verification') or {}
    deployment = repair.get('deployment') or {}
    probe = repair.get('deploymentProbe') or {}
    output = {
        'runId': run_id,
        'state': run['state'],
        'repairStatus': repair.get('status'),
        'artifactDigest': repair.get('artifactDigest'),
        'proofPassed': proof.get('passed'),
        'proofState': proof.get('state'),
        'outerContainment': proof.get('outerContainment'),
        'sourceSha256': (proof.get('sourceReview') or {}).get('sourceSha256'),
        'deployedAt': repair.get('deployedAt'),
        'deployment': {key: deployment.get(key) for key in
                       ('deployed', 'artifactDigest', 'imageDigest', 'sourceSha256')},
        'deploymentProbe': {key: probe.get(key) for key in
                            ('artifactDigest', 'imageDigest', 'sourceSha256',
                             'paymentRouteReady', 'separateService', 'containerId',
                             'baselineContainerId', 'httpStatus')},
        'protectedCompensatingRule': run['protected'].get('compensatingRule'),
        'baselineLedgerCount': len(run['baseline'].get('ledger') or []),
        'protectedLedgerCount': len(run['protected'].get('ledger') or []),
        'recentEvents': [(event['sequence'], event['kind']) for event in run['events'][-10:]],
    }
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
