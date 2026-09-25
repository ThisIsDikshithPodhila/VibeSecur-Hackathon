#!/usr/bin/env python3
"""Authorize and observe one presenter-scoped repair on the hosted API."""
import json
import os
from pathlib import Path
import time
import uuid

import httpx


def main() -> None:
    run_id = os.environ['VIBESECUR_REPAIR_RUN_ID']
    if not run_id.startswith('run-') or len(run_id) != 36:
        raise ValueError('Invalid synthetic run ID')
    origin = os.environ['PUBLIC_ORIGIN']
    if origin.rstrip('/') != 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com':
        raise ValueError('Only the owned HTTPS demo origin is allowed')
    with httpx.Client(base_url=origin, timeout=45, trust_env=False) as client:
        login = client.post('/api/session', json={'accessCode': os.environ['PRESENTER_ACCESS_CODE']},
                            headers={'Origin': origin, 'Idempotency-Key': 'repair-login-'+uuid.uuid4().hex})
        login.raise_for_status()
        csrf = login.json()['csrfToken']
        check = client.get('/api/runs/'+run_id)
        check.raise_for_status()
        run = check.json()
        if run['state'] != 'contained' or (run.get('incident') or {}).get('status') != 'reproduced' or not run.get('investigation'):
            raise RuntimeError('Existing run is not a grounded contained incident')
        command = client.post('/api/runs/'+run_id+'/commands/authorize-repair', json={},
                              headers={'Origin': origin, 'X-CSRF-Token': csrf,
                                       'Idempotency-Key': 'repair-authorize-'+uuid.uuid4().hex})
        command.raise_for_status()
        print('authorized=' + run_id, flush=True)
        deadline = time.monotonic()+720
        last = None
        while time.monotonic() < deadline:
            response = client.get('/api/runs/'+run_id)
            response.raise_for_status()
            run = response.json()
            repair, proof = run.get('repair') or {}, run.get('verification') or {}
            progress = (run['state'], repair.get('status'), repair.get('jobId'), proof.get('state'))
            if progress != last:
                print('progress=' + json.dumps(progress), flush=True)
                last = progress
            if run['state'] in ('held', 'verified', 'deployed', 'cancelled'):
                break
            time.sleep(5)
        repair, proof = run.get('repair') or {}, run.get('verification') or {}
        summary = {'runId': run_id, 'state': run['state'], 'repairStatus': repair.get('status'),
                   'jobId': repair.get('jobId'), 'patchPath': repair.get('patchPath'),
                   'artifactDigest': repair.get('artifactDigest'), 'reason': repair.get('reason'),
                   'verificationState': proof.get('state'), 'verificationPassed': proof.get('passed'),
                   'verificationArtifactDigest': proof.get('artifactDigest'),
                   'testCount': len(proof.get('tests') or []), 'eventCount': len(run['events'])}
        output = Path('/srv/vibesecur/app/artifacts/gates/repair-live-'+run_id+'.json')
        output.write_text(json.dumps(summary, indent=2)+'\n')
        print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
