#!/usr/bin/env python3
"""Copy recorded aggregate counts into presenter data; never execute evaluations."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
rows = []
for treatment, label in (('baseline', 'Baseline'), ('deterministic', 'Deterministic controls'),
                         ('deterministic_laya', 'Controls + Laya')):
    path = ROOT / 'evaluations/reports' / (treatment + '-current.json')
    row = {'treatment': treatment, 'label': label, 'status': 'not_recorded'}
    if path.is_file():
        raw = path.read_bytes()
        report = json.loads(raw)
        metrics = report.get('metrics', {})
        counts = metrics.get('outcomeCounts', {})
        row.update(status=report['status'], sampleSize=report['sampleSize'],
                   recordedAt=report.get('finishedAt'), fixtureVersion=report.get('fixtureVersion'),
                   sourceSha256=hashlib.sha256(raw).hexdigest(),
                   sourcePath=str(path.relative_to(ROOT)),
                   completed=counts.get('authorized_completion'),
                   unauthorizedEffects=counts.get('effect'), notRun=counts.get('not_run'),
                   policyRejections=counts.get('policy_reject'),
                   safeLifecycle=counts.get('safe_lifecycle'),
                   infrastructureErrors=counts.get('infrastructure_error'),
                   timeouts=counts.get('timeout'),
                   legitimateCases=metrics.get('categoryDenominators', {}).get('legitimate'))
    rows.append(row)
output = ROOT / 'apps/presenter/src/evaluation-summary.json'
output.write_text(json.dumps({'track': 'deterministic_replay', 'rows': rows,
    'limitations': ['Recorded in-process replay results, separate from live-agent trials.',
                    'Partial coverage; unrun cases are included in each sample size.',
                    'No accuracy, savings or Laya contribution claim is implied.',
                    'Semantic assessment, live trials and repair verification are separate evidence tracks.']},
    indent=2) + '\n')
print(f'Wrote {len(rows)} aggregate treatment rows to {output.relative_to(ROOT)}; no evaluations ran.')
