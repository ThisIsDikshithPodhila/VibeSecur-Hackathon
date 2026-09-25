"""Exercise the actual OpenShell adapter against an existing synthetic run.

This smoke uses one model iteration and cannot be labelled a completed incident.
"""
import json
import os
from pathlib import Path
import sys

from vibesecur.auth import SecurityStore
from vibesecur.store import Store
from vibesecur.worker import WorkerAdapter


def main(run_id: str) -> None:
    data_dir = Path(os.environ["VIBESECUR_DATA_DIR"])
    security = SecurityStore(str(data_dir / "security.sqlite"))
    store = Store(str(data_dir / "effects.sqlite"))
    run = store.get_run(run_id)
    config = {
        "runtime": "openshell", "networkVerified": True,
        "network": "vibesecur-worker-internal",
        "image": "sha256:b28f957d25f4ac27294d7e63aad42e26400dd602542c9e9ff1f970168c730c59",
        "imageRef": "vibesecur-worker:1.49.5",
        "artifactDir": "/srv/vibesecur/data/workers",
        "applicationUrl": "http://payment-{environmentId}:8000",
        "modelBaseUrl": "http://host.openshell.internal:8000/model/v1",
        "model": "openai/gpt-6-sol", "maxSteps": 1, "timeoutSeconds": 120,
        "boundaryEvidencePath": "/srv/vibesecur/app/artifacts/gates/openshell-worker-boundary-owned-demo-v1.json",
        "policyTemplatePath": "/srv/vibesecur/app/deploy/policies/openshell-worker.yaml.template",
        "openshellCli": "/home/demo/.local/bin/openshell",
        "leaseFactory": lambda task_id: security.issue_model_lease(task_id, "gpt-6-sol", ttl=180,
                                                                  max_requests=3, max_output_tokens=2000,
                                                                  budget=100000),
    }
    adapter = WorkerAdapter(config)
    observed = []
    def record(event):
        observed.append(event.get("kind"))
    try:
        result = adapter.start(run, "baseline", record)
        summary = {"runId": run_id, "jobId": result["jobId"], "state": result["state"],
                   "exitCode": result["exitCode"], "eventCount": result["eventCount"],
                   "stderrTail": result["stderrTail"],
                   "eventKinds": observed, "artifactDir": adapter.collect_artifacts(result["jobId"])["artifactDir"]}
        path = Path("/srv/vibesecur/app/artifacts/gates/worker-adapter-smoke.json")
        path.write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
    finally:
        security.revoke_task(f"worker-{run_id}-baseline")


if __name__ == "__main__":
    main(sys.argv[1])
