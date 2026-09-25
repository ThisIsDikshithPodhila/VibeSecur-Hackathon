"""Launch and observe one authenticated live synthetic OpenHands run on the VM."""
import json
import os
from pathlib import Path
import time
import uuid

import httpx


def main() -> None:
    origin = os.environ["PUBLIC_ORIGIN"]
    if origin.rstrip('/') != 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com':
        raise ValueError('Only the owned HTTPS demo origin is allowed')
    with httpx.Client(base_url=origin, timeout=45, trust_env=False) as client:
        login = client.post("/api/session", json={"accessCode": os.environ["PRESENTER_ACCESS_CODE"]},
                            headers={"Origin": origin, "Idempotency-Key": "live-login-" + uuid.uuid4().hex})
        assert login.status_code == 200, f"login HTTP {login.status_code}"
        csrf = login.json()["csrfToken"]

        def post(path, body):
            response = client.post(path, json=body,
                                   headers={"Origin": origin, "X-CSRF-Token": csrf,
                                            "Idempotency-Key": "live-" + uuid.uuid4().hex})
            assert response.status_code == 200, f"{path} HTTP {response.status_code}: {response.text[:240]}"
            return response.json()

        run = post("/api/runs", {"mode": "live"})
        run_id = run["runId"]
        print("runId=" + run_id, flush=True)
        run = post(f"/api/runs/{run_id}/commands/start", {})["run"]
        for environment in ("baseline", "protected"):
            env = run[environment]
            snapshot = {"environmentId": env["environmentId"], "workspaceId": env["workspaceId"],
                        "missionId": env["missionId"], **env["invoice"], **env["supplier"]}
            post(f"/api/runs/{run_id}/approve-payment",
                 {"environment": environment, "snapshot": snapshot})
            print("approved=" + environment, flush=True)
        deadline = time.monotonic() + 720
        last = None
        while time.monotonic() < deadline:
            response = client.get(f"/api/runs/{run_id}")
            assert response.status_code == 200, f"get run HTTP {response.status_code}"
            run = response.json()
            live = run.get("liveAgent") or {}
            progress = (run["state"], live.get("status"),
                        tuple(sorted(live.get("jobs", {}).items())),
                        tuple(sorted((key, value.get("state")) for key, value in live.get("results", {}).items())))
            if progress != last:
                print("progress=" + json.dumps(progress), flush=True)
                last = progress
            if run["state"] in ("contained", "inconclusive", "held", "cancelled"):
                break
            time.sleep(5)
        live = run.get("liveAgent") or {}
        incident = run.get("incident") or {}
        summary = {"runId": run_id, "state": run["state"],
                   "incidentStatus": incident.get("status"), "source": incident.get("source"),
                   "infrastructureError": incident.get("infrastructureError"),
                   "baselineLedgerCount": len(run["baseline"]["ledger"]),
                   "protectedLedgerCount": len(run["protected"]["ledger"]),
                   "workerResults": incident.get("workerResults"), "liveAgentStatus": live.get("status"),
                   "jobs": live.get("jobs"),
                   "workerEventCount": sum(event["kind"] == "live_agent.event" for event in run["events"]),
                   "eventCount": len(run["events"])}
        output = Path("/srv/vibesecur/app/artifacts/gates/live-run.json")
        output.write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
