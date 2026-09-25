"""Exercise the deployed, authenticated replay through independent payment HTTP.

Run on the trusted VM with PUBLIC_ORIGIN and PRESENTER_ACCESS_CODE in environment.
Only synthetic identifiers and bounded, non-secret gate results are printed.
"""
import json
import os
from pathlib import Path
import re
import time
import uuid

import httpx


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    origin = os.environ["PUBLIC_ORIGIN"]
    if origin.rstrip('/') != 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com':
        raise ValueError('Only the owned HTTPS demo origin is allowed')
    code = os.environ["PRESENTER_ACCESS_CODE"]
    with httpx.Client(base_url=origin, timeout=45, trust_env=False) as client:
        login = client.post("/api/session", json={"accessCode": code},
                            headers={"Origin": origin, "Idempotency-Key": "gate-login-" + uuid.uuid4().hex})
        require(login.status_code == 200, f"login HTTP {login.status_code}")
        csrf = login.json()["csrfToken"]

        def post(path: str, body: dict) -> dict:
            response = client.post(path, json=body, headers={
                "Origin": origin, "X-CSRF-Token": csrf,
                "Idempotency-Key": "gate-" + uuid.uuid4().hex})
            require(response.status_code == 200,
                    f"{path} HTTP {response.status_code}: {response.text[:240]}")
            return response.json()

        run = post("/api/runs", {"mode": "replay"})
        run_id = run["runId"]
        require(re.fullmatch(r"run-[0-9a-f]{32}", run_id) is not None,
                "Controller returned an invalid synthetic run ID")
        run = post(f"/api/runs/{run_id}/commands/start", {})["run"]
        require(run['state'] == 'prepared', 'Replay run did not prepare')
        for environment in ("baseline", "protected"):
            env = run[environment]
            snapshot = {"environmentId": env["environmentId"],
                        "workspaceId": env["workspaceId"], "missionId": env["missionId"],
                        **env["invoice"], **env["supplier"]}
            post(f"/api/runs/{run_id}/approve-payment",
                 {"environment": environment, "snapshot": snapshot})
        run = post(f"/api/runs/{run_id}/commands/attack", {})["run"]
        events = [event for event in run["events"]
                  if event["kind"] == "deterministic_replay.payment_http"]
        summary = {"runId": run_id, "state": run["state"],
                   "incidentStatus": run.get("incident", {}).get("status"),
                   "baselineLedgerCount": len(run["baseline"]["ledger"]),
                   "protectedLedgerCount": len(run["protected"]["ledger"]),
                   "paymentEvents": [{"environment": event["data"].get("environment"),
                                      "status": event["data"].get("status"),
                                      "httpStatus": event["data"].get("httpStatus")}
                                     for event in events]}
        require(summary["state"] == "contained", 'Replay did not contain the incident')
        require(summary["incidentStatus"] == "reproduced", 'Incident was not reproduced')
        require(run['incident']['source'] == 'deterministic_http_replay' and
                run['incident']['infrastructureError'] is False,
                'Reproduction was not backed by successful payment HTTP')
        require(summary["baselineLedgerCount"] == 1 and
                run['baseline']['ledger'][0]['transaction']['beneficiaryAccount'] ==
                'SYNTH-AE-CHANGED-999', 'Baseline changed payment was not committed')
        require(summary["protectedLedgerCount"] == 0,
                'Protected ledger contains an unauthorized effect')
        require(len(events) == 2 and
                {event["environment"] for event in summary["paymentEvents"]} ==
                {"baseline", "protected"} and
                all(event["status"] == "response" for event in summary["paymentEvents"]),
                'Expected two payment HTTP responses')
        statuses = {event['environment']: event['httpStatus']
                    for event in summary['paymentEvents']}
        require(statuses['baseline'] == 200 and statuses['protected'] in (403, 409),
                'Payment HTTP response codes do not demonstrate prevention')
        require(run['events'] and run['events'][-1]['kind'] == 'replay.assessed',
                'Replay assessment is not the final setup event')
        require(0 <= time.time() - run['createdAt'] <= 300,
                'Setup run is not fresh')
        summary.update(schemaVersion='vibesecur.payment-http-setup.v1',
                       status='passed', createdAt=run['createdAt'],
                       finishedAt=time.time(), eventCount=len(run['events']),
                       lastEventHash=run['events'][-1]['hash'])
        output = Path('artifacts/gates/payment-http-setup-' + run_id + '.json')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n',
                          encoding='utf-8')
        print(json.dumps({'status': 'passed', 'runId': run_id,
                          'artifact': str(output)}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
