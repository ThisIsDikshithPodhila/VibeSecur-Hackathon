"""Investigate and export one synthetic hosted run from the trusted VM."""
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

import httpx


def main(run_id: str, destination: str) -> None:
    if not run_id.startswith("run-") or len(run_id) != 36:
        raise ValueError("Invalid synthetic run ID")
    output = Path(destination).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    origin = os.environ["PUBLIC_ORIGIN"]
    if origin.rstrip('/') != 'https://vibesecur-demo-20260925.centralindia.cloudapp.azure.com':
        raise ValueError('Only the owned HTTPS demo origin is allowed')
    with httpx.Client(base_url=origin, timeout=180, trust_env=False) as client:
        response = client.post("/api/session", json={"accessCode": os.environ["PRESENTER_ACCESS_CODE"]},
                               headers={"Origin": origin, "Idempotency-Key": "export-login-" + uuid.uuid4().hex})
        assert response.status_code == 200, f"login HTTP {response.status_code}"
        csrf = response.json()["csrfToken"]
        response = client.post(f"/api/runs/{run_id}/commands/investigate", json={}, headers={
            "Origin": origin, "X-CSRF-Token": csrf,
            "Idempotency-Key": "export-investigate-" + uuid.uuid4().hex})
        assert response.status_code == 200, f"investigate HTTP {response.status_code}: {response.text[:240]}"
        run = response.json()["run"]
        status = (run.get("investigation") or {}).get("modelStatus")
        result = {"runId": run_id, "modelStatus": status, "files": {}}
        for name in ("evidence.jsonl", "reproduction.zip", "incident.md"):
            response = client.get(f"/api/runs/{run_id}/exports/{name}")
            assert response.status_code == 200, f"export {name} HTTP {response.status_code}"
            path = output / name
            path.write_bytes(response.content)
            result["files"][name] = {"sha256": hashlib.sha256(response.content).hexdigest(),
                                     "bytes": len(response.content)}
        (output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: export-run.py RUN_ID OUTPUT_DIRECTORY")
    main(sys.argv[1], sys.argv[2])
