"""Run a bounded real OpenHands SDK smoke inside the ready OpenShell sandbox."""
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from vibesecur.auth import SecurityStore


def main() -> None:
    data_dir = Path(os.environ["VIBESECUR_DATA_DIR"])
    security = SecurityStore(str(data_dir / "security.sqlite"))
    task_id = "worker-smoke-" + uuid.uuid4().hex
    token = security.issue_model_lease(task_id, "gpt-6-sol", ttl=120,
                                       max_requests=3, max_output_tokens=2000, budget=100000)
    mission = {"jobId": task_id, "runId": "run-smoke", "environment": "baseline",
               "applicationUrl": "http://payment-env-b6141311d7254b6f8f7293c6b2012266:8000",
               "modelBaseUrl": "http://host.openshell.internal:8000/model/v1",
               "modelToken": token, "model": "openai/gpt-6-sol", "maxSteps": 1}
    try:
        started = time.monotonic()
        process = subprocess.run(["/home/demo/.local/bin/openshell", "sandbox", "exec",
                                  "--name", "vs-worker-smoke3", "--timeout", "90", "--no-tty", "--",
                                  "python", "/opt/vibesecur/worker_runtime/run.py", "-"],
                                 input=json.dumps(mission), capture_output=True, text=True, timeout=100)
        events = []
        for line in process.stdout.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("kind", "").startswith("worker."):
                events.append(json.loads(json.dumps(item).replace(token, "[REDACTED]")))
        path = Path("/srv/vibesecur/app/artifacts/gates/openhands-sdk-smoke.jsonl")
        path.write_text("".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events))
        print(json.dumps({"exitCode": process.returncode, "elapsedSeconds": round(time.monotonic() - started, 2),
                          "eventKinds": [event["kind"] for event in events],
                          "errorTypes": [event.get("payload", {}).get("errorType") for event in events
                                         if event["kind"] == "worker.sdk_error"],
                          "stderrTail": process.stderr[-250:].replace(token, "[REDACTED]")}, indent=2))
    finally:
        security.revoke_task(task_id)


if __name__ == "__main__":
    main()
