"""Local live runtime: real OpenHands Maya in Docker and real payment services.

This runtime has no measured network boundary. It exists so the full employee
loop can run on a developer machine; every worker event is labeled
`unmeasured_local_docker` and it refuses to start unless explicitly enabled.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from uuid import UUID, uuid4

import httpx

from vibesecur.worker import WorkerAdapter

ROOT = Path(__file__).resolve().parents[1]
BOUNDARY = "unmeasured_local_docker"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LocalPaymentServices:
    """One payment_app process per environment, calling the trusted effect store."""

    def __init__(self, security, effect_store_url: str):
        self.security, self.effect_store_url = security, effect_store_url.rstrip("/")
        self._origins: dict[str, str] = {}
        self._processes: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

    def host_origin(self, run: dict, environment: str) -> str:
        if environment not in ("baseline", "protected"):
            raise ValueError("Unknown payment environment")
        environment_id = run[environment]["environmentId"]
        with self._lock:
            process = self._processes.get(environment_id)
            if process is not None and process.poll() is None:
                return self._origins[environment_id]
            port = _free_port()
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ENVIRONMENT_ID": environment_id,
                   "EFFECT_STORE_URL": self.effect_store_url,
                   "EFFECT_STORE_TOKEN": self.security.issue_service_token(environment_id, ttl=8 * 3600)}
            self._processes[environment_id] = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "payment_app.app:create_app", "--factory",
                 "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
                cwd=ROOT, env=env)
            origin = f"http://127.0.0.1:{port}"
            self._origins[environment_id] = origin
        for _ in range(100):
            try:
                if httpx.get(origin + "/health", timeout=1, trust_env=False).status_code == 200:
                    return origin
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        raise RuntimeError("Local payment service did not start")

    def teardown(self, run: dict) -> None:
        with self._lock:
            for environment in ("baseline", "protected"):
                process = self._processes.pop(run[environment]["environmentId"], None)
                if process is not None:
                    process.terminate()


class LocalDockerWorker:
    """Runs one Maya turn per container with a persisted conversation volume."""

    def __init__(self, config: dict, services: LocalPaymentServices):
        for key in ("image", "modelBaseUrl", "model", "artifactDir"):
            if not config.get(key):
                raise ValueError(f"Local worker requires {key}")
        if not callable(config.get("leaseFactory")):
            raise ValueError("Local worker requires a task-scoped model lease factory")
        self.config, self.services = dict(config), services
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def start(self, run: dict, environment: str, on_event) -> dict:
        raise ValueError("Local runtime supports employee conversation turns only")

    def run_turn(self, run: dict, turn: dict, on_event) -> dict:
        if run.get("mode") != "live":
            raise ValueError("Employee turn requires a live synthetic run")
        run_id = run["runId"]
        conversation_id = run["conversation"]["conversationId"]
        turn_id = turn["turnId"]
        UUID(conversation_id), UUID(turn_id)
        if (run["conversation"].get("activeTurnId") != turn_id or turn.get("status") != "running"
                or turn.get("scope") not in ("read_only", "pay_approved", "clarification")):
            raise ValueError("Employee turn is not the active scoped turn")
        task_id = f"worker-{run_id}-{turn_id}"
        token = run.get("workerModelToken")
        if run.get("workerModelTaskId") != task_id or not isinstance(token, str) or not token:
            raise ValueError("Employee turn requires a fresh scoped model lease")
        application_url = self.services.host_origin(run, "protected")
        volume = "vibesecur-conversation-" + UUID(conversation_id).hex
        subprocess.run(["docker", "volume", "create", "--label", "vibesecur.run-id=" + run_id, volume],
                       capture_output=True, text=True, timeout=15, check=True)
        job_id = "worker-" + uuid4().hex
        artifact_dir = Path(self.config["artifactDir"]).resolve() / job_id
        artifact_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        mission = {"kind": "employee_turn", "jobId": job_id, "runId": run_id, "turnId": turn_id,
                   "conversationId": conversation_id, "environment": "protected",
                   "scope": turn["scope"], "text": turn["text"], "applicationUrl": application_url,
                   "modelBaseUrl": self.config["modelBaseUrl"], "modelToken": token,
                   "model": self.config["model"],
                   "reasoningEffort": self.config.get("reasoningEffort", "low"),
                   "profile": self.config.get("profile", "standard"),
                   "maxSteps": min(int(self.config.get("maxSteps", 40)), 50)}
        timeout = min(int(self.config.get("timeoutSeconds", 600)), 900)
        command = ["docker", "run", "--rm", "-i", "--name", job_id, "--network", "host",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--pids-limit", "256", "--memory", "2g",
                   "-e", "HOME=/workspace", "-v", f"{volume}:/workspace/conversations",
                   self.config["image"], "python", "/opt/vibesecur/worker_runtime/run.py", "-"]
        on_event({"kind": "worker.started", "jobId": job_id, "taskId": task_id, "turnId": turn_id,
                  "runtime": "local-docker", "boundary": BOUNDARY, "source": "host_supervisor"})
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL,
                                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        with self._lock:
            self._jobs[job_id] = {"process": process, "state": "running", "runId": run_id}
        state, assistant, sdk_error, count = "failed", None, None, 0
        try:
            count, assistant, sdk_error = WorkerAdapter._stream_worker_output(
                process, mission, token, artifact_dir / "worker-events.jsonl", timeout, on_event)
            state = "finished" if process.returncode == 0 and assistant else "failed"
        except subprocess.TimeoutExpired:
            state = "timeout"
        except (OSError, ValueError, RuntimeError) as exc:
            sdk_error = type(exc).__name__
        finally:
            subprocess.run(["docker", "rm", "-f", job_id], capture_output=True, timeout=15, check=False)
            if process.poll() is None:
                process.kill()
        with self._lock:
            if self._jobs[job_id]["state"] == "cancelled":
                state = "cancelled"
            self._jobs[job_id]["state"] = state
        result = {"jobId": job_id, "taskId": task_id, "turnId": turn_id, "state": state,
                  "exitCode": process.returncode, "eventCount": count,
                  "conversationId": conversation_id, "boundary": BOUNDARY}
        if state == "finished":
            result["assistantText"] = assistant
        elif sdk_error:
            result["errorType"] = sdk_error
        on_event({"kind": "worker.finished", "jobId": job_id, "taskId": task_id, "turnId": turn_id,
                  "state": state, "exitCode": process.returncode, "source": "host_supervisor"})
        return result

    def cancel(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job["state"] = "cancelled"
        subprocess.run(["docker", "rm", "-f", job_id], capture_output=True, timeout=15, check=False)

    def teardown_conversation(self, run: dict) -> None:
        conversation_id = (run.get("conversation") or {}).get("conversationId")
        if conversation_id:
            subprocess.run(["docker", "volume", "rm", "-f",
                            "vibesecur-conversation-" + UUID(conversation_id).hex],
                           capture_output=True, timeout=15, check=False)
        self.services.teardown(run)


def local_runtime_from_env(security) -> tuple[LocalDockerWorker, LocalPaymentServices] | None:
    if os.environ.get("VIBESECUR_WORKER_RUNTIME") != "local-docker":
        return None
    if os.environ.get("VIBESECUR_LOCAL_UNMEASURED_BOUNDARY") != "1":
        raise ValueError("local-docker runtime requires VIBESECUR_LOCAL_UNMEASURED_BOUNDARY=1")
    api_url = os.environ.get("VIBESECUR_LOCAL_API_URL", "http://127.0.0.1:8000")
    model = os.environ.get("VIBESECUR_WORKER_MODEL", "gpt-6-luna").removeprefix("openai/")
    services = LocalPaymentServices(security, api_url)
    worker = LocalDockerWorker({
        "image": os.environ.get("VIBESECUR_LOCAL_WORKER_IMAGE", "vibesecur-worker:local"),
        "modelBaseUrl": api_url + "/model/v1", "model": "openai/" + model,
        "artifactDir": os.environ.get("VIBESECUR_LOCAL_ARTIFACT_DIR", str(ROOT / "artifacts" / "local-worker")),
        "reasoningEffort": os.environ.get("VIBESECUR_WORKER_REASONING", "low"),
        "profile": os.environ.get("VIBESECUR_MAYA_PROFILE", "standard"),
        "leaseFactory": lambda task_id: security.issue_model_lease(
            task_id, model, ttl=900, max_requests=40, max_output_tokens=4096)}, services)
    return worker, services
