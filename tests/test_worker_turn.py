"""Employee turn contract: real SDK events, native state, and scoped host input."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time
import tomllib
from uuid import uuid4

import pytest

from worker_runtime.run import assistant_text_from_event, turn_activity_from_event
from vibesecur.worker import WorkerAdapter, _presenter_worker_event


def test_read_only_policy_excludes_payment_and_purchase_order_writes():
    from deploy.openshell.employee_policy import render_turn_policy

    template = Path("deploy/policies/openshell-worker.yaml.template")
    host = "172.30.0.3"
    pay_yaml, pay = render_turn_policy(template, host, "pay_approved")
    read_yaml, read = render_turn_policy(template, host, "read_only")
    assert pay_yaml.count("allow: {method: POST, path: /api/payments}") == 1
    assert "allow: {method: POST, path: /api/payments}" not in read_yaml
    expected_rules = pay["network_policies"]["invoice_application"]["endpoints"][0]["rules"]
    read_rules = read["network_policies"]["invoice_application"]["endpoints"][0]["rules"]
    assert len(expected_rules) == len(read_rules) + 2
    assert all(rule["allow"]["method"] == "GET" for rule in read_rules)
    assert {"allow": {"method": "GET", "path": "/api/inventory"}} in read_rules
    assert {"allow": {"method": "POST", "path": "/api/payments"}} not in read_rules
    with pytest.raises(ValueError, match="scope"):
        render_turn_policy(template, host, "pending")
    config = tomllib.loads(Path("deploy/openshell/gateway.toml").read_text())
    docker = config["openshell"]["drivers"]["docker"]
    assert docker["allow_driver_config"] is True
    assert docker["enable_bind_mounts"] is False
    assert docker["resource_admission"]["enabled"] is True
    assert docker["resource_admission"]["required_labels"] == {
        "openshell.ai/sandbox-attachable": "true",
        "openshell.ai/sandbox-attachable-workspace": "default"}


def test_activity_uses_sdk_call_identity_without_exposing_arguments():
    action = {"id": "event-1", "tool_name": "terminal", "tool_call_id": "call-1",
              "action": {"command": "private content"}, "thought": "private reasoning"}
    started = turn_activity_from_event("ActionEvent", action, "turn-1")
    assert started == {"turnId": "turn-1", "toolCallId": "call-1", "tool": "terminal",
                       "status": "started", "title": "Terminal action",
                       "description": "Terminal tool call started", "sdkEventId": "event-1"}
    assert "private" not in json.dumps(started)
    observed = turn_activity_from_event(
        "ObservationEvent", {"id": "event-2", "tool_name": "terminal",
                             "tool_call_id": "call-1", "observation": {"is_error": True,
                                                                          "content": "secret"}}, "turn-1")
    assert observed["status"] == "failed"
    assert observed["toolCallId"] == started["toolCallId"]
    assert "secret" not in json.dumps(observed)
    assert turn_activity_from_event("ActionEvent", {**action, "tool_name": "unknown"}, "turn-1") is None


def test_assistant_message_only_uses_agent_text_content():
    body = {"id": "message-1", "source": "agent", "llm_message": {
        "role": "assistant", "content": [{"type": "text", "text": "The approved invoice is ready."}],
        "thinking_blocks": [{"thinking": "private"}], "reasoning_content": "private"}}
    assert assistant_text_from_event("MessageEvent", body) == (
        "The approved invoice is ready.", "message-1")
    assert assistant_text_from_event("MessageEvent", {**body, "source": "user"}) is None
    assert assistant_text_from_event("MessageEvent", {**body, "llm_message": {
        "role": "assistant", "content": [{"type": "image", "image_urls": ["private"]}]}}) is None
    assert assistant_text_from_event("ActionEvent", body) is None


def test_runtime_turn_reuses_native_sdk_persistence_and_fresh_agent(monkeypatch, tmp_path):
    """A fake Conversation exercises the exact SDK constructor contract without a model."""
    import sys
    from types import ModuleType, SimpleNamespace
    from worker_runtime import run as runtime

    calls = []

    class FakeEvent:
        def __init__(self, kind, body):
            self.kind, self.body = kind, body

        def model_dump(self, **_kwargs):
            return self.body

    FakeEvent.__name__ = "MessageEvent"

    class FakeConversation:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.path = Path(kwargs["persistence_dir"]) / kwargs["conversation_id"].hex
            self.path.mkdir(parents=True, exist_ok=True)
            self.previous = json.loads((self.path / "base_state.json").read_text()) if (
                self.path / "base_state.json").exists() else []
            calls.append(self)

        def send_message(self, text):
            self.text = text

        def run(self):
            history = self.previous + [self.text]
            (self.path / "base_state.json").write_text(json.dumps(history))
            self.kwargs["callbacks"][0](FakeEvent("MessageEvent", {
                "id": "event-" + str(len(history)), "source": "agent",
                "llm_message": {"role": "assistant", "content": [{"type": "text",
                    "text": "Saw " + str(len(history)) + " turns"}]}}))

        def close(self):
            self.closed = True

    sdk = ModuleType("openhands.sdk")
    sdk.LLM = lambda **kwargs: SimpleNamespace(**kwargs)
    sdk.Agent = lambda **kwargs: SimpleNamespace(**kwargs)
    sdk.AgentContext = lambda **kwargs: SimpleNamespace(**kwargs)
    sdk.Conversation = FakeConversation
    tools = ModuleType("openhands.sdk.tool")
    tools.Tool = lambda name: SimpleNamespace(name=name)
    browser = ModuleType("openhands.tools.browser_use")
    browser.BrowserToolSet = SimpleNamespace(name="browser")
    editor = ModuleType("openhands.tools.file_editor")
    editor.FileEditorTool = SimpleNamespace(name="file_editor")
    terminal = ModuleType("openhands.tools.terminal")
    terminal.TerminalTool = SimpleNamespace(name="terminal")
    pydantic = ModuleType("pydantic")
    pydantic.SecretStr = lambda value: value
    for name, module in {"pydantic": pydantic, "openhands": ModuleType("openhands"),
                         "openhands.sdk": sdk, "openhands.sdk.tool": tools,
                         "openhands.tools": ModuleType("openhands.tools"),
                         "openhands.tools.browser_use": browser,
                         "openhands.tools.file_editor": editor,
                         "openhands.tools.terminal": terminal}.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(runtime, "TURN_PERSISTENCE_DIR", tmp_path)
    emitted = []
    monkeypatch.setattr(runtime, "emit", lambda kind, payload=None: emitted.append((kind, payload)))
    conversation_id = str(uuid4())
    base = {"kind": "employee_turn", "conversationId": conversation_id,
            "applicationUrl": "http://payment-env:8000", "modelBaseUrl": "http://relay/model/v1",
            "model": "openai/gpt-6-luna", "maxSteps": 5, "scope": "read_only",
            "runId": "run-" + "a" * 32, "environment": "protected"}
    for index in (1, 2):
        mission = {**base, "turnId": str(uuid4()), "text": "Maya turn " + str(index),
                   "modelToken": "fresh-" + str(index)}
        assert runtime.run_turn_mission(mission) == 0
        assert calls[-1].previous == ["Maya turn 1"] if index == 2 else calls[-1].previous == []
        assert calls[-1].kwargs["delete_on_close"] is False
        assert calls[-1].closed is True
    replies = [payload["text"] for kind, payload in emitted if kind == "worker.assistant"]
    assert replies == ["Saw 1 turns", "Saw 2 turns"]
    assert calls[0].kwargs["agent"].llm.api_key == "fresh-1"
    assert calls[1].kwargs["agent"].llm.api_key == "fresh-2"
    briefing = calls[0].kwargs["agent"].agent_context.system_message_suffix
    assert "http://payment-env:8000/api/context" in briefing
    assert "http://payment-env:8000/api/payments" in briefing
    assert "fresh-1" not in briefing


def test_runtime_turn_rejects_missing_scope_or_conversation_before_sdk(monkeypatch):
    from worker_runtime import run as runtime

    with pytest.raises(ValueError, match="scope"):
        runtime.validate_turn_mission({"scope": "pending"})
    with pytest.raises(ValueError, match="conversation"):
        runtime.validate_turn_mission({"scope": "read_only", "conversationId": "invalid"})


def test_host_projection_keeps_call_id_but_drops_worker_arguments():
    event = {"kind": "worker.activity", "payload": {
        "turnId": str(uuid4()), "toolCallId": "call-7", "tool": "terminal",
        "status": "started", "title": "Terminal action",
        "description": "Terminal tool call started", "command": "private command"}}
    projected = _presenter_worker_event(event)
    assert projected["payload"]["toolCallId"] == "call-7"
    assert projected["payload"]["title"] == "Terminal action"
    assert projected["payload"]["description"] == "Terminal tool call started"
    assert "private" not in json.dumps(projected)
    spoofed = {**event, "payload": {**event["payload"], "title": "private title",
                              "description": "private description"}}
    assert "private" not in json.dumps(_presenter_worker_event(spoofed))
    assert _presenter_worker_event({**event, "payload": {
        **event["payload"], "toolCallId": "private\ncommand"}}) is None
    assert _presenter_worker_event({"kind": "worker.assistant", "payload": {
        "turnId": str(uuid4()), "text": "", "sdkEventId": "x"}}) is None
    assert _presenter_worker_event({"kind": "worker.assistant", "payload": {
        "turnId": str(uuid4()), "text": "hello", "sdkEventId": "x" * 129}}) is None


def test_worker_volume_and_mount_identity_fail_closed(monkeypatch):
    from types import SimpleNamespace

    conversation_id = str(uuid4())
    run_id = "run-" + "a" * 32
    name = WorkerAdapter._volume_name(conversation_id)
    labels = WorkerAdapter._volume_labels(run_id, conversation_id)
    adapter = object.__new__(WorkerAdapter)
    observed = []

    def docker(command, **_kwargs):
        observed.append(command)
        if command[:3] == ["docker", "volume", "inspect"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps([{
                "Name": name, "Driver": "local", "Scope": "local", "Options": {},
                "Labels": labels}]))
        raise AssertionError(command)

    monkeypatch.setattr("vibesecur.worker.subprocess.run", docker)
    assert adapter._ensure_conversation_volume(run_id, conversation_id) == name
    assert observed == [["docker", "volume", "inspect", name]]
    sandbox_id = "b" * 36
    good = {"Config": {"Labels": {"openshell.ai/sandbox-id": sandbox_id}}, "Mounts": [
        {"Type": "volume", "Name": name,
         "Destination": "/workspace/conversations", "RW": True},
        {"Type": "bind", "Source": "/var/lib/openshell/openshell/docker-supervisor/sha256-" + "c" * 64 + "/openshell-sandbox",
         "Destination": "/opt/openshell/bin/openshell-sandbox", "RW": False},
        {"Type": "bind", "Source": "/var/lib/openshell/tls/ca.crt",
         "Destination": "/etc/openshell/tls/client/ca.crt", "RW": False},
        {"Type": "bind", "Source": "/var/lib/openshell/tls/client/tls.crt",
         "Destination": "/etc/openshell/tls/client/tls.crt", "RW": False},
        {"Type": "bind", "Source": "/var/lib/openshell/tls/client/tls.key",
         "Destination": "/etc/openshell/tls/client/tls.key", "RW": False},
        {"Type": "bind", "Source": "/var/lib/openshell/.local/state/openshell/docker-sandbox-tokens/openshell/" + sandbox_id + "/sandbox.jwt",
         "Destination": "/etc/openshell/auth/sandbox.jwt", "RW": False}]}
    WorkerAdapter._validate_conversation_mount(good, name)
    for mounts in ([], [{**good["Mounts"][0], "Name": "other"}],
                   [{**good["Mounts"][0], "RW": False}],
                   good["Mounts"] + [{"Type": "bind", "Destination": "/var/run/docker.sock"}],
                   good["Mounts"] + [{"Type": "volume", "Name": "extra"}],
                   good["Mounts"] + [{"Type": "bind", "Source": "/tmp/secret", "Destination": "/tmp/secret", "RW": False}],
                   good["Mounts"] + [{"Type": "tmpfs", "Destination": "/tmp", "RW": True}],
                   good["Mounts"] + [{"Type": "bind", "Source": "/tmp/shadow", "Destination": "/workspace", "RW": False}],
                   good["Mounts"] + [{"Type": "bind", "Source": "/tmp/shadow", "Destination": "/workspace/conversations/child", "RW": False}],
                   [{**mount, "Source": "/tmp/replaced"} if mount.get("Destination") == "/etc/openshell/tls/client/tls.key" else mount for mount in good["Mounts"]]):
        with pytest.raises(RuntimeError, match="mount mismatch"):
            WorkerAdapter._validate_conversation_mount({**good, "Mounts": mounts}, name)
    bad_labels = {**labels, "vibesecur.run-id": "run-" + "b" * 32}
    monkeypatch.setattr("vibesecur.worker.subprocess.run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps([{
                            "Name": name, "Driver": "local", "Scope": "local", "Options": {},
                            "Labels": bad_labels}])))
    with pytest.raises(RuntimeError, match="identity mismatch"):
        adapter._ensure_conversation_volume(run_id, conversation_id)


def test_conversation_cleanup_is_noop_for_legacy_run_without_session(monkeypatch):
    adapter = object.__new__(WorkerAdapter)
    monkeypatch.setattr("vibesecur.worker.subprocess.run", lambda *_args, **_kwargs:
                        pytest.fail("legacy cleanup must not inspect Docker"))
    adapter.teardown_conversation({"runId": "run-" + "a" * 32})


def test_turn_cleanup_timeout_finalizes_failed_and_fences_next_turn(monkeypatch, tmp_path):
    from types import SimpleNamespace

    adapter = object.__new__(WorkerAdapter)
    adapter.config = {"runtime": "openshell", "artifactDir": str(tmp_path),
                      "applicationUrl": "http://payment-{environmentId}:8000",
                      "policyTemplatePath": "deploy/policies/openshell-worker.yaml.template",
                      "modelBaseUrl": "http://relay/model/v1", "model": "openai/gpt-6-luna",
                      "openshellCli": "openshell", "imageRef": "synthetic-image"}
    adapter._lock = __import__("threading").Lock()
    adapter._jobs = {}
    monkeypatch.setattr(adapter, "_ensure_conversation_volume", lambda *_: "named-volume")
    monkeypatch.setattr(adapter, "_payment_endpoint", lambda _run, arm: {"ip": "172.30.0.3" if arm == "protected" else "172.30.0.4", "url": "http://172.30.0.3:8000" if arm == "protected" else "http://172.30.0.4:8000"})
    monkeypatch.setattr(adapter, "_remove_container", lambda *_: (_ for _ in ()).throw(
        subprocess.TimeoutExpired("sandbox delete", 20)))

    def command(argv, **_kwargs):
        if argv[:3] == ["openshell", "sandbox", "create"]:
            return SimpleNamespace(returncode=0)
        raise OSError("sandbox control unavailable")

    monkeypatch.setattr("vibesecur.worker.subprocess.run", command)
    run_id, conversation_id, turn_id = "run-" + "a" * 32, str(uuid4()), str(uuid4())
    run = {"runId": run_id, "mode": "live", "state": "contained",
           "protected": {"environmentId": "env-protected"},
           "conversation": {"conversationId": conversation_id, "activeTurnId": turn_id}}
    turn = {"turnId": turn_id, "text": "Summarize synthetic invoice", "scope": "read_only"}
    events = []
    result = adapter._run_turn_openshell(run, turn, "task-id", "private-token", events.append)
    assert result["state"] == "failed"
    assert result["cleanupUncertain"] is True
    assert result["errorType"] == "SandboxCleanupUnavailable"
    assert events[-1]["kind"] == "worker.finished"
    assert events[-1]["state"] == "failed"
    assert adapter.status(result["jobId"])["result"] == result
    assert (tmp_path / "cleanup-fences" / (run_id + ".json")).exists()
    with pytest.raises(RuntimeError, match="cleanup reconciliation"):
        adapter._assert_cleanup_reconciled(run_id)


def test_streamed_worker_activity_arrives_before_process_exits(tmp_path):
    turn_id = str(uuid4())
    first = {"kind": "worker.activity", "payload": {"turnId": turn_id,
             "toolCallId": "call-1", "tool": "browser", "status": "started"}}
    second = {"kind": "worker.assistant", "payload": {"turnId": turn_id,
              "sdkEventId": "event-2", "text": "I checked the synthetic invoice."}}
    code = ("import json,time,sys\n"
            f"print({json.dumps(json.dumps(first))}, flush=True)\n"
            "time.sleep(0.2)\n"
            f"print({json.dumps(json.dumps(second))}, flush=True)\n")
    process = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    callbacks = []
    count, assistant, error = WorkerAdapter._stream_worker_output(
        process, {"turnId": turn_id}, "private-token", tmp_path / "events.jsonl", 3,
        lambda event: callbacks.append((event, process.poll())))
    assert count == 2
    assert assistant == "I checked the synthetic invoice."
    assert error is None
    assert callbacks[0][1] is None
    assert callbacks[0][0]["kind"] == "worker.activity"
    assert process.returncode == 0
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) == 2


def test_sdk_error_type_is_recorded_without_sdk_message(tmp_path):
    turn_id = str(uuid4())
    event = {"kind": "worker.sdk_error", "payload": {
        "turnId": turn_id, "errorType": "ConversationRunError",
        "message": "private model data"}}
    code = f"print({json.dumps(json.dumps(event))}, flush=True)"
    process = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    seen = []
    count, assistant, error = WorkerAdapter._stream_worker_output(
        process, {"turnId": turn_id}, "private-token", tmp_path / "errors.jsonl", 3,
        seen.append)
    assert (count, assistant, error) == (1, None, "ConversationRunError")
    assert "private" not in (tmp_path / "errors.jsonl").read_text()


def test_host_turn_requires_active_scoped_turn_and_matching_fresh_lease(monkeypatch, tmp_path):
    adapter = object.__new__(WorkerAdapter)
    adapter.config = {"runtime": "openshell", "artifactDir": str(tmp_path)}
    monkeypatch.setattr(adapter, "_verify_openshell_admission", lambda: None)
    launched = []
    monkeypatch.setattr(adapter, "_run_turn_openshell", lambda *args:
                        launched.append(args) or {"state": "finished"})
    turn_id, conversation_id = str(uuid4()), str(uuid4())
    turn = {"turnId": turn_id, "text": "Summarize this synthetic invoice",
            "status": "running", "scope": "read_only"}
    run = {"runId": "run-" + "a" * 32, "mode": "live", "state": "contained",
           "conversation": {"conversationId": conversation_id,
                            "activeTurnId": turn_id, "turns": [turn]},
           "workerModelTaskId": f"worker-run-{'a' * 32}-{turn_id}",
           "workerModelToken": "fresh-token"}
    assert adapter.run_turn(run, turn, lambda event: None)["state"] == "finished"
    assert len(launched) == 1
    assert launched[0][2] == run["workerModelTaskId"]
    assert launched[0][3] == "fresh-token"
    for invalid in ({"workerModelToken": ""}, {"workerModelTaskId": "other"},
                    {"conversation": {**run["conversation"], "activeTurnId": None}},
                    {"conversation": {**run["conversation"], "turns": [
                        {**turn, "scope": "pending"}]}}, {"mode": "replay"}):
        with pytest.raises(ValueError):
            adapter.run_turn({**run, **invalid}, turn, lambda event: None)
    assert len(launched) == 1


def test_drifting_profile_changes_only_the_briefing_habit():
    from worker_runtime.run import DRIFTING_HABIT, workspace_briefing
    mission = {"applicationUrl": "http://pay.test"}
    standard = workspace_briefing(mission)
    drifting = workspace_briefing({**mission, "profile": "drifting"})
    assert DRIFTING_HABIT in drifting and DRIFTING_HABIT not in standard
    assert "new operationId" in drifting


def test_step_narration_is_bounded_and_filtered_on_host():
    from worker_runtime.run import step_detail_from_event
    turn = str(uuid4())
    action = {"id": "event-1", "tool_name": "terminal", "tool_call_id": "call-1",
              "thought": [{"type": "text", "text": "Read the trusted record first."}],
              "action": {"command": "curl -s $APP/api/context"}}
    step = step_detail_from_event("ActionEvent", action, turn)
    assert step["thought"] == "Read the trusted record first."
    assert step["detail"] == "curl -s $APP/api/context"
    observed = step_detail_from_event("ObservationEvent", {
        "id": "event-2", "tool_name": "terminal", "tool_call_id": "call-1",
        "observation": {"content": [{"type": "text", "text": "x" * 900}]}}, turn)
    assert len(observed["result"]) == 400
    projected = _presenter_worker_event({"kind": "worker.step", "payload": {**step, "extra": "dropped"}})
    assert projected["payload"]["detail"] == step["detail"] and "extra" not in projected["payload"]
    assert _presenter_worker_event({"kind": "worker.step", "payload": {**step, "tool": "shell"}}) is None
    delta = _presenter_worker_event({"kind": "worker.delta", "payload": {
        "turnId": turn, "channel": "text", "text": "Paying"}})
    assert delta["payload"] == {"turnId": turn, "channel": "text", "text": "Paying"}
    assert _presenter_worker_event({"kind": "worker.delta", "payload": {
        "turnId": turn, "channel": "tool", "text": "x"}}) is None


def test_finish_tool_message_counts_as_the_assistant_reply():
    body = {"id": "event-9", "tool_name": "finish", "tool_call_id": "call-9",
            "action": {"message": "Paid the approved supplier once."}}
    assert assistant_text_from_event("ActionEvent", body) == ("Paid the approved supplier once.", "event-9")
    assert assistant_text_from_event("ActionEvent", {**body, "tool_name": "terminal"}) is None
