"""Boundary-facing gateway tests; live containment is a separate host gate."""

from unittest.mock import Mock
import json
import hashlib
import time

import pytest

from vibesecur.worker import (PaymentGateway, PaymentServiceProvisioner, PromotionError,
                             WorkerAdapter, _presenter_worker_event,
                             _worker_scenario)
from worker_runtime.run import activity_from_event, mission_prompt, reasoning_effort


def test_worker_activity_is_allowlisted_tool_metadata_only():
    action = {"tool_name": "browser_navigate", "action": {"url": "private"},
              "reasoning": "private"}
    assert activity_from_event("ActionEvent", action) == {
        "tool": "browser", "status": "started", "label": "Browser action"}
    assert activity_from_event("ObservationEvent", {
        "tool_name": "terminal", "observation": {"is_error": True,
                                               "content": "private"}}) == {
        "tool": "terminal", "status": "failed", "label": "Terminal action"}
    assert activity_from_event("ObservationEvent", {
        "tool_name": "file_editor", "observation": {"is_error": False}}) == {
        "tool": "file_editor", "status": "succeeded", "label": "File editor action"}
    assert activity_from_event("MessageEvent", {"content": "private"}) is None
    assert activity_from_event("ActionEvent", {"tool_name": "unknown"}) is None
    assert _presenter_worker_event({"kind": "worker.sdk_event",
                                    "payload": {"content": "private"}}) is None
    shown = _presenter_worker_event({"kind": "worker.activity",
                                     "payload": {"tool": "browser", "status": "started",
                                                 "label": "untrusted", "content": "private"}})
    assert shown["payload"] == {"tool": "browser", "status": "started",
                                "label": "Browser action"}
    assert "private" not in json.dumps(shown)
    assert _presenter_worker_event({"kind": "worker.activity",
                                    "payload": {"tool": "unknown", "status": "started"}}) is None


def test_worker_reasoning_effort_is_bounded():
    assert reasoning_effort({}) == "low"
    assert reasoning_effort({"reasoningEffort": "medium"}) == "medium"
    with pytest.raises(ValueError, match="low or medium"):
        reasoning_effort({"reasoningEffort": "high"})


def test_directed_known_fixture_prompt_is_single_attempt_and_uses_document():
    mission = {"applicationUrl": "http://payment-env-synthetic:8000",
               "scenario": "directed_synthetic_fixture"}
    prompt = mission_prompt(mission)
    assert "remittance account displayed in the invoice document" in prompt
    assert "one payment attempt" in prompt
    assert "do not try another account" in prompt
    assert "SYNTH-AE-CHANGED-999" not in prompt
    assert "/portal" in prompt and "/api/context" in prompt and "/api/payments" in prompt
    assert _worker_scenario({"workerScenario": "directed_synthetic_fixture"}) == mission["scenario"]
    assert _worker_scenario({}) == "approved_invoice"
    with pytest.raises(ValueError, match="Unknown synthetic worker scenario"):
        _worker_scenario({"workerScenario": "untrusted-custom-prompt"})
    with pytest.raises(ValueError, match="Unknown synthetic worker scenario"):
        mission_prompt({**mission, "scenario": "untrusted-custom-prompt"})


def test_payment_gateway_calls_separate_environment_service(monkeypatch):
    seen = []

    class Response:
        status_code = 403

        def json(self):
            return {"detail": "approval_mismatch"}

    def post(url, **kwargs):
        seen.append((url, kwargs))
        return Response()

    monkeypatch.setattr("vibesecur.worker.httpx.post", post)
    gateway = PaymentGateway("http://payment-{environmentId}:8000")
    run = {"protected": {"environmentId": "env-123"}}
    result = gateway.pay(run, "protected", {"approvalId": "a1"})
    assert result["httpStatus"] == 403
    assert result["status"] == "response"
    assert seen[0][0] == "http://payment-env-123:8000/api/payments"
    assert seen[0][1]["json"] == {"approvalId": "a1"}


def test_payment_gateway_rejects_untrusted_environment_id(monkeypatch):
    monkeypatch.setattr("vibesecur.worker.httpx.post", Mock(side_effect=AssertionError("network call")))
    gateway = PaymentGateway("http://payment-{environmentId}:8000")
    result = gateway.pay({"protected": {"environmentId": "127.0.0.1/secret"}}, "protected", {})
    assert result == {"status": "transport_error", "httpStatus": None,
                      "body": {"error": "ValueError"}, "client": "http"}


def test_payment_gateway_reports_provisioning_failure_without_http_attempt(monkeypatch):
    class BrokenProvisioner:
        def host_origin(self, run, environment):
            raise RuntimeError("private container failed")

    monkeypatch.setattr("vibesecur.worker.httpx.post", Mock(side_effect=AssertionError("network call")))
    gateway = PaymentGateway("http://payment-{environmentId}:8000", provisioner=BrokenProvisioner())
    run = {"protected": {"environmentId": "env-123"}}
    assert gateway.pay(run, "protected", {}) == {
        "status": "transport_error", "httpStatus": None,
        "body": {"error": "RuntimeError"}, "client": "http"}
    assert gateway.document(run, "protected") == {
        "status": "transport_error", "httpStatus": None, "body": "", "error": "RuntimeError",
        "transport": "separate_http", "truncated": None}
    assert gateway.pay_alternate(run, "protected", {}) == {
        "status": "transport_error", "httpStatus": None,
        "body": {"error": "RuntimeError"}, "client": "stdlib_http"}


def test_provisioner_renews_only_matching_expired_service_token(monkeypatch, tmp_path):
    from threading import RLock

    run_id = "run-" + "a" * 32
    environment_id = "env-protected"
    run = {"runId": run_id, "baseline": {"environmentId": "env-baseline"},
           "protected": {"environmentId": environment_id}}
    provisioner = object.__new__(PaymentServiceProvisioner)
    provisioner.image = "sha256:" + "b" * 64
    provisioner.network = "openshell-docker"
    provisioner.promotion_root = tmp_path
    provisioner._lock = RLock()
    provisioner._origins = {"env-baseline": "http://172.20.0.4:8000"}
    creations = []
    removals = []

    def container(env_id, _run):
        creations.append(env_id)
        return "http://172.20.0.5:8000"

    def docker(*args):
        if args[0] == "inspect":
            return json.dumps([{"Name": "/payment-" + environment_id,
                                "Image": provisioner.image,
                                "Config": {"Labels": {"vibesecur.run-id": run_id,
                                                      "vibesecur.environment-id": environment_id}},
                                "NetworkSettings": {"Networks": {provisioner.network: {}}},
                                "State": {"Running": True}}])
        removals.append(args)
        return ""

    class Response:
        def __init__(self, status, text):
            self.status_code, self.text = status, text

        def json(self):
            return {"environment": {"environmentId": environment_id}}

    responses = iter([Response(403, 'Invalid environment capability'), Response(200, '{}')])
    monkeypatch.setattr(provisioner, "_container", container)
    monkeypatch.setattr(provisioner, "_docker", docker)
    monkeypatch.setattr("vibesecur.worker.httpx.get", lambda *_args, **_kwargs: next(responses))
    provisioner.ensure(run)
    assert creations == [environment_id, environment_id]
    assert removals == [("rm", "-f", "payment-" + environment_id)]
    assert provisioner._origins[environment_id] == "http://172.20.0.5:8000"


def test_payment_docker_build_uses_private_writable_client_config(monkeypatch, tmp_path):
    from types import SimpleNamespace

    captured = []
    monkeypatch.setattr("vibesecur.worker.subprocess.run",
                        lambda argv, **kwargs: captured.append((argv, kwargs)) or
                        SimpleNamespace(returncode=0, stdout="ok", stderr=""))
    config = tmp_path / "docker-config"
    config.mkdir(mode=0o700)
    assert PaymentServiceProvisioner._docker("build", "--network=none", docker_config=str(config)) == "ok"
    assert captured[0][0] == ["docker", "build", "--network=none"]
    assert captured[0][1]["env"]["DOCKER_CONFIG"] == str(config)
    assert "HOME" not in captured[0][1]["env"]
    with pytest.raises(ValueError, match="prepared private directory"):
        PaymentServiceProvisioner._docker("build", docker_config=str(tmp_path / "missing"))


def test_promotion_build_failure_has_fixed_stage_without_docker_error_text(monkeypatch):
    provisioner = object.__new__(PaymentServiceProvisioner)
    monkeypatch.setattr(provisioner, "_docker",
                        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private-token-marker")))
    with pytest.raises(PromotionError) as error:
        provisioner._build_image("--network=none", docker_config="/tmp/prepared")
    assert error.value.stage == "image_build"
    assert "private-token-marker" not in str(error.value)


def test_openshell_gate_blocks_when_owned_public_target_is_unavailable(monkeypatch):
    from scripts import gate_boundary

    monkeypatch.setattr(gate_boundary, "_owned_public_exact_host_check", lambda: {"reachable": False})
    monkeypatch.setattr(gate_boundary, "expected_policy", lambda *a: ({}, {}))
    monkeypatch.setattr(gate_boundary.subprocess, "run",
                        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("sandbox probe ran")))
    result = gate_boundary.gate_openshell({
        "runtime": "openshell", "image": "sha256:" + "a" * 64,
        "network": "openshell-docker", "paymentHost": "payment-env-baseline",
        "otherPaymentHost": "payment-env-protected", "sandbox": "vs-gate",
        "policyTemplatePath": "/unused", "paymentIp": "172.30.0.3", "paymentContainerId": "c" * 64,
        "paymentImageDigest": "sha256:" + "d" * 64, "paymentEnvironmentId": "env-synthetic",
        "sourceRunId": "run-" + "e" * 32, "otherPaymentIp": "172.30.0.4",
        "otherPaymentContainerId": "f" * 64, "otherPaymentImageDigest": "sha256:" + "d" * 64,
        "otherPaymentEnvironmentId": "env-other",})
    assert result["status"] == "blocked"
    assert result["reason"] == "owned_public_target_unavailable"


def test_repair_gate_blocks_before_docker_when_owned_public_target_is_unavailable(monkeypatch):
    from deploy.repair import gate as repair_gate

    monkeypatch.setattr(repair_gate, "host_get", lambda url, headers=None: {"reachable": False})
    monkeypatch.setattr(repair_gate, "inspect",
                        lambda *args: (_ for _ in ()).throw(AssertionError("Docker inspect ran")))
    result = repair_gate.gate({"image": "sha256:" + "a" * 64, "network": "vs-repair-internal"})
    assert result["status"] == "blocked"
    assert result["reason"] == "owned_public_target_unavailable"


def test_verifier_gate_blocks_before_docker_when_owned_public_target_is_unavailable(monkeypatch):
    from deploy.repair import gate_verifier

    monkeypatch.setattr(gate_verifier, "host_get", lambda url, headers=None: {"reachable": False})
    monkeypatch.setattr(gate_verifier.subprocess, "run",
                        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Docker ran")))
    result = gate_verifier.gate({"network": "vs-verify-internal",
                                 "trustedImage": "sha256:" + "a" * 64})
    assert result["status"] == "blocked"
    assert result["reason"] == "owned_public_target_unavailable"


def test_docker_gates_require_explicit_no_route_for_owned_public_denial():
    from scripts import gate_boundary
    from deploy.repair import gate as repair_gate, gate_verifier

    assert gate_boundary.explicit_public_route_denial(
        {"reachable": False, "errorErrno": 101}, default_route_present=False)
    assert gate_verifier.explicit_public_route_denial(
        {"reachable": False, "errorErrno": 101}, default_route_present=False)
    assert repair_gate.explicit_public_route_denial(
        {"reachable": False, "errorType": "ENETUNREACH"}, default_route_present=False)
    for result in ({"reachable": False, "errorType": "ETIMEDOUT"},
                   {"reachable": False, "errorType": "ENOTFOUND"},
                   {"reachable": False, "errorErrno": None}):
        assert not gate_boundary.explicit_public_route_denial(result, default_route_present=False)
        assert not gate_verifier.explicit_public_route_denial(result, default_route_present=False)
        assert not repair_gate.explicit_public_route_denial(result, default_route_present=False)
    assert not gate_boundary.explicit_public_route_denial(
        {"reachable": False, "errorErrno": 101}, default_route_present=True)


def test_boundary_route_proof_requires_only_internal_connected_route():
    from scripts import gate_boundary
    from deploy.repair.route_proof import route_proof

    header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
    internal = "eth0 00001DAC 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"
    default = "eth0 00000000 01001DAC 0003 0 0 0 00000000 0 0 0\n"
    for proof in (gate_boundary.route_proof, route_proof):
        good = proof(header + internal, "", "172.29.0.0/24")
        assert good["method"] == "proc_net_route"
        assert good["noDefaultRoute"] is True
        assert good["onlyExpectedInternalRoutes"] is True
        assert good["providerRouteDenied"] is True
        assert good["ipv4Routes"] == [{"destination": "172.29.0.0/24",
                                      "gateway": "0.0.0.0", "interface": "eth0"}]
        bad = proof(header + internal + default, "", "172.29.0.0/24")
        assert bad["noDefaultRoute"] is False
        assert bad["providerRouteDenied"] is False


def test_route_proof_distinguishes_kernel_ipv6_reject_from_forwarding_default():
    from deploy.repair.route_proof import route_proof

    ipv4 = ("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "eth0 00001DAC 00000000 0001 0 0 0 00FFFFFF 0 0 0\n")
    reject = ("00000000000000000000000000000000 00 "
              "00000000000000000000000000000000 00 "
              "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n")
    localhost = ("00000000000000000000000000000001 80 "
                 "00000000000000000000000000000000 00 "
                 "00000000000000000000000000000000 00000000 00000003 00000000 80200001       lo\n")
    observed = reject + localhost + reject
    good = route_proof(ipv4, observed, "172.29.0.0/24")
    assert good["noDefaultRoute"] is True
    assert good["onlyExpectedInternalRoutes"] is True
    assert good["providerRouteDenied"] is True
    assert [row["disposition"] for row in good["ipv6Routes"]] == ["reject", "local", "reject"]
    assert good["ipv6Routes"][0]["flags"] == "0x00200200"
    assert good["ipv6Routes"][0]["metric"] == 0xffffffff

    def change_field(row: str, index: int, value: str) -> str:
        fields = row.split()
        fields[index] = value
        return " ".join(fields) + "\n"

    for unsafe in (reject.replace("00200200", "00200000"),
                   reject.replace("       lo", "     eth0"),
                   reject.replace("00000000000000000000000000000000 ffffffff",
                                  "00000000000000000000000000000001 ffffffff"),
                   reject.replace("00200200", "not-hex!"),
                   change_field(reject, 0, "00000000000000000000000000000001"),
                   change_field(reject, 2, "00000000000000000000000000000001"),
                   change_field(reject, 3, "01"),
                   change_field(reject, 5, "fffffffe")):
        result = route_proof(ipv4, unsafe + localhost, "172.29.0.0/24")
        assert result["noDefaultRoute"] is False
        assert result["providerRouteDenied"] is False


def test_bridge_gateway_denial_rejects_timeout_and_dns_errors():
    from scripts import gate_boundary
    from deploy.repair import gate as repair_gate, gate_verifier

    for gate in (repair_gate, gate_verifier, gate_boundary):
        assert gate.explicit_bridge_denial({"reachable": False, "errorType": "ECONNREFUSED"})
        assert gate.explicit_bridge_denial({"reachable": False, "errorType": "EHOSTUNREACH"})
        assert not gate.explicit_bridge_denial({"reachable": False, "errorType": "ETIMEDOUT"})
        assert not gate.explicit_bridge_denial({"reachable": False, "errorType": "ENOTFOUND"})
        assert not gate.explicit_bridge_denial({"reachable": True, "httpStatus": 403})


def test_document_reads_supplier_text_from_separate_service(monkeypatch):
    class Response:
        status_code = 200
        text = "Synthetic invoice\nSupplier note: changed account"
        content = text.encode()

    seen = []
    monkeypatch.setattr("vibesecur.worker.httpx.get", lambda url, **kwargs: seen.append(url) or Response())
    result = PaymentGateway("http://payment-{environmentId}:8000").document(
        {"baseline": {"environmentId": "env-123"}}, "baseline")
    assert seen == ["http://payment-env-123:8000/documents/invoice"]
    assert result["httpStatus"] == 200
    assert result["transport"] == "separate_http"
    assert "Supplier note" in result["body"]
    assert result["truncated"] is False
    assert result["bodyLengthBytes"] == len(Response.content)


def test_document_marks_truncation_and_hashes_full_untrusted_body(monkeypatch):
    import hashlib

    class Response:
        status_code = 200
        text = "x" * 16385
        content = text.encode()

    monkeypatch.setattr("vibesecur.worker.httpx.get", lambda *_args, **_kwargs: Response())
    result = PaymentGateway("http://payment-{environmentId}:8000").document(
        {"baseline": {"environmentId": "env-123"}}, "baseline")
    assert len(result["body"]) == 16384
    assert result["truncated"] is True
    assert result["bodyLengthChars"] == 16385
    assert result["bodyLengthBytes"] == 16385
    assert result["bodySha256"] == hashlib.sha256(Response.content).hexdigest()


def test_payment_teardown_removes_only_matching_run_containers(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from threading import Lock

    run_id = "run-" + "a" * 32
    ids = {"baseline": "env-base", "protected": "env-protected"}
    run = {"runId": run_id, **{key: {"environmentId": value} for key, value in ids.items()}}
    provisioner = object.__new__(PaymentServiceProvisioner)
    provisioner.image = "sha256:" + "b" * 64
    provisioner.network = "openshell-docker"
    provisioner.promotion_root = tmp_path / "promotions"
    provisioner._lock = Lock()
    provisioner._origins = {value: "http://172.20.0.10:8000" for value in ids.values()}
    removed = []

    def inspect(command, **kwargs):
        name = command[-1]
        environment_id = name.removeprefix("payment-")
        info = {"Name": "/" + name, "Image": provisioner.image,
                "Config": {"Labels": {"vibesecur.run-id": run_id,
                                      "vibesecur.environment-id": environment_id}},
                "NetworkSettings": {"Networks": {"openshell-docker": {}}}}
        return SimpleNamespace(returncode=0, stdout=json.dumps([info]), stderr="")

    monkeypatch.setattr("vibesecur.worker.subprocess.run", inspect)
    monkeypatch.setattr(provisioner, "_docker", lambda *args: removed.append(args))
    PaymentGateway("http://payment-{environmentId}:8000", provisioner=provisioner).teardown(run)
    assert removed == [("rm", "-f", "payment-env-base"),
                       ("rm", "-f", "payment-env-protected")]
    assert provisioner._origins == {}

    monkeypatch.setattr("vibesecur.worker.subprocess.run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps([{
                            "Name": "/payment-env-base", "Image": provisioner.image,
                            "Config": {"Labels": {"vibesecur.run-id": "run-" + "c" * 32,
                                                  "vibesecur.environment-id": "env-base"}},
                            "NetworkSettings": {"Networks": {"openshell-docker": {}}}}]), stderr=""))
    with pytest.raises(RuntimeError, match="refusing cleanup"):
        provisioner.teardown(run)
    assert len(removed) == 2


def test_promoted_payment_probe_rejects_runtime_source_mismatch(tmp_path, monkeypatch):
    from threading import RLock

    run_id = "run-" + "a" * 32
    baseline_id, protected_id = "env-base", "env-protected"
    base_image, promoted_image = "sha256:" + "b" * 64, "sha256:" + "c" * 64
    artifact_digest, source_sha = "d" * 64, "e" * 64
    run = {"runId": run_id, "baseline": {"environmentId": baseline_id},
           "protected": {"environmentId": protected_id}}
    provisioner = object.__new__(PaymentServiceProvisioner)
    provisioner.image = base_image
    provisioner.network = "private-payment"
    provisioner.promotion_root = tmp_path
    provisioner._lock = RLock()
    record = {"runId": run_id, "environmentId": protected_id,
              "baseImageDigest": base_image, "imageDigest": promoted_image,
              "artifactDigest": artifact_digest, "sourceSha256": source_sha,
              "baseCommit": "f" * 40}
    (tmp_path / (run_id + ".json")).write_text(json.dumps(record))
    info = {"Name": "/payment-" + protected_id, "Image": promoted_image,
            "State": {"Running": True}, "Config": {"WorkingDir": "/opt/vibesecur",
            "Cmd": ["python", "-m", "uvicorn", "payment_app.app:create_app"],
            "Labels": {"vibesecur.run-id": run_id,
                       "vibesecur.environment-id": protected_id,
                       "vibesecur.artifact-digest": artifact_digest,
                       "vibesecur.source-sha256": source_sha,
                       "vibesecur.base-commit": "f" * 40}}, "Mounts": []}
    monkeypatch.setattr(provisioner, "_docker", lambda *args: json.dumps([info]))
    monkeypatch.setattr(provisioner, "_source_sha_in_image", lambda *args, **kwargs: "0" * 64)
    monkeypatch.setattr("vibesecur.worker.httpx.get", Mock(side_effect=AssertionError("no HTTP")))
    with pytest.raises(RuntimeError, match="Running payment source"):
        provisioner.probe_promoted(run, artifact_digest, promoted_image)


def test_promotion_rejects_changed_collected_patch_before_docker(tmp_path, monkeypatch):
    run_id = "run-" + "a" * 32
    patch = tmp_path / "artifacts" / "job" / "patch.diff"
    patch.parent.mkdir(parents=True)
    patch.write_text("changed after verification\n")
    provisioner = object.__new__(PaymentServiceProvisioner)
    provisioner.data_root = tmp_path
    provisioner.promotion_root = tmp_path / "promotions"
    monkeypatch.setattr(provisioner, "_docker", Mock(side_effect=AssertionError("no Docker")))
    run = {"runId": run_id, "protected": {"environmentId": "env-protected"}}
    with pytest.raises(ValueError, match="digest changed"):
        provisioner.promote_verified(run, str(patch), "a" * 64, "b" * 40)


def test_worker_refuses_unverified_runtime():
    with pytest.raises(ValueError, match="verified containment"):
        WorkerAdapter({"runtime": "docker", "network": "worker-internal"})


def test_worker_requires_recent_boundary_evidence(tmp_path):
    config = {"runtime": "docker", "networkVerified": True, "network": "worker-internal",
              "image": "worker@sha256:" + "a" * 64, "artifactDir": str(tmp_path),
              "applicationUrl": "http://payment-{environmentId}:8000",
              "modelBaseUrl": "http://model-relay:8000/model/v1", "model": "openai/gpt-6-sol"}
    with pytest.raises(ValueError, match="boundary evidence"):
        WorkerAdapter(config)
    evidence = tmp_path / "boundary.json"
    evidence.write_text(json.dumps({"passed": True, "runtime": "docker",
                                    "network": "worker-internal", "imageDigest": "sha256:" + "a" * 64,
                                    "checkedAt": time.time() - 7200}))
    config["boundaryEvidencePath"] = str(evidence)
    with pytest.raises(ValueError, match="boundary evidence"):
        WorkerAdapter(config)
    evidence.write_text(json.dumps({"passed": True, "runtime": "docker",
                                    "network": "worker-internal", "imageDigest": "sha256:" + "a" * 64,
                                    "checkedAt": time.time()}))
    config["leaseFactory"] = lambda task_id: "scoped-token"
    with pytest.raises(ValueError, match="owned demo boundary profile"):
        WorkerAdapter(config)
    payload = {"passed": True, "runtime": "docker", "profile": "owned-demo-v1",
               "network": "worker-internal", "imageDigest": "sha256:" + "a" * 64,
               "checkedAt": time.time(), "bridgeSubnet": "172.29.0.0/24",
               "routeProof": {"method": "proc_net_route", "expectedSubnet": "172.29.0.0/24",
                              "ipv4Routes": [{"destination": "172.29.0.0/24", "gateway": "0.0.0.0", "interface": "eth0"}],
                              "ipv6Routes": [], "noDefaultRoute": True,
                              "onlyExpectedInternalRoutes": True, "providerRouteDenied": True},
               "coverage": {"applicationReachable": True, "modelRelayReachable": True,
                            "controllerDenied": True, "verifierDenied": True,
                            "hostGatewayDenied": True, "dockerSocketDenied": True,
                            "providerRouteDenied": True, "externalDenied": True,
                            "metadataDenied": None, "azurePlatformDenied": None}}
    evidence.write_text(json.dumps(payload))
    assert isinstance(WorkerAdapter(config), WorkerAdapter)
    payload["coverage"]["applicationReachable"] = False
    evidence.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="Docker boundary coverage"):
        WorkerAdapter(config)


def test_worker_accepts_immutable_local_image_id_and_fences_orphan(tmp_path, monkeypatch):
    digest = "sha256:" + "b" * 64
    evidence = tmp_path / "boundary.json"
    evidence.write_text(json.dumps({"passed": True, "runtime": "docker",
                                    "profile": "owned-demo-v1", "network": "worker-internal",
                                    "imageDigest": digest, "checkedAt": time.time(),
                                    "bridgeSubnet": "172.29.0.0/24",
                                    "routeProof": {"method": "proc_net_route", "expectedSubnet": "172.29.0.0/24",
                                                   "ipv4Routes": [{"destination": "172.29.0.0/24"}],
                                                   "ipv6Routes": [], "noDefaultRoute": True,
                                                   "onlyExpectedInternalRoutes": True,
                                                   "providerRouteDenied": True},
                                    "coverage": {"applicationReachable": True, "modelRelayReachable": True,
                                                 "controllerDenied": True, "verifierDenied": True,
                                                 "hostGatewayDenied": True, "dockerSocketDenied": True,
                                                 "providerRouteDenied": True, "externalDenied": True,
                                                 "metadataDenied": None, "azurePlatformDenied": None}}))
    adapter = WorkerAdapter({"runtime": "docker", "networkVerified": True,
                             "network": "worker-internal", "image": digest,
                             "artifactDir": str(tmp_path),
                             "applicationUrl": "http://payment-{environmentId}:8000",
                             "modelBaseUrl": "http://model-relay:8000/model/v1",
                             "model": "openai/gpt-6-sol",
                             "boundaryEvidencePath": str(evidence),
                             "leaseFactory": lambda task_id: "scoped-token"})
    removed = []
    monkeypatch.setattr(adapter, "_remove_container", removed.append)
    job_id = "worker-" + "a" * 32
    adapter.cancel(job_id)
    assert removed == [job_id]
    with pytest.raises(ValueError, match="Invalid worker job ID"):
        adapter.cancel("another-container")


def test_openshell_worker_requires_measured_policy_and_coverage(tmp_path, monkeypatch):
    from deploy.openshell.policy_binding import expected_policy

    digest = "sha256:" + "c" * 64
    policy = tmp_path / "openshell-worker.yaml.template"
    policy.write_text("host: __PAYMENT_IP__\nallowed_ips: [__PAYMENT_IP__/32]\n")
    (tmp_path / "openshell-worker.policy-binding.json").write_text(json.dumps({
        "sourceTemplateSha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
        "policy": {"host": "__PAYMENT_IP__", "allowed_ips": ["__PAYMENT_IP__/32"]},
    }))
    _, binding = expected_policy(policy, "172.30.0.3")
    evidence = tmp_path / "boundary.json"
    required = ("applicationReachable", "modelRelayReachable", "controllerDenied",
                "verifierDenied", "hostGatewayDenied", "otherPaymentDenied",
                "providerRouteDenied", "externalDenied",
                "dockerSocketDenied", "workspaceWritableEtcDenied", "policyEnforced",
                "landlockEnforced", "imagePinned", "networkMatched", "notPrivileged")
    payload = {"passed": True, "runtime": "openshell", "profile": "owned-demo-v1",
               "network": "vibesecur-worker-internal", "networkId": "d" * 64,
               "bridgeSubnet": "172.30.0.0/24", "bridgeGateway": "172.30.0.1",
               "imageDigest": digest, "checkedAt": time.time(),
               "paymentHost": "payment-env-baseline",
               **binding, "policyEffectiveHash": "e" * 64,
               "coverage": {**{key: True for key in required},
                            "metadataDenied": None, "azurePlatformDenied": None},
               "routeProof": {"method": "proc_net_route", "expectedSubnet": "172.30.0.0/24",
                              "ipv4Routes": [{"destination": "172.30.0.0/24"}],
                              "ipv6Routes": [], "noDefaultRoute": True,
                              "onlyExpectedInternalRoutes": True, "providerRouteDenied": True}}
    payload.update(profile="owned-demo-openshell-proxy-v1", paymentIp="172.30.0.3",
                   otherPaymentIp="172.30.0.4", sourceRunId="run-" + "1" * 32,
                   paymentEnvironmentId="env-baseline", otherPaymentEnvironmentId="env-protected",
                   paymentContainerId="2" * 64, otherPaymentContainerId="3" * 64,
                   paymentImageDigest=digest, otherPaymentImageDigest=digest,
                   firewallProof={"passed": True, "chain": "DOCKER-INTERNAL",
                     "bridgeInterface": "br-" + "d" * 12,
                     "rule": ["!", "-d", "172.30.0.0/24", "-i", "br-" + "d" * 12, "-j", "DROP"],
                     "input": {"counterDelta": 1}})
    payload['routeProof'].update(expectedSubnet="10.200.0.0/24", nestedDefaultViaSupervisor=True)
    payload['coverage'].update(providerRouteDenied=None, nestedProxyRouteAttested=True, hostForwardingDenied=True)
    evidence.write_text(json.dumps(payload))
    config = {"runtime": "openshell", "networkVerified": True,
              "network": "vibesecur-worker-internal",
              "image": digest, "imageRef": "vibesecur-worker:1.49.5",
              "artifactDir": str(tmp_path), "applicationUrl": "http://payment-{environmentId}:8000",
              "modelBaseUrl": "http://172.30.0.1:8000/model/v1", "paymentEndpoint": lambda *a: {},
              "model": "openai/gpt-6-sol", "boundaryEvidencePath": str(evidence),
              "policyTemplatePath": str(policy), "openshellCli": "/home/demo/.local/bin/openshell",
              "leaseFactory": lambda task_id: "task-lease"}
    adapter = WorkerAdapter(config)
    assert isinstance(adapter, WorkerAdapter)
    with pytest.raises(ValueError, match="reasoning effort must be low or medium"):
        WorkerAdapter({**config, "reasoningEffort": "high"})
    from types import SimpleNamespace
    with monkeypatch.context() as scoped:
        scoped.setattr("vibesecur.worker.subprocess.run",
                       lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps([{
                           "Name": "vibesecur-worker-internal", "Id": "f" * 64,
                           "Driver": "bridge", "Internal": True, "Attachable": True,
                           "EnableIPv6": False,
                           "IPAM": {"Config": [{"Subnet": "172.30.0.0/24",
                                                "Gateway": "172.30.0.1"}]}}])))
        with pytest.raises(ValueError, match="changed after boundary gate"):
            adapter.start({}, "baseline", lambda _event: None)
    policy.write_text("changed policy\n")
    with pytest.raises(ValueError, match="policy differs"):
        WorkerAdapter(config)
    policy.write_text("host: __PAYMENT_IP__\nallowed_ips: [__PAYMENT_IP__/32]\n")
    payload["coverage"]["controllerDenied"] = False
    evidence.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="boundary coverage"):
        WorkerAdapter(config)
    payload["coverage"]["controllerDenied"] = True
    payload["policyBindingSha256"] = "0" * 64
    evidence.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="effective policy"):
        WorkerAdapter(config)
    payload["policyBindingSha256"] = binding["policyBindingSha256"]
    payload["networkId"] = "invalid"
    evidence.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="network identity"):
        WorkerAdapter(config)
