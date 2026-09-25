"""Pure checks for the pinned OpenShell bridge and effective policy binding."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from deploy.openshell.policy_binding import effective_policy, expected_policy
from deploy.openshell.worker_network import GATEWAY, NAME, SUBNET, validate, validate_attachment
from deploy.openshell import worker_network
from scripts.gate_boundary import _check_host_verifier, _host_verifier_ready


def network(**changes):
    value = {"Name": NAME, "Id": "a" * 64, "Driver": "bridge",
             "Internal": True, "Attachable": True, "EnableIPv6": False,
             "IPAM": {"Config": [{"Subnet": SUBNET, "Gateway": GATEWAY}]}}
    value.update(changes)
    return value


def test_exact_internal_worker_network_identity():
    validate(network())
    for changed in (network(Internal=False), network(Driver="overlay"),
                    network(EnableIPv6=True),
                    network(Name="openshell-docker"), network(Id="bad"),
                    network(IPAM={"Config": [{"Subnet": "172.20.0.0/16",
                                               "Gateway": GATEWAY}]}),
                    network(IPAM={"Config": [{"Subnet": SUBNET,
                                               "Gateway": "172.30.0.2"}]})):
        with pytest.raises(ValueError, match="identity mismatch"):
            validate(changed)


def test_sandbox_attachment_requires_measured_network_id():
    container = {"HostConfig": {"NetworkMode": NAME},
                 "NetworkSettings": {"Networks": {NAME: {"NetworkID": "a" * 64}}}}
    validate_attachment(container, "a" * 64)
    with pytest.raises(ValueError, match="different network"):
        validate_attachment(container, "b" * 64)
    container["HostConfig"]["NetworkMode"] = "openshell-docker"
    with pytest.raises(ValueError, match="different network"):
        validate_attachment(container, "a" * 64)
    container["HostConfig"]["NetworkMode"] = NAME
    container["NetworkSettings"]["Networks"]["unexpected-egress"] = {"NetworkID": "c" * 64}
    with pytest.raises(ValueError, match="different network"):
        validate_attachment(container, "a" * 64)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
def test_compose_requires_precreated_external_worker_bridge():
    compose = Path(__file__).resolve().parents[1] / "deploy/openshell/docker-compose.yml"
    result = subprocess.run(["docker", "compose", "-f", str(compose), "config",
                             "--format", "json"], capture_output=True, text=True,
                            timeout=10, check=True)
    resolved = json.loads(result.stdout)
    assert resolved["networks"]["worker_boundary"]["name"] == NAME
    assert resolved["networks"]["worker_boundary"]["external"] is True
    assert set(resolved["services"]["gateway"]["networks"]) == {"default", "worker_boundary"}


def test_network_setup_rejects_existing_noninternal_without_recreation(monkeypatch):
    from types import SimpleNamespace

    calls = []

    def fake_docker(*args):
        calls.append(args)
        if args[:2] == ("network", "ls"):
            return SimpleNamespace(returncode=0, stdout="existing-id\n")
        return SimpleNamespace(returncode=0, stdout=json.dumps([network(Internal=False)]))

    monkeypatch.setattr(worker_network, "_docker", fake_docker)
    with pytest.raises(ValueError, match="identity mismatch"):
        worker_network.main()
    assert not any(args[:2] == ("network", "create") for args in calls)


def test_network_setup_creates_only_internal_exact_bridge(monkeypatch, capsys):
    from types import SimpleNamespace

    calls = []

    def fake_docker(*args):
        calls.append(args)
        if args == ("network", "ls", "-q", "--filter", f"name=^{NAME}$"):
            return SimpleNamespace(returncode=0, stdout="")
        if args == ("network", "ls", "-q"):
            return SimpleNamespace(returncode=0, stdout="old-id\n")
        if args == ("network", "inspect", "old-id"):
            return SimpleNamespace(returncode=0, stdout=json.dumps([{
                "IPAM": {"Config": [{"Subnet": "172.20.0.0/16"}]}}]))
        if args[:2] == ("network", "create"):
            return SimpleNamespace(returncode=0, stdout="new-id\n")
        if args == ("network", "inspect", NAME):
            return SimpleNamespace(returncode=0, stdout=json.dumps([network()]))
        raise AssertionError(args)

    monkeypatch.setattr(worker_network, "_docker", fake_docker)
    assert worker_network.main() == 0
    create = next(args for args in calls if args[:2] == ("network", "create"))
    assert "--internal" in create and "--attachable" in create
    assert create[-1] == NAME
    assert json.loads(capsys.readouterr().out)["networkId"] == "a" * 64


def test_checked_in_policy_binding_matches_pinned_synthetic_template():
    template = Path(__file__).resolve().parents[1] / "deploy/policies/openshell-worker.yaml.template"
    expected, identity = expected_policy(template, "172.30.0.3")
    assert identity["policyTemplateSha256"] == "a62a1fdf15da79f8df2764403baa0d7ca61c66229641aad9c8adb9f11a89b342"
    assert expected["network_policies"]["invoice_application"]["endpoints"][0]["host"] == "172.30.0.3"
    observed = {"status": "effective", "sandbox": "owned-gate", "hash": "b" * 64,
                "policy": expected}
    assert effective_policy(json.dumps(observed), expected, "owned-gate") == "b" * 64
    changed = json.loads(json.dumps(observed))
    changed["policy"]["network_policies"]["invoice_application"]["endpoints"][0]["rules"].append(
        {"allow": {"method": "GET", "path": "/internal/secret"}})
    with pytest.raises(ValueError, match="effective policy differs"):
        effective_policy(json.dumps(changed), expected, "owned-gate")
    observed["status"] = "pending"
    with pytest.raises(ValueError, match="effective policy differs"):
        effective_policy(json.dumps(observed), expected, "owned-gate")


def test_policy_binding_fails_if_yaml_and_companion_drift(tmp_path):
    template = tmp_path / "openshell-worker.yaml.template"
    template.write_text("host: __PAYMENT_HOST__\n")
    companion = tmp_path / "openshell-worker.policy-binding.json"
    companion.write_text(json.dumps({"sourceTemplateSha256": "0" * 64,
                                     "policy": {"host": "__PAYMENT_HOST__"}}))
    with pytest.raises(ValueError, match="differs from approved binding"):
        expected_policy(template, "172.30.0.3")
    with pytest.raises(ValueError, match="Invalid payment IP"):
        expected_policy(template, "example.com")


def test_verifier_host_positive_requires_exact_live_route(monkeypatch):
    class Response:
        status = 200

        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return self.body

    class Opener:
        def __init__(self, body):
            self.body = body

        def open(self, url, timeout):
            assert url == "http://172.30.0.1:8000/internal/verifier/health"
            assert timeout == 5
            return Response(self.body)

    import scripts.gate_boundary as gate
    url = "http://172.30.0.1:8000/internal/verifier/health"
    for body, expected in ((b'{"service":"vibesecur-verifier","configured":true}', True),
                           (b'{"service":"vibesecur-api","configured":true}', False),
                           (b'{"service":"vibesecur-verifier","configured":false}', False),
                           (b'not-json', False)):
        monkeypatch.setattr(gate, "build_opener", lambda *_args: Opener(body))
        assert _host_verifier_ready(_check_host_verifier(url)) is expected
    assert not _host_verifier_ready({"reachable": True, "httpStatus": 404})


def test_openshell_gate_stops_before_sandbox_probe_when_verifier_route_is_absent(monkeypatch):
    from types import SimpleNamespace
    from scripts import gate_boundary as gate

    monkeypatch.setattr(gate, "_owned_public_exact_host_check", lambda: {"reachable": True, "httpStatus": 200})
    monkeypatch.setattr(gate, "_check_host", lambda _url: {"reachable": True, "httpStatus": 200})
    monkeypatch.setattr(gate, "_check_host_verifier",
                        lambda _url: {"reachable": True, "httpStatus": 404,
                                      "identityMatched": False})
    monkeypatch.setattr(gate.socket, "gethostbyname", lambda _host: gate.OWNED_PUBLIC_IP)
    container = {"HostConfig": {"NetworkMode": NAME},
                 "NetworkSettings": {"Networks": {NAME: {"NetworkID": "a" * 64}}}}

    def fake_run(command, **_kwargs):
        command = tuple(command)
        if command[1:3] == ("policy", "get"):
            body = "{}"
        elif command[1:3] == ("sandbox", "list"):
            body = '[{"name":"vs-gate","phase":"Ready","id":"abcd"}]'
        elif command[:2] == ("docker", "inspect"):
            body = json.dumps([container])
        elif command[:3] == ("docker", "network", "inspect"):
            body = json.dumps([network()])
        else:
            raise AssertionError("Sandbox probe ran without live verifier route")
        return SimpleNamespace(returncode=0, stdout=body, stderr="")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    template = Path(__file__).resolve().parents[1] / "deploy/policies/openshell-worker.yaml.template"
    result = gate.gate_openshell({"runtime": "openshell", "image": "sha256:" + "b" * 64,
                                  "network": NAME, "paymentHost": "payment-env-synthetic",
                                  "paymentIp": "172.30.0.3", "paymentContainerId": "c" * 64,
        "paymentImageDigest": "sha256:" + "d" * 64, "paymentEnvironmentId": "env-synthetic",
        "sourceRunId": "run-" + "e" * 32, "otherPaymentIp": "172.30.0.4",
        "otherPaymentContainerId": "f" * 64, "otherPaymentImageDigest": "sha256:" + "d" * 64,
        "otherPaymentEnvironmentId": "env-other",
                                  "otherPaymentHost": "payment-env-other", "sandbox": "vs-gate",
                                  "policyTemplatePath": str(template), "cli": "openshell"})
    assert result["passed"] is False
    assert result["reason"] == "owned_verifier_route_unavailable"
    assert result["hostChecks"]["verifier"]["httpStatus"] == 404
