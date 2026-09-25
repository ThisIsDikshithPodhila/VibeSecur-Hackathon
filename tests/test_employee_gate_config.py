"""Fresh owned-run configuration for the independent OpenShell boundary gate."""

from pathlib import Path

import pytest

from deploy.openshell.prepare_employee_gate import gate_config
from deploy.openshell.worker_network import NAME


TEMPLATE = Path("deploy/policies/openshell-worker.yaml.template")
IMAGE = "sha256:" + "a" * 64


def synthetic_run():
    return {"runId": "run-" + "b" * 32,
            "baseline": {"environmentId": "env-base"},
            "protected": {"environmentId": "env-protected"}}


def test_gate_config_derives_current_owned_hosts_and_pinned_network():
    run = synthetic_run()
    endpoints = {arm: {'runId': run['runId'], 'environmentId': run[arm]['environmentId'],
                      'containerId': digit * 64, 'imageDigest': IMAGE, 'ip': ip}
                 for arm, digit, ip in [('protected', 'c', '172.30.0.3'), ('baseline', 'd', '172.30.0.4')]}
    config = gate_config(run, IMAGE, "vs-current-gate", TEMPLATE, endpoints)
    assert config['paymentIp'] == '172.30.0.3'
    assert config['otherPaymentIp'] == '172.30.0.4'
    assert {key: config[key] for key in ('runtime','image','network','sandbox','paymentHost',
                                        'otherPaymentHost','policyTemplatePath','sourceRunId')} == {
        "runtime": "openshell", "image": IMAGE, "network": NAME,
        "sandbox": "vs-current-gate", "paymentHost": "payment-env-protected",
        "otherPaymentHost": "payment-env-base",
        "policyTemplatePath": str(TEMPLATE.resolve()),
        "sourceRunId": "run-" + "b" * 32}
    assert config["network"] != "openshell-docker"


@pytest.mark.parametrize("change", [
    {"runId": "old-run"},
    {"protected": {"environmentId": "env/unsafe"}},
    {"baseline": {"environmentId": "env-protected"}},
])
def test_gate_config_rejects_invalid_or_ambiguous_run(change):
    with pytest.raises(ValueError):
        gate_config({**synthetic_run(), **change}, IMAGE, "vs-current-gate", TEMPLATE)


def test_gate_config_requires_immutable_image_and_bound_policy(tmp_path):
    for image in ("worker:latest", "sha256:" + "z" * 64):
        with pytest.raises(ValueError):
            gate_config(synthetic_run(), image, "vs-current-gate", TEMPLATE)
    with pytest.raises((FileNotFoundError, ValueError)):
        gate_config(synthetic_run(), IMAGE, "vs-current-gate", tmp_path / "missing.yaml")
