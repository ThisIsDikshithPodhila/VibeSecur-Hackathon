"""Immutable accepted payment profile selection and source attestation."""

import hashlib
import json
from threading import RLock

import pytest

from vibesecur.worker import PaymentGateway, PaymentServiceProvisioner


def fixture(tmp_path):
    base, image = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    proof = {"passed": True, "state": "passed", "outerContainment": True,
             "outerControls": {"passed": True},
             "contractDigest": "c" * 64, "artifactDigest": "d" * 64,
             "acceptanceManifestDigest": "e" * 64,
             "sourceReview": {"passed": True, "sourceSha256": "f" * 64},
             "imageIds": {base: base},
             "tests": [{"name": "candidate.freshApproval", "passed": True}]}
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    record = {"id": "verified-healthy-v1", "version": 1,
              "proofSha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
              "contractDigest": proof["contractDigest"],
              "artifactDigest": proof["artifactDigest"],
              "acceptanceManifestDigest": proof["acceptanceManifestDigest"],
              "sourceSha256": proof["sourceReview"]["sourceSha256"],
              "imageDigest": image, "baseImageDigest": base,
              "baseCommit": "1" * 40,
              "acceptedRunId": "run-" + "2" * 32}
    record_path = tmp_path / "accepted.json"
    record_path.write_text(json.dumps(record))
    record_hash = hashlib.sha256(record_path.read_bytes()).hexdigest()
    provisioner = object.__new__(PaymentServiceProvisioner)
    provisioner.image = base
    provisioner.accepted_profile_path = record_path
    provisioner.accepted_profile_sha256 = record_hash
    provisioner.accepted_proof_path = proof_path
    provisioner.promotion_root = tmp_path / "promotions"
    provisioner._lock = RLock()
    provisioner._origins = {}
    run = {"runId": "run-" + "3" * 32,
           "paymentProfile": {"id": record["id"], "recordSha256": record_hash},
           "baseline": {"environmentId": "env-baseline"},
           "protected": {"environmentId": "env-protected"}}
    return provisioner, run, record, proof


def test_healthy_profile_requires_pinned_record_and_matching_independent_proof(tmp_path):
    provisioner, run, record, proof = fixture(tmp_path)
    for arm in ("baseline", "protected"):
        image, selected = provisioner._expected_image(run, run[arm]["environmentId"])
        assert image == record["imageDigest"]
        assert selected["sourceSha256"] == proof["sourceReview"]["sourceSha256"]
    with pytest.raises(ValueError, match="profile"):
        provisioner._expected_image({**run, "paymentProfile": {**run["paymentProfile"],
                                   "recordSha256": "0" * 64}}, "env-baseline")
    provisioner.accepted_proof_path.write_text('{"passed": false}')
    with pytest.raises(ValueError, match="proof"):
        provisioner._expected_image(run, "env-baseline")


def test_gateway_exposes_trusted_profile_attestation_only_from_provisioner(tmp_path):
    provisioner, run, record, _ = fixture(tmp_path)
    gateway = PaymentGateway("http://payment-{environmentId}:8000", provisioner=provisioner)
    provisioner.profile_attestation = lambda current: {
        "status": "verified_healthy", "runId": current["runId"],
        "recordSha256": run["paymentProfile"]["recordSha256"]}
    assert gateway.profile_attestation(run)["status"] == "verified_healthy"
    with pytest.raises(RuntimeError, match="unavailable"):
        PaymentGateway("http://payment-{environmentId}:8000").profile_attestation(run)
