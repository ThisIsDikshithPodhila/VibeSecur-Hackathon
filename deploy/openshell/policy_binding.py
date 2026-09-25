"""Bind the approved OpenShell YAML template to its effective JSON policy.

The companion JSON is generated from the reviewed YAML at development time.
Runtime verification uses only the Python standard library and fails closed if
either file changes independently or OpenShell composes a different policy.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


PAYMENT_HOST = re.compile(r"payment-[A-Za-z0-9-]{1,80}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PLACEHOLDER = "__PAYMENT_HOST__"
BINDING_NAME = "openshell-worker.policy-binding.json"


def expected_policy(template_path: str | Path, payment_host: str) -> tuple[dict, dict]:
    """Return exact expected policy and stable binding identities."""
    if not PAYMENT_HOST.fullmatch(payment_host):
        raise ValueError("Invalid payment host for OpenShell policy")
    template_path = Path(template_path)
    template = template_path.read_bytes()
    binding_path = template_path.with_name(BINDING_NAME)
    binding_bytes = binding_path.read_bytes()
    binding = json.loads(binding_bytes)
    template_digest = hashlib.sha256(template).hexdigest()
    if (not isinstance(binding, dict)
            or binding.get("sourceTemplateSha256") != template_digest
            or template.count(PLACEHOLDER.encode()) != 1):
        raise ValueError("OpenShell policy template differs from approved binding")
    policy = binding.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("OpenShell approved policy missing")
    policy_text = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    if policy_text.count(PLACEHOLDER) != 1:
        raise ValueError("OpenShell approved policy payment host is ambiguous")
    rendered = json.loads(policy_text.replace(PLACEHOLDER, payment_host))
    return rendered, {
        "policyTemplateSha256": template_digest,
        "policyBindingSha256": hashlib.sha256(binding_bytes).hexdigest(),
        "renderedPolicySha256": hashlib.sha256(
            json.dumps(rendered, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def effective_policy(output: str, expected: dict, sandbox: str) -> str:
    """Require the gateway's full effective policy to equal approved rules."""
    observed = json.loads(output)
    if (not isinstance(observed, dict)
            or observed.get("status") != "effective"
            or observed.get("sandbox") != sandbox
            or observed.get("policy") != expected
            or not isinstance(observed.get("hash"), str)
            or not SHA256.fullmatch(observed["hash"])):
        raise ValueError("OpenShell effective policy differs from approved policy")
    return observed["hash"]
