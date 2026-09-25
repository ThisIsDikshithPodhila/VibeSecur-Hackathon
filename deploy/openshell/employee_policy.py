"""Derive the narrower employee read-only policy from the measured template."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from deploy.openshell.policy_binding import expected_policy


_PAYMENT_RULE = "          - allow: {method: POST, path: /api/payments}\n"
_PAYMENT_ALLOW = {"allow": {"method": "POST", "path": "/api/payments"}}


def render_turn_policy(template_path: str | Path, payment_host: str,
                       scope: str) -> tuple[str, dict]:
    """Bind the pay policy, then remove its sole payment POST for safe reads."""
    if scope not in ("read_only", "pay_approved", "clarification"):
        raise ValueError("Unsupported employee turn scope")
    expected, _ = expected_policy(template_path, payment_host)
    raw = Path(template_path).read_text(encoding="utf-8")
    if raw.count("__PAYMENT_HOST__") != 1 or raw.count(_PAYMENT_RULE) != 1:
        raise ValueError("Approved payment rule is not unique")
    rendered = raw.replace("__PAYMENT_HOST__", payment_host)
    if scope == "pay_approved":
        return rendered, expected
    narrowed = deepcopy(expected)
    rules = narrowed["network_policies"]["invoice_application"]["endpoints"][0]["rules"]
    if rules.count(_PAYMENT_ALLOW) != 1:
        raise ValueError("Approved payment rule is not unique")
    rules.remove(_PAYMENT_ALLOW)
    return rendered.replace(_PAYMENT_RULE, ""), narrowed
