#!/usr/bin/env python3
"""Build a fresh OpenShell boundary config for one owned synthetic run.

This prepares input only. The boundary gate independently inspects the live
Docker network, sandbox attachment, effective policy, and owned endpoints.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from deploy.openshell.policy_binding import expected_policy
from deploy.openshell.worker_network import NAME as WORKER_NETWORK_NAME


_RUN_ID = re.compile(r"run-[0-9a-f]{32}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ENV_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,79}\Z")
_SANDBOX = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,79}\Z")


def gate_config(run: dict, image: str, sandbox: str, template: Path) -> dict:
    if (not isinstance(run, dict) or not _RUN_ID.fullmatch(str(run.get("runId", "")))
            or not _IMAGE_ID.fullmatch(image)
            or not _SANDBOX.fullmatch(sandbox)):
        raise ValueError("Owned run, pinned image, or sandbox identity is invalid")
    try:
        protected = run["protected"]["environmentId"]
        baseline = run["baseline"]["environmentId"]
    except (KeyError, TypeError):
        raise ValueError("Synthetic payment environments are missing") from None
    if (not isinstance(protected, str) or not isinstance(baseline, str)
            or not _ENV_ID.fullmatch(protected) or not _ENV_ID.fullmatch(baseline)
            or protected == baseline):
        raise ValueError("Synthetic payment environments are invalid")
    policy_path = template.resolve(strict=True)
    payment_host = "payment-" + protected
    expected_policy(policy_path, payment_host)
    return {"runtime": "openshell", "image": image,
            "network": WORKER_NETWORK_NAME, "sandbox": sandbox,
            "paymentHost": payment_host, "otherPaymentHost": "payment-" + baseline,
            "policyTemplatePath": str(policy_path), "sourceRunId": run["runId"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-json", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--policy-template", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = gate_config(json.loads(args.run_json.read_text(encoding="utf-8")),
                         args.image, args.sandbox, args.policy_template)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as target:
        json.dump(config, target, indent=2, sort_keys=True)
        target.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
