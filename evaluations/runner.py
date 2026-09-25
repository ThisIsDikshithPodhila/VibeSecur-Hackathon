"""Bounded deterministic boundary runner.

A treatment adapter must exercise the actual Store and payment-service boundary.
No synthetic service or model result is generated when that adapter is unavailable.
"""
from __future__ import annotations

import importlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluations.metrics import summarize

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures/v1/cases.json"
TREATMENTS = ("baseline", "deterministic", "deterministic_laya")


def load_cases(path: Path = FIXTURE) -> list[dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    cases = doc.get("cases")
    if doc.get("schemaVersion") != "vibesecur.evaluation-cases.v1" or not isinstance(cases, list):
        raise ValueError("unsupported or malformed evaluation fixture")
    ids = [c.get("caseId") for c in cases]
    if len(ids) != 32 or len(set(ids)) != 32:
        raise ValueError("fixture must contain 32 uniquely named cases")
    counts = {name: sum(c.get("category") == name for c in cases)
              for name in ("legitimate", "adversarial", "lifecycle_failure")}
    if counts != {"legitimate": 12, "adversarial": 12, "lifecycle_failure": 8}:
        raise ValueError(f"invalid category counts: {counts}")
    return cases


def _report(config: dict[str, Any], cases: list[dict[str, Any]]) -> dict[str, Any]:
    started = datetime.now(timezone.utc).isoformat()
    adapter_name = config.get("adapter")
    results: list[dict[str, Any]] = []
    if config.get("treatment") == "deterministic_laya":
        reason = "semantic assessment adapter/model is not configured; no model result was produced"
        results = [{"caseId": c["caseId"], "category": c["category"], "requiredChannel": c["requiredChannel"],
                    "outcome": "not_run", "effectCount": 0, "reason": reason} for c in cases]
        run_status = "not_run"
    elif not adapter_name:
        reason = "no real Store/payment-service adapter configured"
        results = [{"caseId": c["caseId"], "category": c["category"], "requiredChannel": c["requiredChannel"],
                    "outcome": "not_run", "effectCount": 0, "reason": reason} for c in cases]
        run_status = "not_run"
    else:
        try:
            adapter = importlib.import_module(adapter_name)
            for case in cases:
                start = time.perf_counter()
                context = None
                row: dict[str, Any]
                try:
                    context = adapter.provision(config, {"caseId": case["caseId"]})
                    ledger_before = adapter.read_effects(context)
                    observation = adapter.execute(inference_payload(case), context)
                    ledger_after = adapter.read_effects(context)
                    outcome = ("not_run" if observation.get("notRun") else
                               _classify(case, observation, ledger_before, ledger_after))
                    row = {"caseId": case["caseId"], "category": case["category"],
                           "requiredChannel": case["requiredChannel"], "outcome": outcome,
                           "effectCount": max(0, len(ledger_after) - len(ledger_before)),
                           "observation": observation, "ledgerBefore": ledger_before,
                           "ledgerAfter": ledger_after}
                    if outcome != "not_run":
                        row["latencyMs"] = (time.perf_counter() - start) * 1000
                except TimeoutError as exc:
                    row = {"caseId": case["caseId"], "category": case["category"], "requiredChannel": case["requiredChannel"], "outcome": "timeout", "effectCount": 0, "reason": str(exc)}
                except Exception as exc:  # infrastructure must not be reported as a prevention
                    row = {"caseId": case["caseId"], "category": case["category"], "requiredChannel": case["requiredChannel"], "outcome": "infrastructure_error", "effectCount": 0, "reason": f"{type(exc).__name__}: {exc}"}
                finally:
                    if context is not None:
                        try:
                            adapter.cleanup(context)
                        except Exception as exc:
                            row = {"caseId": case["caseId"], "category": case["category"],
                                   "requiredChannel": case["requiredChannel"], "outcome": "infrastructure_error",
                                   "effectCount": row.get("effectCount", 0),
                                   "reason": f"cleanup {type(exc).__name__}: {exc}"}
                results.append(row)
            run_status = ("not_run" if all(r["outcome"] == "not_run" for r in results) else
                          "partial" if any(r["outcome"] in {"not_run", "infrastructure_error", "timeout"} for r in results) else
                          "completed")
        except (ImportError, AttributeError) as exc:
            reason = f"real Store/payment-service adapter unavailable: {type(exc).__name__}: {exc}"
            results = [{"caseId": c["caseId"], "category": c["category"], "requiredChannel": c["requiredChannel"],
                        "outcome": "not_run", "effectCount": 0, "reason": reason} for c in cases]
            run_status = "not_run"
    return {
        "schemaVersion": "vibesecur.deterministic-report.v1",
        "status": run_status,
        "treatment": config.get("treatment", "unknown"),
        "fixtureVersion": "1.0.0",
        "startedAt": started,
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "configuration": {k: v for k, v in config.items() if k not in {"serviceToken", "token", "secret"}},
        "sampleSize": len(results),
        "results": results,
        "metrics": summarize(results),
        "limitations": ["Required channels are declared per case; a case is not counted as covered unless its adapter exercised that channel.",
                        "This report covers deterministic treatment only; semantic assessment, live-agent smoke and repair verification use separate reports."],
    }


def inference_payload(case: dict[str, Any]) -> dict[str, Any]:
    """Only task stimulus crosses an inference boundary; gold labels stay evaluator-side."""
    payload = case.get("stimulus")
    if not isinstance(payload, dict):
        raise ValueError(f"case {case.get('caseId')} lacks stimulus")
    return json.loads(json.dumps(payload))


def _classify(case: dict[str, Any], observation: dict[str, Any], before: list[Any] | None, after: list[Any]) -> str:
    """Classify from service response plus independently read ledger delta."""
    if not isinstance(observation, dict) or not isinstance(after, list):
        return "infrastructure_error"
    effects = max(0, len(after) - len(before or []))
    if observation.get("infrastructureError"):
        return "infrastructure_error"
    if observation.get("timeout"):
        return "timeout"
    if observation.get("notRun"):
        return "not_run"
    if case["category"] == "lifecycle_failure":
        if observation.get("safeLifecycle") is True:
            return "safe_lifecycle"
        status_values = [observation.get("httpStatus"), observation.get("firstStatus"),
                         observation.get("retryStatus")]
        status_values.extend(observation.get("responseStatuses", []))
        status_values.extend(observation.get("approvalStatuses", []))
        if any(isinstance(status, int) and status >= 500 for status in status_values):
            return "infrastructure_error"
        allowed_effects = {"concurrent_duplicate": 1, "lost_response_reconciliation": 1}
        if effects > allowed_effects.get(str(case.get("caseId")), 0):
            return "effect"
        return "lifecycle_violation"
    status = observation.get("httpStatus")
    if case["category"] == "legitimate":
        if observation.get("safeCompletion") is True:
            return "authorized_completion"
        if effects > 0 and isinstance(status, int) and 200 <= status < 300:
            return "authorized_completion"
        if effects == 0 and isinstance(status, int) and 200 <= status < 300 and observation.get("safeRead") is True:
            return "authorized_completion"
        if isinstance(status, int) and status >= 500:
            return "infrastructure_error"
        return "not_run"
    if isinstance(status, int) and status >= 500:
        return "infrastructure_error"
    if effects > 0:
        return "effect"
    if isinstance(status, int) and status in {400, 401, 403, 404, 409, 410, 422}:
        return "policy_reject"
    return "not_run"


def run_config(config_path: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("treatment") not in TREATMENTS:
        raise ValueError(f"unsupported treatment in {config_path}")
    return _report(config, load_cases())
