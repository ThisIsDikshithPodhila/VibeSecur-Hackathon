#!/usr/bin/env python3
"""Build the presenter summary from current aggregate evaluation reports."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "evaluations" / "reports"
OUTPUT = ROOT / "apps" / "presenter" / "src" / "evaluation-summary.json"


def load_report(name: str) -> tuple[dict[str, Any], str]:
    path = REPORTS / name
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def deterministic_row(
    report: dict[str, Any], digest: str, source_path: str, label: str
) -> dict[str, Any]:
    treatment = report["treatment"]
    if report.get("status") not in {"partial", "completed"}:
        raise ValueError(f"expected partial or completed status in {source_path}")

    metrics = report["metrics"]
    outcomes = metrics["outcomeCounts"]
    denominators = metrics["categoryDenominators"]
    return {
        "treatment": treatment,
        "label": label,
        "status": report["status"],
        "sampleSize": report["sampleSize"],
        "startedAt": report["startedAt"],
        "recordedAt": report["finishedAt"],
        "fixtureVersion": report["fixtureVersion"],
        "sourcePath": source_path,
        "sourceSha256": digest,
        "actionDenominator": metrics["actionDenominator"],
        "categoryDenominators": denominators,
        "completed": outcomes["authorized_completion"],
        "legitimateCases": denominators["legitimate"],
        "unauthorizedEffectOutcomes": outcomes["effect"],
        "actualEffectCount": metrics["actualEffectCount"],
        "notRun": outcomes["not_run"],
        "infrastructureErrors": outcomes["infrastructure_error"],
        "timeouts": outcomes["timeout"],
        "policyRejections": outcomes["policy_reject"],
        "safeLifecycle": outcomes["safe_lifecycle"],
        "outcomeCounts": outcomes,
    }


def has_unrun_cases(rows: list[dict[str, Any]]) -> bool:
    return any(row.get("notRun", 0) for row in rows if row.get("status") != "not_recorded")


def build_summary() -> dict[str, Any]:
    baseline, baseline_digest = load_report("baseline-current.json")
    deterministic, deterministic_digest = load_report("deterministic-current.json")
    semantic, semantic_digest = load_report("semantic-assessment.json")
    live_smoke, live_digest = load_report("live-smoke.json")
    repair, repair_digest = load_report("repair-verification.json")

    rows = [
        deterministic_row(
            baseline,
            baseline_digest,
            "evaluations/reports/baseline-current.json",
            "Baseline",
        ),
        deterministic_row(
            deterministic,
            deterministic_digest,
            "evaluations/reports/deterministic-current.json",
            "Deterministic controls",
        ),
        {
            "treatment": "deterministic_laya",
            "label": "Controls + Laya",
            "status": "not_recorded",
        },
    ]
    snapshots = [row["recordedAt"] for row in rows if row.get("recordedAt")]
    limitations = list(dict.fromkeys(baseline.get("limitations", []) + deterministic.get("limitations", [])))
    if has_unrun_cases(rows):
        limitations.append("Unrun cases are included in each deterministic sample size.")
    limitations.append("No accuracy, savings, or Laya contribution claim is implied.")

    semantic_pairs = semantic.get("pairs", [])
    live_trials = live_smoke.get("trials", [])
    repair_results = [
        {
            "checkId": result["checkId"],
            "status": result["status"],
            "artifactDigest": result["artifactDigest"],
        }
        for result in repair.get("results", [])
    ]

    return {
        "track": "deterministic_replay",
        "snapshotAt": max(snapshots),
        "rows": rows,
        "evidenceTracks": [
            {
                "id": "semantic_assessment",
                "label": "Semantic assessment",
                "status": semantic["status"],
                "sampleSize": semantic.get("sampleSize"),
                "pairCount": len(semantic_pairs),
                "sourcePath": "evaluations/reports/semantic-assessment.json",
                "sourceSha256": semantic_digest,
            },
            {
                "id": "live_smoke",
                "label": "Live-agent smoke",
                "status": live_smoke["status"],
                "requiredTrials": live_smoke.get("requiredTrials"),
                "recordedTrials": len(live_trials),
                "sourcePath": "evaluations/reports/live-smoke.json",
                "sourceSha256": live_digest,
            },
            {
                "id": "repair_verification",
                "label": "Isolated candidate verification",
                "status": repair["status"],
                "verifier": repair.get("verifier"),
                "results": repair_results,
                "limitations": repair.get("limitations", []),
                "sourcePath": "evaluations/reports/repair-verification.json",
                "sourceSha256": repair_digest,
            },
        ],
        "limitations": limitations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the checked-in presenter summary is stale",
    )
    args = parser.parse_args()

    expected = json.dumps(build_summary(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != expected:
            parser.error(f"{OUTPUT.relative_to(ROOT)} is stale; regenerate it without --check")
        print(f"Current: {OUTPUT.relative_to(ROOT)}")
        return 0

    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"Wrote: {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
