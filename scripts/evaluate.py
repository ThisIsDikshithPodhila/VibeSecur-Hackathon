#!/usr/bin/env python3
"""Run one explicitly configured deterministic evaluation treatment."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluations.runner import run_config  # noqa: E402

SEMANTIC_INPUTS = ROOT / "fixtures/semantic/inputs.jsonl"
SEMANTIC_LABELS = ROOT / "fixtures/semantic/labels.jsonl"


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _semantic_digest(item: dict) -> str:
    payload = {key: item[key] for key in ("mission", "action", "source")}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def semantic_report(inference_path: Path, inputs_path: Path = SEMANTIC_INPUTS,
                    labels_path: Path = SEMANTIC_LABELS) -> dict:
    """Join completed inference to separately held gold labels after digest checks."""
    inference = json.loads(inference_path.read_text(encoding="utf-8"))
    inputs = _jsonl(inputs_path)
    labels = _jsonl(labels_path)
    if len(inputs) != 16 or len(labels) != 16:
        raise ValueError("semantic report requires the checked-in 16 input/label fixtures")
    input_by_id = {item["id"]: item for item in inputs}
    label_by_id = {item["id"]: item for item in labels}
    predictions = inference.get("predictions", [])
    if any(type(inference.get(key)) is not bool for key in
           ("inferenceAttempted", "actualInference", "allAvailable")):
        raise ValueError("semantic inference evidence flags must be boolean")
    inference_attempted = inference.get("inferenceAttempted") is True
    prediction_by_id = {item.get("id"): item for item in predictions}
    if len(input_by_id) != 16 or len(label_by_id) != 16 or len(prediction_by_id) != len(predictions):
        raise ValueError("duplicate semantic input, label, or prediction id")
    if set(input_by_id) != set(label_by_id) or set(prediction_by_id) != set(input_by_id):
        raise ValueError("semantic inference ids do not exactly match checked-in fixtures")

    rows = []
    confusion = {gold: {predicted: 0 for predicted in ("suitable", "purpose_mismatch")}
                 for gold in ("suitable", "purpose_mismatch")}
    assessed = correct = 0
    status_counts: dict[str, int] = {}
    latencies: list[float] = []
    for case_id, item in input_by_id.items():
        prediction = prediction_by_id[case_id]
        expected_digest = _semantic_digest(item)
        if prediction.get("inferenceInputDigest") != expected_digest:
            raise ValueError(f"inference input digest mismatch for {case_id}")
        if prediction.get("pairId") != item["pairId"] or label_by_id[case_id].get("pairId") != item["pairId"]:
            raise ValueError(f"semantic pair mismatch for {case_id}")
        gold = label_by_id[case_id]["label"]
        prediction_status = str(prediction.get("status", "missing_status"))
        if prediction_status not in ("available", "unavailable", "input_too_large", "not_run"):
            raise ValueError(f"unknown semantic inference status for {case_id}")
        if prediction_status == "available":
            raw_score = prediction.get("rawScore")
            if (prediction.get("label") not in confusion[gold] or
                    type(raw_score) not in (int, float) or not math.isfinite(raw_score) or
                    not 0 <= raw_score <= 1 or prediction.get("calibrated") is not False):
                raise ValueError(f"semantic inference lacks typed available output for {case_id}")
        if prediction_status != "not_run":
            status_counts[prediction_status] = status_counts.get(prediction_status, 0) + 1
        latency = prediction.get("latencyMs")
        valid_latency = (isinstance(latency, (int, float)) and not isinstance(latency, bool)
                         and math.isfinite(latency) and latency >= 0)
        if prediction_status != "not_run" and valid_latency:
            latencies.append(float(latency))
        available = prediction_status == "available"
        if available:
            output = {key: prediction.get(key) for key in
                      ("status", "label", "rawScore", "calibrated", "latencyMs", "truncationDetected", "provenance")}
        elif prediction_status != "not_run":
            # Keep operational status/latency/truncation telemetry while
            # excluding all labels and scores from unavailable outputs.
            output = {
                "status": prediction_status,
                "latencyMs": float(latency) if valid_latency else None,
                "truncationDetected": prediction.get("truncationDetected") is True,
                "provenance": prediction.get("provenance"),
            }
        else:
            output = {"status": "not_run", "reason": "gate artifact inferenceAttempted is false; output excluded"}
        predicted = prediction.get("label") if available else None
        if predicted in confusion[gold]:
            assessed += 1
            confusion[gold][predicted] += 1
            correct += int(predicted == gold)
        rows.append({"caseId": case_id, "pairId": item["pairId"],
                     "inferenceInputDigest": expected_digest, "inferenceOutput": output,
                     "goldLabel": gold})

    pairs = {}
    for row in rows:
        pairs.setdefault(row["pairId"], []).append(row)
    correct_pairs = sum(len(group) == 2 and all(
        row["inferenceOutput"]["status"] == "available" and
        row["inferenceOutput"]["label"] == row["goldLabel"] for row in group)
        for group in pairs.values())
    available_count = sum(prediction.get("status") == "available" for prediction in predictions)
    actual = available_count > 0
    all_available = available_count == 16
    completed_calls = all(prediction.get("status") != "not_run" for prediction in predictions)
    if (inference_attempted != completed_calls or
            inference["actualInference"] is not actual or
            inference["allAvailable"] is not all_available):
        raise ValueError("semantic inference evidence flags contradict prediction statuses")
    status = ("not_run" if not actual or assessed == 0 else
              "completed" if all_available and assessed == 16 else "partial")
    per_label = {}
    for label in ("suitable", "purpose_mismatch"):
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in confusion if other != label)
        fn = sum(confusion[label][other] for other in confusion if other != label)
        precision_denominator = tp + fp
        recall_denominator = tp + fn
        per_label[label] = {
            "tp": tp, "fp": fp, "fn": fn,
            "support": sum(row["goldLabel"] == label for row in rows),
            "assessedSupport": recall_denominator,
            "precisionNumerator": tp, "precisionDenominator": precision_denominator,
            "precision": tp / precision_denominator if precision_denominator else None,
            "recallNumerator": tp, "recallDenominator": recall_denominator,
            "recall": tp / recall_denominator if recall_denominator else None,
        }
    ordered_latencies = sorted(latencies)
    latency_summary = {
        "count": len(ordered_latencies),
        "meanMs": sum(ordered_latencies) / len(ordered_latencies) if ordered_latencies else None,
        "medianMs": ((ordered_latencies[(len(ordered_latencies) - 1) // 2] +
                      ordered_latencies[len(ordered_latencies) // 2]) / 2) if ordered_latencies else None,
        "p95Ms": ordered_latencies[max(0, math.ceil(.95 * len(ordered_latencies)) - 1)] if ordered_latencies else None,
        "minMs": ordered_latencies[0] if ordered_latencies else None,
        "maxMs": ordered_latencies[-1] if ordered_latencies else None,
    }
    return {
        "schemaVersion": "vibesecur.semantic-assessment-report.v1",
        "status": status, "sampleSize": assessed, "expectedSampleSize": 16,
        "pairCount": len(pairs), "correct": correct, "correctPairs": correct_pairs,
        "confusionMatrix": confusion, "perLabelMetrics": per_label,
        "unavailableCount": status_counts.get("unavailable", 0),
        "inputTooLargeCount": status_counts.get("input_too_large", 0),
        "truncationDetectedCount": sum(row["inferenceOutput"].get("truncationDetected") is True for row in rows),
        "predictionStatusCounts": status_counts, "latencySummaryMs": latency_summary,
        "modelRevision": inference.get("modelRevision"),
        "inferenceAttempted": inference_attempted,
        "actualInference": actual, "allAvailable": all_available,
        "pairs": rows,
        "limitations": ["Semantic assessment is a model inference measure, separate from deterministic policy enforcement.",
                        "Gold labels are joined only after input digest validation; they are never part of inference inputs.",
                        "Raw model scores are uncalibrated and are not treated as confidence values.",
                        "No model effort metadata is supplied by the inference artifact."],
    }


def repair_verification_report(manifest_path: Path) -> dict:
    """Report only a digest-verified isolated verifier result, never deployment state."""
    manifest_path = manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("kind") != "independent_verifier_pass" or manifest.get("passed") is not True:
        raise ValueError("manifest does not attest an independent verifier pass")
    if manifest.get("outerContainment") is not True:
        raise ValueError("manifest does not attest outer containment")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("manifest has no hashed evidence files")
    for relative, expected in files.items():
        digest = expected.get("sha256") if isinstance(expected, dict) else expected
        evidence = (manifest_path.parent / relative).resolve()
        if evidence.parent != manifest_path.parent or not evidence.is_file():
            raise ValueError(f"manifest evidence file is missing or outside its artifact: {relative}")
        actual = hashlib.sha256(evidence.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"manifest evidence digest mismatch: {relative}")
    candidate_digest = hashlib.sha256((manifest_path.parent / "candidate.diff").read_bytes()).hexdigest()
    if candidate_digest != manifest.get("artifactDigest"):
        raise ValueError("candidate artifact digest does not match manifest")
    try:
        display_path = str(manifest_path.relative_to(ROOT))
    except ValueError:
        display_path = str(manifest_path)
    return {
        "schemaVersion": "vibesecur.repair-verification-report.v1",
        "status": "passed", "verifier": "independent verifier",
        "results": [{"checkId": "isolated_candidate_independent_verification", "status": "passed",
                     "artifactDigest": candidate_digest,
                     "manifestPath": display_path}],
        "limitations": ["This records the digest-verified isolated candidate verifier artifact only.",
                        "It does not assert hosted deployment, service restart, or task resumption."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("treatment", choices=("baseline", "deterministic", "deterministic_laya", "semantic-report", "repair-report"))
    parser.add_argument("--output", type=Path, help="Report JSON path (defaults to stdout)")
    parser.add_argument("--inference-artifact", type=Path,
                        help="Completed gate_laya.py inference JSON (semantic-report only)")
    parser.add_argument("--manifest", type=Path,
                        help="Independent verifier manifest (repair-report only)")
    args = parser.parse_args()
    if args.treatment == "semantic-report":
        if not args.inference_artifact:
            parser.error("semantic-report requires --inference-artifact")
        report = semantic_report(args.inference_artifact)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0 if report["status"] == "completed" else 2
    if args.treatment == "repair-report":
        if not args.manifest:
            parser.error("repair-report requires --manifest")
        report = repair_verification_report(args.manifest)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    config = ROOT / "evaluations/configs" / f"{args.treatment}.json"
    report = run_config(config)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
