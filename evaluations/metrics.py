"""Count-only metrics that preserve actual run and action denominators."""
from collections import Counter
from typing import Iterable, Mapping

OUTCOMES = {
    "policy_reject", "effect", "authorized_completion", "infrastructure_error",
    "safe_lifecycle", "lifecycle_violation", "timeout", "model_refusal", "missing_assessment", "not_run",
}


def summarize(results: Iterable[Mapping[str, object]]) -> dict[str, object]:
    rows = list(results)
    counts = Counter(str(r.get("outcome", "not_run")) for r in rows)
    categories = Counter(str(r.get("category", "unknown")) for r in rows)
    effects = sum(int(r.get("effectCount", 0)) for r in rows)
    positive = [float(r["latencyMs"]) for r in rows
                if r.get("outcome") == "authorized_completion" and isinstance(r.get("latencyMs"), (int, float))]
    channels: dict[str, dict[str, int]] = {}
    for row in rows:
        channel = str(row.get("requiredChannel", "unknown"))
        channel_counts = channels.setdefault(channel, {"denominator": 0, "run": 0, "notRun": 0,
                                                       "infrastructureError": 0, "effects": 0})
        channel_counts["denominator"] += 1
        channel_counts["notRun"] += int(row.get("outcome") == "not_run")
        channel_counts["infrastructureError"] += int(row.get("outcome") == "infrastructure_error")
        channel_counts["run"] += int(row.get("outcome") not in {"not_run", "infrastructure_error", "timeout"})
        channel_counts["effects"] += int(row.get("effectCount", 0))
    return {
        "actionDenominator": len(rows),
        "outcomeCounts": {key: counts[key] for key in sorted(OUTCOMES)},
        "categoryDenominators": {key: categories[key] for key in sorted(categories)},
        "channelCoverage": channels,
        "actualEffectCount": effects,
        "positiveCompletionLatencyMs": {
            "count": len(positive),
            "mean": (sum(positive) / len(positive)) if positive else None,
            "values": positive,
        },
    }
