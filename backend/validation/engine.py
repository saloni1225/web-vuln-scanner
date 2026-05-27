from __future__ import annotations

import hashlib
from statistics import mean


def build_validation_summary(findings: list[dict[str, object]]) -> dict[str, object]:
    cache_keys = []
    validated = 0
    review = 0
    proof_scores = []
    clusters: dict[str, int] = {}
    for finding in findings:
        cache_keys.append(_validation_cache_key(finding))
        state = str(finding.get("validation_state", "requires-review"))
        if state == "validated":
            validated += 1
        else:
            review += 1
        proof_score = _exploit_proof_score(finding)
        proof_scores.append(proof_score)
        cluster_key = str(finding.get("category") or finding.get("detector") or "generic")
        clusters[cluster_key] = clusters.get(cluster_key, 0) + 1
    return {
        "validated_count": validated,
        "requires_review_count": review,
        "validation_cache_keys": cache_keys[:100],
        "average_exploit_proof_score": round(mean(proof_scores), 2) if proof_scores else 0.0,
        "high_proof_count": sum(1 for score in proof_scores if score >= 0.75),
        "anomaly_clusters": [
            {"cluster": key, "finding_count": value}
            for key, value in sorted(clusters.items(), key=lambda item: item[1], reverse=True)
        ],
        "engines": ["response-diff", "timing-analysis", "anomaly-analysis", "safe-replay"],
        "false_positive_reduction": "confidence-weighted validation with replayable evidence bundles",
        "safe_replay_runner": {
            "mode": "manual-confirmation",
            "cache": "deduplicated by detector/url/parameter/payload",
            "verification": "baseline and mutated response comparison with timing and content-length deltas",
        },
    }


def _validation_cache_key(finding: dict[str, object]) -> str:
    raw = "|".join(str(finding.get(key, "")) for key in ("detector", "url", "parameter", "payload"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _exploit_proof_score(finding: dict[str, object]) -> float:
    score = 0.2
    if finding.get("validation_state") == "validated":
        score += 0.25
    if finding.get("confidence") == "high":
        score += 0.2
    elif finding.get("confidence") == "medium":
        score += 0.1
    if finding.get("baseline_status") != finding.get("mutated_status") and finding.get("mutated_status") is not None:
        score += 0.15
    baseline_length = finding.get("baseline_length")
    mutated_length = finding.get("mutated_length")
    if isinstance(baseline_length, int) and isinstance(mutated_length, int) and abs(baseline_length - mutated_length) > 20:
        score += 0.1
    if finding.get("payload"):
        score += 0.05
    if finding.get("request_snapshot") or finding.get("response_snapshot"):
        score += 0.05
    return round(min(score, 1.0), 2)
