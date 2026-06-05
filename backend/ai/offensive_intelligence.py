from __future__ import annotations

from backend.ai.embeddings import embedding_runtime_status
from backend.ai.vector_intelligence import VectorIntelligenceService


HIGH_VALUE_CATEGORIES = {
    "ssrf",
    "blind-ssrf",
    "request-smuggling",
    "cache-poisoning",
    "race-condition",
    "jwt",
    "oauth",
    "idor",
    "rbac-bypass",
    "graphql",
    "nosql-injection",
    "command-injection",
    "ssti",
    "xxe",
    "deserialization",
    "file-upload",
    "path-traversal",
}


def build_offensive_ai_intelligence(scan_or_scans: dict[str, object] | list[dict[str, object]]) -> dict[str, object]:
    scans = scan_or_scans if isinstance(scan_or_scans, list) else [scan_or_scans]
    findings = [finding for scan in scans for finding in scan.get("findings", []) if isinstance(finding, dict)]
    endpoints = [endpoint for scan in scans for endpoint in scan.get("endpoints", []) if isinstance(endpoint, dict)]
    attack_paths = [
        path
        for scan in scans
        for path in (scan.get("attack_surface_graph", {}).get("attack_paths", []) if isinstance(scan.get("attack_surface_graph"), dict) else [])
        if isinstance(path, dict)
    ]
    vector_service = VectorIntelligenceService()
    finding_clusters = vector_service.cluster_findings(findings)
    risky_assets = _predict_risky_assets(scans, findings, endpoints)
    return {
        "runtime": {
            **embedding_runtime_status(),
            "inference_ready": True,
            "supported_inference_models": ["meta-llama/Meta-Llama-3-8B-Instruct", "mistralai/Mistral-7B-Instruct-v0.3"],
        },
        "exploitability_predictions": [_exploitability_prediction(finding) for finding in findings[:100]],
        "attack_path_confidence": [_attack_path_confidence(path) for path in attack_paths[:50]],
        "risky_asset_predictions": risky_assets,
        "sensitive_endpoint_predictions": [_endpoint_prediction(endpoint) for endpoint in endpoints[:100]],
        "anomaly_intelligence": _anomaly_intelligence(scans),
        "finding_deduplication": {
            "cluster_count": len(finding_clusters),
            "clusters": finding_clusters,
        },
        "ai_remediation": _ai_remediation(findings[:10]),
    }


def _exploitability_prediction(finding: dict[str, object]) -> dict[str, object]:
    severity = str(finding.get("severity", "medium")).lower()
    category = str(finding.get("category", finding.get("detector", ""))).lower()
    validation = str(finding.get("validation_state", "")).lower()
    score = {"critical": 92, "high": 82, "medium": 58, "low": 34}.get(severity, 48)
    if category in HIGH_VALUE_CATEGORIES:
        score += 10
    if validation == "validated":
        score += 8
    if any(token in str(finding.get("url", "")).lower() for token in ("admin", "graphql", "api", "upload")):
        score += 5
    score = min(100, score)
    return {
        "title": finding.get("detector") or category or "finding",
        "url": finding.get("url"),
        "category": category,
        "score": score,
        "confidence": "high" if score >= 80 else "medium" if score >= 55 else "low",
        "reason": "Severity, exposed surface, validation state, and offensive category weighting.",
    }


def _attack_path_confidence(path: dict[str, object]) -> dict[str, object]:
    risk = int(path.get("risk_score", 0) or 0)
    steps = len(path.get("steps", []) or [])
    finding_samples = len(path.get("finding_samples", []) or [])
    confidence = min(100, risk + steps * 2 + finding_samples * 3)
    return {
        "name": path.get("name"),
        "risk_score": risk,
        "confidence": confidence,
        "explainability": "Path confidence combines risk score, chain length, and finding evidence density.",
    }


def _predict_risky_assets(scans: list[dict[str, object]], findings: list[dict[str, object]], endpoints: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for scan in scans:
        summary = scan.get("summary", {}) if isinstance(scan.get("summary"), dict) else {}
        target = str(scan.get("target_url", "unknown"))
        target_findings = [finding for finding in findings if str(finding.get("url", "")).startswith(target) or target.split("?")[0] in str(finding.get("url", ""))]
        target_endpoints = [endpoint for endpoint in endpoints if target.split("?")[0] in str(endpoint.get("url", ""))]
        score = min(100, len(target_findings) * 8 + len(target_endpoints) + int(summary.get("high_severity_count", 0) or 0) * 18)
        rows.append({"asset": target, "score": score, "prediction": "risky" if score >= 60 else "watch" if score >= 30 else "stable"})
    return sorted(rows, key=lambda item: int(item["score"]), reverse=True)[:50]


def _endpoint_prediction(endpoint: dict[str, object]) -> dict[str, object]:
    url = str(endpoint.get("url", ""))
    lower = url.lower()
    score = 20
    if "graphql" in lower:
        score += 25
    if "/api" in lower:
        score += 18
    if any(token in lower for token in ("admin", "dashboard", "console", "debug")):
        score += 25
    if any(token in lower for token in ("user", "account", "payment", "token", "upload")):
        score += 12
    return {
        "url": url,
        "type": endpoint.get("type", "endpoint"),
        "sensitivity_score": min(100, score),
        "prediction": "sensitive" if score >= 60 else "review" if score >= 40 else "low",
    }


def _anomaly_intelligence(scans: list[dict[str, object]]) -> dict[str, object]:
    summaries = [scan.get("summary", {}) if isinstance(scan.get("summary"), dict) else {} for scan in scans]
    endpoint_counts = [int(summary.get("endpoint_count", 0) or scan.get("endpoint_count", 0) or 0) for scan, summary in zip(scans, summaries)]
    finding_counts = [int(summary.get("finding_count", 0) or scan.get("findings_count", 0) or 0) for scan, summary in zip(scans, summaries)]
    endpoint_spike = max(endpoint_counts, default=0) - min(endpoint_counts, default=0)
    finding_spike = max(finding_counts, default=0) - min(finding_counts, default=0)
    return {
        "endpoint_spike": endpoint_spike,
        "finding_spike": finding_spike,
        "anomaly_score": min(100, endpoint_spike // 2 + finding_spike * 4),
        "status": "investigate" if endpoint_spike > 25 or finding_spike > 5 else "normal",
    }


def _ai_remediation(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "finding": finding.get("detector") or finding.get("category"),
            "priority": finding.get("remediation_priority", "P2"),
            "action": finding.get("recommendation") or "Validate exploitability, assign owner, add regression coverage, and retest.",
        }
        for finding in findings
    ]
