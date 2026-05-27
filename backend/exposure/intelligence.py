from __future__ import annotations

from urllib.parse import urlparse


SENSITIVE_API_TOKENS = {
    "admin": 28,
    "user": 14,
    "users": 14,
    "account": 16,
    "billing": 22,
    "payment": 24,
    "invoice": 20,
    "token": 24,
    "session": 18,
    "graphql": 26,
    "upload": 18,
    "export": 16,
    "internal": 20,
}


def build_exposure_intelligence(scan: dict[str, object]) -> dict[str, object]:
    summary = scan.get("summary", {}) if isinstance(scan.get("summary"), dict) else {}
    recon = scan.get("recon_summary", {}) if isinstance(scan.get("recon_summary"), dict) else {}
    api_security = scan.get("api_security_summary", {}) if isinstance(scan.get("api_security_summary"), dict) else {}
    auth = scan.get("auth_intelligence", {}) if isinstance(scan.get("auth_intelligence"), dict) else {}
    graph = scan.get("attack_surface_graph", {}) if isinstance(scan.get("attack_surface_graph"), dict) else {}
    endpoints = [item for item in scan.get("endpoints", []) if isinstance(item, dict)]
    findings = [item for item in scan.get("findings", []) if isinstance(item, dict)]

    public_score = _public_exposure_score(summary, recon, endpoints)
    api_score = _api_sensitivity_score(endpoints, api_security)
    auth_score = _auth_exposure_score(auth, findings)
    cloud_score = _cloud_exposure_score(recon)
    exploitability_score = _exploitability_score(findings, graph)
    exposure_score = min(100, round(public_score * 0.25 + api_score * 0.22 + auth_score * 0.18 + cloud_score * 0.15 + exploitability_score * 0.2))

    return {
        "target_url": scan.get("target_url"),
        "score": exposure_score,
        "label": _score_label(exposure_score),
        "dimensions": {
            "public_attack_surface": public_score,
            "api_sensitivity": api_score,
            "auth_exposure": auth_score,
            "cloud_exposure": cloud_score,
            "exploitability": exploitability_score,
        },
        "priority_assets": _priority_assets(scan, endpoints, findings),
        "heatmap": _heatmap(endpoints, findings),
        "recommended_operations": _recommended_operations(exposure_score, api_score, auth_score, cloud_score),
    }


def aggregate_exposure(scans: list[dict[str, object]]) -> dict[str, object]:
    enriched = []
    for scan in scans:
        existing = scan.get("exposure_intelligence") if isinstance(scan.get("exposure_intelligence"), dict) else None
        enriched.append(existing or build_exposure_intelligence(scan))
    if not enriched:
        return {"score": 0, "label": "no telemetry", "targets": [], "highest_risk": None, "dimension_averages": {}}
    dimension_keys = list(enriched[0].get("dimensions", {}).keys())
    return {
        "score": round(sum(int(item.get("score", 0) or 0) for item in enriched) / len(enriched)),
        "label": _score_label(round(sum(int(item.get("score", 0) or 0) for item in enriched) / len(enriched))),
        "targets": enriched[:100],
        "highest_risk": max(enriched, key=lambda item: int(item.get("score", 0) or 0)),
        "dimension_averages": {
            key: round(sum(int(item.get("dimensions", {}).get(key, 0) or 0) for item in enriched) / len(enriched))
            for key in dimension_keys
        },
    }


def _public_exposure_score(summary: dict[str, object], recon: dict[str, object], endpoints: list[dict[str, object]]) -> int:
    endpoint_score = min(35, int(summary.get("endpoint_count", len(endpoints)) or 0) // 8)
    risky_endpoint_score = min(25, int(summary.get("high_risk_endpoint_count", 0) or 0) * 6)
    port_score = min(20, len(recon.get("port_summary", {}).get("open_ports", [])) * 8) if isinstance(recon.get("port_summary"), dict) else 0
    admin_score = 20 if any("admin" in str(item.get("url", "")).lower() or "dashboard" in str(item.get("url", "")).lower() for item in endpoints) else 0
    return min(100, endpoint_score + risky_endpoint_score + port_score + admin_score)


def _api_sensitivity_score(endpoints: list[dict[str, object]], api_security: dict[str, object]) -> int:
    score = int(api_security.get("undocumented_endpoint_count", 0) or 0) * 4
    score += int(api_security.get("graphql_endpoint_count", 0) or 0) * 14
    for endpoint in endpoints:
        url = str(endpoint.get("url", "")).lower()
        if "/api" in url:
            score += 4
        for token, weight in SENSITIVE_API_TOKENS.items():
            if token in url:
                score += weight
                break
    return min(100, score)


def _auth_exposure_score(auth: dict[str, object], findings: list[dict[str, object]]) -> int:
    score = int(auth.get("auth_endpoint_count", 0) or 0) * 8
    score += len(auth.get("risk_indicators", [])) * 16 if isinstance(auth.get("risk_indicators"), list) else 0
    score += sum(18 for finding in findings if any(token in str(finding).lower() for token in ("auth", "idor", "jwt", "oauth", "csrf")))
    return min(100, score)


def _cloud_exposure_score(recon: dict[str, object]) -> int:
    cloud = recon.get("cloud_asset_summary", {}) if isinstance(recon.get("cloud_asset_summary"), dict) else {}
    exposed = int(cloud.get("exposed_count", len(cloud.get("exposed", []))) or 0)
    candidates = int(cloud.get("candidate_count", len(cloud.get("candidates", []))) or 0)
    return min(100, exposed * 40 + min(20, candidates // 2))


def _exploitability_score(findings: list[dict[str, object]], graph: dict[str, object]) -> int:
    score = sum({"critical": 30, "high": 22, "medium": 10, "low": 3}.get(str(item.get("severity", "low")).lower(), 4) for item in findings)
    score += sum(8 for item in findings if item.get("validation_state") == "validated")
    score += min(42, len(graph.get("attack_paths", [])) * 22) if isinstance(graph.get("attack_paths"), list) else 0
    return min(100, score)


def _priority_assets(scan: dict[str, object], endpoints: list[dict[str, object]], findings: list[dict[str, object]]) -> list[dict[str, object]]:
    target_host = urlparse(str(scan.get("target_url", ""))).hostname or str(scan.get("target_url", ""))
    assets = []
    for endpoint in endpoints:
        url = str(endpoint.get("url", ""))
        endpoint_findings = [finding for finding in findings if str(finding.get("url", "")) == url]
        assets.append(
            {
                "asset": url or target_host,
                "type": endpoint.get("type", "endpoint"),
                "score": min(100, _api_sensitivity_score([endpoint], {}) + len(endpoint_findings) * 18),
                "finding_count": len(endpoint_findings),
                "reason": "sensitive API or exposed route" if "/api" in url.lower() or "admin" in url.lower() else "mapped public endpoint",
            }
        )
    return sorted(assets, key=lambda item: int(item["score"]), reverse=True)[:25]


def _heatmap(endpoints: list[dict[str, object]], findings: list[dict[str, object]]) -> list[dict[str, object]]:
    buckets = {"api": 0, "auth": 0, "admin": 0, "cloud": 0, "findings": len(findings)}
    for endpoint in endpoints:
        url = str(endpoint.get("url", "")).lower()
        if "/api" in url or endpoint.get("type") in {"api", "graphql"}:
            buckets["api"] += 1
        if any(token in url for token in ("login", "oauth", "session", "token")):
            buckets["auth"] += 1
        if any(token in url for token in ("admin", "dashboard", "console")):
            buckets["admin"] += 1
    return [{"dimension": key, "value": value, "intensity": min(100, value * 12)} for key, value in buckets.items()]


def _recommended_operations(exposure_score: int, api_score: int, auth_score: int, cloud_score: int) -> list[str]:
    operations = ["monitor drift and preserve evidence"]
    if exposure_score >= 70:
        operations.insert(0, "open offensive triage for top attack paths")
    if api_score >= 50:
        operations.append("run API auth boundary and BOLA checks")
    if auth_score >= 45:
        operations.append("compare roles and validate object authorization")
    if cloud_score >= 35:
        operations.append("validate cloud storage permissions and ownership")
    return operations


def _score_label(score: int | float) -> str:
    if score >= 80:
        return "critical exposure"
    if score >= 60:
        return "high exposure"
    if score >= 35:
        return "elevated exposure"
    if score > 0:
        return "controlled exposure"
    return "no exposure telemetry"
