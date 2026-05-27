from __future__ import annotations


def analyze_api_surface(site_map: dict[str, object], schema_fuzz_summary: dict[str, object]) -> dict[str, object]:
    endpoints = [item for item in site_map.get("endpoints", []) if isinstance(item, dict)]
    api_endpoints = [item for item in endpoints if str(item.get("type")) in {"api", "graphql", "schema"} or "/api" in str(item.get("url", "")).lower()]
    graphql = [item for item in endpoints if "graphql" in str(item.get("url", "")).lower()]
    undocumented = [
        item for item in api_endpoints
        if not any(marker in str(item.get("url", "")).lower() for marker in ("swagger", "openapi", "schema"))
    ]
    sensitivity = [_endpoint_sensitivity(item) for item in api_endpoints]
    return {
        "rest_endpoint_count": len([item for item in api_endpoints if item not in graphql]),
        "graphql_endpoint_count": len(graphql),
        "schema_fuzz_probe_count": schema_fuzz_summary.get("probe_count", 0),
        "schema_learning": {
            "openapi_detected": any("openapi" in str(item.get("url", "")).lower() for item in endpoints),
            "swagger_detected": any("swagger" in str(item.get("url", "")).lower() for item in endpoints),
            "graphql_introspection_candidate": bool(graphql),
        },
        "risk_tests": [
            "BOLA/IDOR differential checks",
            "mass-assignment candidate modeling",
            "API auth bypass probes",
            "rate-limit posture checks",
            "undocumented endpoint discovery",
        ],
        "undocumented_endpoint_count": len(undocumented),
        "undocumented_endpoint_samples": undocumented[:20],
        "sensitive_endpoint_count": sum(1 for item in sensitivity if item["score"] >= 50),
        "sensitivity_score": min(100, round(sum(item["score"] for item in sensitivity) / max(1, len(sensitivity)))),
        "sensitive_endpoint_samples": sorted(sensitivity, key=lambda item: item["score"], reverse=True)[:20],
    }


def _endpoint_sensitivity(endpoint: dict[str, object]) -> dict[str, object]:
    url = str(endpoint.get("url", "")).lower()
    score = 10
    reasons = []
    for token, weight in {
        "graphql": 28,
        "admin": 34,
        "user": 14,
        "account": 18,
        "billing": 24,
        "payment": 26,
        "token": 28,
        "session": 20,
        "upload": 16,
        "internal": 24,
    }.items():
        if token in url:
            score += weight
            reasons.append(token)
    if str(endpoint.get("method", "GET")).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 12
        reasons.append("state-changing")
    return {"url": endpoint.get("url", ""), "type": endpoint.get("type", "api"), "score": min(100, score), "reasons": reasons or ["generic-api"]}
