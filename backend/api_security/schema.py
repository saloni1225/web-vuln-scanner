from __future__ import annotations


def parse_openapi_document(document: dict[str, object]) -> dict[str, object]:
    paths = document.get("paths", {}) if isinstance(document.get("paths"), dict) else {}
    endpoints = []
    sensitive_count = 0
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if str(method).lower() not in {"get", "post", "put", "patch", "delete", "options"}:
                continue
            auth_required = bool((operation if isinstance(operation, dict) else {}).get("security") or document.get("security"))
            sensitivity = _api_path_sensitivity(str(path), method=str(method), auth_required=auth_required)
            sensitive_count += 1 if sensitivity["score"] >= 50 else 0
            endpoints.append({"path": path, "method": str(method).upper(), "auth_required": auth_required, "sensitivity": sensitivity})
    return {
        "format": "openapi",
        "title": document.get("info", {}).get("title", "") if isinstance(document.get("info"), dict) else "",
        "endpoint_count": len(endpoints),
        "sensitive_endpoint_count": sensitive_count,
        "endpoints": endpoints[:500],
    }


def parse_postman_collection(collection: dict[str, object]) -> dict[str, object]:
    endpoints: list[dict[str, object]] = []

    def walk(items: list[object]) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):
                walk(item["item"])
                continue
            request = item.get("request", {})
            if not isinstance(request, dict):
                continue
            method = str(request.get("method", "GET")).upper()
            url = request.get("url", "")
            raw_url = str(url.get("raw", "")) if isinstance(url, dict) else str(url)
            endpoints.append({"name": item.get("name", raw_url), "method": method, "url": raw_url, "sensitivity": _api_path_sensitivity(raw_url, method=method)})

    walk(collection.get("item", []) if isinstance(collection.get("item"), list) else [])
    return {
        "format": "postman",
        "name": collection.get("info", {}).get("name", "") if isinstance(collection.get("info"), dict) else "",
        "endpoint_count": len(endpoints),
        "sensitive_endpoint_count": sum(1 for endpoint in endpoints if endpoint["sensitivity"]["score"] >= 50),
        "endpoints": endpoints[:500],
    }


def analyze_graphql_schema(schema_text: str) -> dict[str, object]:
    lowered = schema_text.lower()
    mutations = _extract_graphql_fields(schema_text, "mutation")
    queries = _extract_graphql_fields(schema_text, "query")
    sensitive = [field for field in [*mutations, *queries] if any(token in field.lower() for token in ("user", "admin", "token", "payment", "delete", "update", "create"))]
    return {
        "format": "graphql",
        "query_count": len(queries),
        "mutation_count": len(mutations),
        "sensitive_field_count": len(sensitive),
        "introspection_enabled_hint": "__schema" in lowered or "__type" in lowered,
        "sensitive_fields": sensitive[:100],
        "risk_tests": ["authorization on object fields", "mutation abuse", "introspection exposure", "batching and depth limits"],
    }


def _extract_graphql_fields(schema_text: str, type_name: str) -> list[str]:
    marker = f"type {type_name.capitalize()}"
    start = schema_text.find(marker)
    if start < 0:
        return []
    open_brace = schema_text.find("{", start)
    close_brace = schema_text.find("}", open_brace)
    if open_brace < 0 or close_brace < 0:
        return []
    body = schema_text[open_brace + 1:close_brace]
    fields = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields.append(line.split("(", 1)[0].split(":", 1)[0].strip())
    return [field for field in fields if field]


def _api_path_sensitivity(path: str, *, method: str, auth_required: bool = False) -> dict[str, object]:
    lower = path.lower()
    score = 10
    reasons = []
    for token, weight in {
        "admin": 34,
        "user": 18,
        "account": 18,
        "payment": 28,
        "billing": 24,
        "token": 30,
        "session": 24,
        "delete": 16,
        "upload": 16,
        "internal": 24,
    }.items():
        if token in lower:
            score += weight
            reasons.append(token)
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 12
        reasons.append("state-changing")
    if auth_required:
        score += 8
        reasons.append("auth-boundary")
    return {"score": min(100, score), "reasons": reasons or ["generic-api"]}

