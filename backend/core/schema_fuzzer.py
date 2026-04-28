import json
from urllib.parse import urlencode, urlparse, urlunparse

from backend.config.settings import settings


GENERIC_VALUES = {
    "id": "1",
    "user": "scanner-user",
    "username": "scanner-user",
    "email": "scanner@example.test",
    "name": "scanner",
    "q": "scanner",
    "query": "scanner",
    "search": "scanner",
    "password": "Password123!",
}

BOUNDARY_VALUES = {
    "integer": ["0", "1", "-1", "2147483647"],
    "number": ["0", "1.1", "-1.1", "1e309"],
    "boolean": ["true", "false", "1", "0"],
    "string": ["scanner", "", "A" * 256, "scanner@example.test"],
    "array": ["[]", "[\"scanner\"]"],
    "object": ["{}", "{\"scanner\":\"value\"}"],
}


async def run_schema_fuzzing(site_map: dict[str, object], request_handler, enabled: bool = True) -> dict[str, object]:
    if not enabled:
        return {"enabled": False, "probes": [], "graphql": []}
    probes = []
    graphql = []
    for endpoint in site_map.get("endpoints", [])[:30]:
        if not isinstance(endpoint, dict):
            continue
        endpoint_type = str(endpoint.get("type", "page"))
        url = str(endpoint.get("url", ""))
        method = str(endpoint.get("method", "get")).lower()
        fields = [str(item) for item in [*endpoint.get("query_params", []), *endpoint.get("schema_fields", [])] if item]
        field_types = endpoint.get("schema_field_types", {}) if isinstance(endpoint.get("schema_field_types"), dict) else {}
        if not url or endpoint_type not in {"api", "graphql"}:
            continue
        if endpoint_type == "graphql":
            graphql.append(await _probe_graphql(url, fields, field_types, request_handler))
            continue
        probes.append(await _probe_rest(url, method, fields, field_types, request_handler))
    return {
        "enabled": True,
        "probes": probes,
        "graphql": graphql,
        "probe_count": len(probes) + len(graphql),
        "schema_field_count": sum(len(item.get("fields", [])) for item in probes + graphql),
        "mutation_case_count": sum(len(item.get("cases", [])) for item in probes + graphql),
    }


async def _probe_rest(url: str, method: str, fields: list[str], field_types: dict[str, object], request_handler) -> dict[str, object]:
    fields = list(dict.fromkeys(fields))[:8]
    cases = _build_mutation_cases(fields, field_types)
    body = _representative_body(cases)
    try:
        if method == "get":
            parsed = urlparse(url)
            query = dict([part.split("=", 1) if "=" in part else [part, ""] for part in parsed.query.split("&") if part])
            query.update(body)
            response = await request_handler.get(urlunparse(parsed._replace(query=urlencode(query))))
        else:
            response = await request_handler.post_json(url, body)
        status_code = response.status_code
        content_type = response.headers.get("content-type", "")
        reflected_fields = [field for field, value in body.items() if str(value) in response.text]
    except Exception as exc:
        return {"url": url, "method": method.upper(), "fields": fields, "status": "failed", "error": str(exc)}
    return {
        "url": url,
        "method": method.upper(),
        "fields": fields,
        "status_code": status_code,
        "content_type": content_type,
        "reflected_fields": reflected_fields,
        "cases": cases,
        "field_types": field_types,
        "status": "completed",
    }


async def _probe_graphql(url: str, fields: list[str], field_types: dict[str, object], request_handler) -> dict[str, object]:
    fields = [field for field in list(dict.fromkeys(fields)) if field not in {"query", "variables"}][:8]
    cases = _build_mutation_cases(fields, field_types)
    query = "{__typename}"
    if fields:
        query = _build_graphql_probe_query(fields)
    try:
        variables = _representative_body(cases)
        response = await request_handler.post_json(url, {"query": query, "variables": variables})
        payload = json.loads(response.text) if response.text.strip().startswith("{") else {}
    except Exception as exc:
        return {"url": url, "fields": fields, "status": "failed", "error": str(exc)}
    return {
        "url": url,
        "fields": fields,
        "status_code": response.status_code,
        "errors": payload.get("errors", []) if isinstance(payload, dict) else [],
        "data_keys": list(payload.get("data", {}).keys()) if isinstance(payload.get("data"), dict) else [],
        "cases": cases,
        "field_types": field_types,
        "query": query,
        "status": "completed",
    }


def _value_for_field(field: str) -> str:
    lowered = field.lower()
    for key, value in GENERIC_VALUES.items():
        if key in lowered:
            return value
    return "scanner"


def _build_mutation_cases(fields: list[str], field_types: dict[str, object]) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for field in fields:
        schema_type = str(field_types.get(field) or _infer_type_from_name(field)).lower()
        values = BOUNDARY_VALUES.get(schema_type, BOUNDARY_VALUES["string"])
        for value in values[: settings.max_schema_fuzz_cases_per_field]:
            cases.append({"field": field, "type": schema_type, "value": _coerce_value(value, schema_type)})
    if not cases:
        cases.append({"field": "scanner", "type": "string", "value": "scanner"})
    return cases[: max(1, len(fields) * settings.max_schema_fuzz_cases_per_field)]


def _representative_body(cases: list[dict[str, object]]) -> dict[str, object]:
    body: dict[str, object] = {}
    for case in cases:
        field = str(case.get("field") or "")
        if field and field not in body:
            body[field] = case.get("value")
    return body


def _infer_type_from_name(field: str) -> str:
    lowered = field.lower()
    if lowered.startswith("is_") or lowered.startswith("has_") or lowered in {"enabled", "active", "admin"}:
        return "boolean"
    if any(token in lowered for token in ("id", "count", "age", "page", "limit", "offset")):
        return "integer"
    if any(token in lowered for token in ("price", "amount", "total", "score")):
        return "number"
    return "string"


def _coerce_value(value: str, schema_type: str) -> object:
    if schema_type == "integer":
        try:
            return int(value)
        except ValueError:
            return value
    if schema_type == "number":
        try:
            return float(value)
        except ValueError:
            return value
    if schema_type == "boolean":
        return value in {"true", "1"}
    if schema_type in {"array", "object"}:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _build_graphql_probe_query(fields: list[str]) -> str:
    safe_fields = [field for field in fields if field.replace("_", "").isalnum()][:6]
    selection = " ".join(safe_fields) if safe_fields else "__typename"
    return f"query ScannerProbe {{ __typename {selection} }}"
