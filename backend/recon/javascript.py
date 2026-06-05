from __future__ import annotations

import re
from urllib.parse import urljoin


SECRET_PATTERNS = {
    "jwt": r"eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}",
    "api_key": r"(?i)(api[_-]?key|secret|token)[\"'\s:=]{1,8}[a-z0-9_\-]{16,}",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
}


def analyze_javascript_intelligence(base_url: str, script_bodies: list[dict[str, object]]) -> dict[str, object]:
    endpoints: set[str] = set()
    routes: set[str] = set()
    secrets: list[dict[str, object]] = []
    sinks: set[str] = set()
    debug_flags: set[str] = set()
    source_maps: set[str] = set()
    auth_signals: set[str] = set()

    for script in script_bodies:
        url = str(script.get("url", base_url))
        body = str(script.get("body", ""))
        for candidate in _extract_endpoint_candidates(body):
            endpoints.add(urljoin(base_url, candidate) if candidate.startswith("/") else candidate)
        for route in re.findall(r"['\"](\/[a-zA-Z0-9_\-\/:]{2,})['\"]", body):
            routes.add(route)
        for name, pattern in SECRET_PATTERNS.items():
            for match in re.findall(pattern, body):
                value = match if isinstance(match, str) else match[-1]
                secrets.append({"type": name, "script": url, "fingerprint": str(value)[:10], "severity": "high"})
        for sink in ("innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", "localStorage", "sessionStorage"):
            if sink in body:
                sinks.add(sink.rstrip("("))
        for flag in ("debug=true", "NODE_ENV", "__DEV__", "sourceMappingURL"):
            if flag in body:
                debug_flags.add(flag)
        for match in re.findall(r"sourceMappingURL=([^\s*]+)", body):
            source_maps.add(urljoin(url, match))
        for signal in ("Authorization", "Bearer ", "refreshToken", "accessToken", "isAdmin", "role", "tenantId"):
            if signal in body:
                auth_signals.add(signal)

    return {
        "script_count": len(script_bodies),
        "internal_endpoints": sorted(endpoints)[:100],
        "hidden_routes": sorted(routes)[:100],
        "secret_findings": secrets[:50],
        "dom_sink_indicators": sorted(sinks),
        "debug_indicators": sorted(debug_flags),
        "source_map_candidates": sorted(source_maps)[:50],
        "auth_boundary_indicators": sorted(auth_signals),
        "client_side_auth_analysis": {
            "stores_tokens": any(token in auth_signals for token in ("refreshToken", "accessToken", "Bearer ")),
            "role_logic_present": any(token in auth_signals for token in ("isAdmin", "role", "tenantId")),
        },
        "dom_taint_tracking_ready": bool(sinks),
        "risk_score": min(100, len(secrets) * 25 + len(sinks) * 8 + len(endpoints) * 2),
    }


def _extract_endpoint_candidates(body: str) -> list[str]:
    candidates = []
    patterns = [
        r"fetch\(['\"]([^'\"]+)['\"]",
        r"axios\.[a-z]+\(['\"]([^'\"]+)['\"]",
        r"['\"]((?:\/api|\/graphql|https?:\/\/)[^'\"]{3,})['\"]",
    ]
    for pattern in patterns:
        candidates.extend(re.findall(pattern, body, flags=re.IGNORECASE))
    return [candidate for candidate in candidates if not candidate.startswith("data:")][:200]
