from __future__ import annotations


def summarize_modern_crawl(site_map: dict[str, object]) -> dict[str, object]:
    endpoints = [item for item in site_map.get("endpoints", []) if isinstance(item, dict)]
    forms = [item for item in site_map.get("forms", []) if isinstance(item, dict)]
    api_endpoints = [item for item in endpoints if item.get("type") in {"api", "graphql", "schema"}]
    dom_candidates = [
        endpoint for endpoint in endpoints
        if any(token in str(endpoint.get("url", "")).lower() for token in ("callback", "redirect", "returnurl", "next="))
    ]
    return {
        "browser_instrumentation": "playwright",
        "spa_framework_support": ["React", "Vue", "Angular", "Svelte"],
        "dynamic_route_count": len(endpoints),
        "form_count": len(forms),
        "api_extraction_count": len(api_endpoints),
        "graphql_candidates": [item for item in endpoints if item.get("type") == "graphql"],
        "dom_sink_candidates": dom_candidates[:25],
        "state_controls": {
            "safe_mode": True,
            "state_changing_requests": bool(site_map.get("allow_state_changing_fuzz", False)),
            "concurrency_model": "bounded-async",
        },
    }

