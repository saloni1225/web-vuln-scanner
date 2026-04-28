from copy import deepcopy


SCAN_PROFILES: dict[str, dict[str, object]] = {
    "quick": {
        "label": "Quick Scan",
        "description": "Fast crawl and core detectors for local smoke testing.",
        "rate_limit_per_second": 5.0,
        "enable_api_fuzzing": True,
        "enable_graphql_checks": False,
        "enable_directory_fuzzing": False,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": False,
    },
    "deep": {
        "label": "Deep Scan",
        "description": "Broader discovery, API fuzzing, validation, and recon.",
        "rate_limit_per_second": 2.0,
        "enable_api_fuzzing": True,
        "enable_graphql_checks": True,
        "enable_directory_fuzzing": True,
        "enable_safe_port_scan": True,
        "enable_subdomain_recon": True,
        "enable_screenshot_recon": True,
    },
    "passive": {
        "label": "Passive Audit",
        "description": "Header, TLS, technology, and surface review with minimal probing.",
        "rate_limit_per_second": 1.5,
        "enable_api_fuzzing": False,
        "enable_graphql_checks": False,
        "enable_directory_fuzzing": False,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": True,
        "enable_screenshot_recon": True,
    },
    "api": {
        "label": "API Scan",
        "description": "REST, JSON, OpenAPI, and GraphQL focused probing.",
        "rate_limit_per_second": 2.5,
        "enable_api_fuzzing": True,
        "enable_graphql_checks": True,
        "enable_directory_fuzzing": True,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": False,
    },
    "stealth": {
        "label": "Low Impact",
        "description": "Authorized low-noise profile with slower pacing and limited probes.",
        "rate_limit_per_second": 0.7,
        "enable_api_fuzzing": True,
        "enable_graphql_checks": False,
        "enable_directory_fuzzing": False,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": False,
    },
    "authenticated": {
        "label": "Authenticated Scan",
        "description": "Session-aware scan tuned for login-protected surfaces.",
        "rate_limit_per_second": 2.0,
        "enable_api_fuzzing": True,
        "enable_graphql_checks": True,
        "enable_directory_fuzzing": True,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": True,
    },
}


def list_scan_profiles() -> list[dict[str, object]]:
    return [
        {"name": name, **profile}
        for name, profile in SCAN_PROFILES.items()
    ]


def get_scan_profile(name: str | None) -> dict[str, object]:
    profile_name = (name or "deep").lower()
    profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["deep"])
    return {"name": profile_name if profile_name in SCAN_PROFILES else "deep", **deepcopy(profile)}


def apply_scan_profile(scan_options: dict[str, object] | None) -> dict[str, object]:
    options = dict(scan_options or {})
    profile = get_scan_profile(str(options.get("scan_profile") or "deep"))
    for key, value in profile.items():
        if options.get(key) is None:
            options[key] = value
    options["scan_profile"] = profile["name"]
    options["scan_profile_label"] = profile["label"]
    options["scan_profile_description"] = profile["description"]
    return options
