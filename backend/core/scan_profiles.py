from copy import deepcopy


SCAN_PROFILES: dict[str, dict[str, object]] = {
    "quick": {
        "label": "Recon Sweep",
        "description": "Fast bug bounty triage: crawl, fingerprint, and run core low-noise checks.",
        "rate_limit_per_second": 5.0,
        "enable_api_fuzzing": True,
        "enable_unsafe_state_changing_fuzz": False,
        "enable_graphql_checks": False,
        "enable_directory_fuzzing": False,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": False,
        "max_detector_params": 3,
        "max_payloads_per_param": 1,
        "enable_login_route_probing": False,
    },
    "deep": {
        "label": "Bounty Standard",
        "description": "Balanced authorized assessment with SPA crawling, API probes, validation, and recon.",
        "rate_limit_per_second": 2.0,
        "enable_api_fuzzing": True,
        "enable_unsafe_state_changing_fuzz": False,
        "enable_graphql_checks": True,
        "enable_directory_fuzzing": True,
        "enable_safe_port_scan": True,
        "enable_subdomain_recon": True,
        "enable_screenshot_recon": True,
        "max_detector_params": 6,
        "max_payloads_per_param": 2,
        "enable_login_route_probing": False,
    },
    "passive": {
        "label": "Passive Recon",
        "description": "Header, TLS, technology, screenshot, and surface review with minimal active traffic.",
        "rate_limit_per_second": 1.5,
        "enable_api_fuzzing": False,
        "enable_unsafe_state_changing_fuzz": False,
        "enable_graphql_checks": False,
        "enable_directory_fuzzing": False,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": True,
        "enable_screenshot_recon": True,
        "max_detector_params": 0,
        "max_payloads_per_param": 0,
        "enable_login_route_probing": False,
    },
    "api": {
        "label": "API Bounty",
        "description": "REST, JSON, OpenAPI, and GraphQL focused probes with controlled state-changing traffic.",
        "rate_limit_per_second": 2.5,
        "enable_api_fuzzing": True,
        "enable_unsafe_state_changing_fuzz": False,
        "enable_graphql_checks": True,
        "enable_directory_fuzzing": True,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": False,
        "max_detector_params": 8,
        "max_payloads_per_param": 2,
        "enable_login_route_probing": False,
    },
    "stealth": {
        "label": "Low-Noise Triage",
        "description": "Slow-paced authorized triage for fragile targets and rate-limited programs.",
        "rate_limit_per_second": 0.7,
        "enable_api_fuzzing": True,
        "enable_unsafe_state_changing_fuzz": False,
        "enable_graphql_checks": False,
        "enable_directory_fuzzing": False,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": False,
        "max_detector_params": 2,
        "max_payloads_per_param": 1,
        "enable_login_route_probing": False,
    },
    "authenticated": {
        "label": "Authenticated Bounty",
        "description": "Session-aware assessment for login-protected surfaces and role-aware review.",
        "rate_limit_per_second": 2.0,
        "enable_api_fuzzing": True,
        "enable_unsafe_state_changing_fuzz": False,
        "enable_graphql_checks": True,
        "enable_directory_fuzzing": True,
        "enable_safe_port_scan": False,
        "enable_subdomain_recon": False,
        "enable_screenshot_recon": True,
        "max_detector_params": 10,
        "max_payloads_per_param": 3,
        "enable_login_route_probing": True,
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
