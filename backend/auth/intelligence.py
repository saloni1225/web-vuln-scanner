from __future__ import annotations


def build_auth_intelligence(scan: dict[str, object]) -> dict[str, object]:
    endpoints = [item for item in scan.get("endpoints", []) if isinstance(item, dict)]
    findings = [item for item in scan.get("findings", []) if isinstance(item, dict)]
    auth_endpoints = [
        item for item in endpoints
        if any(token in str(item.get("url", "")).lower() for token in ("login", "oauth", "openid", "sso", "token", "session", "mfa"))
    ]
    auth_findings = [
        item for item in findings
        if any(token in str(item.get("detector", "")).lower() + str(item.get("category", "")).lower() for token in ("auth", "jwt", "oauth", "idor", "csrf"))
    ]
    return {
        "auth_endpoint_count": len(auth_endpoints),
        "auth_endpoints": auth_endpoints[:50],
        "auth_finding_count": len(auth_findings),
        "identity_providers": _infer_identity_providers(auth_endpoints),
        "risk_indicators": _risk_indicators(auth_endpoints, auth_findings),
        "recommended_tests": [
            "role differential replay",
            "JWT claim hardening review",
            "OAuth redirect URI validation",
            "session fixation and reuse checks",
            "IDOR correlation on object APIs",
        ],
    }


def _infer_identity_providers(auth_endpoints: list[dict[str, object]]) -> list[str]:
    blob = " ".join(str(item.get("url", "")).lower() for item in auth_endpoints)
    providers = []
    for token, provider in {"okta": "Okta", "auth0": "Auth0", "azure": "Microsoft Entra ID", "google": "Google Identity", "oauth": "OAuth2", "openid": "OpenID Connect"}.items():
        if token in blob:
            providers.append(provider)
    return sorted(set(providers))


def _risk_indicators(auth_endpoints: list[dict[str, object]], auth_findings: list[dict[str, object]]) -> list[str]:
    indicators = []
    if auth_endpoints and not any("mfa" in str(item.get("url", "")).lower() for item in auth_endpoints):
        indicators.append("mfa-surface-not-observed")
    if any("jwt" in str(item).lower() for item in auth_findings):
        indicators.append("jwt-finding-present")
    if any("idor" in str(item).lower() for item in auth_findings):
        indicators.append("object-authorization-risk")
    if len(auth_endpoints) > 5:
        indicators.append("complex-auth-surface")
    return indicators

