from __future__ import annotations


def authenticated_scan_capabilities() -> dict[str, object]:
    return {
        "supported": ["JWT reuse", "cookie reuse", "custom headers", "login form replay", "role labels"],
        "planned_protocols": ["OAuth authorization code", "OIDC discovery", "MFA TOTP handoff", "browser login recording"],
        "security_controls": ["encrypted credential storage boundary", "scope allowlists", "authorization confirmation"],
    }

