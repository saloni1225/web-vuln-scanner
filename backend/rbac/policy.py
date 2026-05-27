from __future__ import annotations


ROLE_PERMISSIONS = {
    "owner": {"org:admin", "workspace:admin", "scan:run", "scan:read", "finding:manage", "report:read", "api_key:manage"},
    "analyst": {"workspace:read", "scan:run", "scan:read", "finding:manage", "report:read"},
    "viewer": {"workspace:read", "scan:read", "report:read"},
    "ci-bot": {"scan:run", "scan:read", "report:read"},
}


def can(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def rbac_overview() -> dict[str, object]:
    return {
        "roles": [{"role": role, "permissions": sorted(permissions)} for role, permissions in ROLE_PERMISSIONS.items()],
        "enforcement_points": ["API routes", "workspace isolation", "scan execution", "report access", "API keys"],
    }

