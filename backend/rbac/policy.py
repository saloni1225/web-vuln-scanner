from __future__ import annotations


ROLE_PERMISSIONS = {
    "owner": {
        "org:admin", "workspace:admin", "scan:run", "scan:read", "finding:manage", "report:read", "api_key:manage",
        "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read", "orchestration:read",
        "threat_intel:read", "ai:read", "compliance:read", "integration:manage", "devsecops:read", "rbac:admin",
    },
    "admin": {
        "workspace:admin", "scan:run", "scan:read", "finding:manage", "report:read", "api_key:manage",
        "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read", "orchestration:read",
        "threat_intel:read", "ai:read", "compliance:read", "integration:manage", "devsecops:read",
    },
    "security_engineer": {
        "workspace:read", "scan:run", "scan:read", "finding:manage", "report:read",
        "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read",
        "threat_intel:read", "ai:read", "devsecops:read",
    },
    "analyst": {"workspace:read", "scan:run", "scan:read", "finding:manage", "report:read", "monitoring:read"},
    "viewer": {"workspace:read", "scan:read", "report:read", "monitoring:read"},
    "ci-bot": {"scan:run", "scan:read", "report:read", "devsecops:read"},
}


def can(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def rbac_overview() -> dict[str, object]:
    return {
        "roles": [{"role": role, "permissions": sorted(permissions)} for role, permissions in ROLE_PERMISSIONS.items()],
        "enforcement_points": ["API routes", "websocket feeds", "workspace isolation", "scan execution", "report access", "API keys", "telemetry", "attack intelligence"],
    }
