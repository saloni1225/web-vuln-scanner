from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, WebSocket, status

from backend.rbac.policy import can


@dataclass(frozen=True)
class Principal:
    role: str
    actor: str
    permissions: set[str]

    def can(self, permission: str) -> bool:
        return can(self.role, permission)


def principal_from_role(role: str | None, actor: str | None = None) -> Principal:
    normalized = (role or "owner").strip().lower().replace("-", "_")
    if normalized == "security engineer":
        normalized = "security_engineer"
    return Principal(role=normalized, actor=actor or "local-user", permissions=set())


async def current_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    x_adaptivescan_role: str | None = Header(default=None),
    x_adaptivescan_actor: str | None = Header(default=None),
) -> Principal:
    role = x_adaptivescan_role or _role_from_authorization(authorization) or request.query_params.get("role")
    return principal_from_role(role, x_adaptivescan_actor)


def require_permission(permission: str):
    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.can(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": "This workspace module requires privileged operations access.",
                    "required_permission": permission,
                    "role": principal.role,
                },
            )
        return principal

    return dependency


def websocket_principal(websocket: WebSocket) -> Principal:
    role = websocket.query_params.get("role") or websocket.headers.get("x-adaptivescan-role")
    auth = websocket.query_params.get("token") or websocket.headers.get("authorization")
    return principal_from_role(role or _role_from_authorization(auth), websocket.query_params.get("actor"))


def _role_from_authorization(value: str | None) -> str | None:
    if not value:
        return None
    token = value.removeprefix("Bearer").strip()
    if not token:
        return None
    if token in {"owner", "admin", "security_engineer", "analyst", "viewer", "ci-bot"}:
        return token
    try:
        payload = token.split(".")[1] if "." in token else token
        payload += "=" * (-len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
        return str(decoded.get("role") or decoded.get("adaptivescan_role") or "")
    except Exception:
        return None
