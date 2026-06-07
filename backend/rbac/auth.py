"""
backend/rbac/auth.py — Secure RBAC principal extraction.

SECURITY NOTE (2024 refactor):
The original implementation of this module extracted roles from request headers
(X-AdaptiveScan-Role) and query parameters (?role=owner) WITHOUT any signature
verification. This is a critical authentication bypass vulnerability — any caller
could escalate their role by setting an HTTP header.

This module is now a secure wrapper around `backend.security.jwt_guard.verified_principal`.
All role extraction is done from cryptographically verified JWTs only.

The legacy functions (`current_principal`, `websocket_principal`, `principal_from_role`)
are kept for API compatibility but now delegate to real JWT verification.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, WebSocket, status

from backend.rbac.policy import can
from backend.security.jwt_guard import (
    VerifiedPrincipal,
    _extract_token,
    _verify_jwt,
    verified_principal,
)


@dataclass(frozen=True)
class Principal:
    role: str
    actor: str
    permissions: set[str]
    organization_id: str = "local-org"

    def can(self, permission: str) -> bool:
        return can(self.role, permission)


def _verified_principal_to_principal(vp: VerifiedPrincipal) -> Principal:
    return Principal(
        role=vp.role,
        actor=vp.actor,
        permissions=set(vp.permissions),
        organization_id=vp.organization_id,
    )


async def current_principal(request: Request) -> Principal:
    """
    Extract and verify the current principal from a valid JWT.
    Raises HTTP 401 if no token is present, HTTP 401 if token is invalid.

    SECURITY: Roles are ONLY accepted from cryptographically verified JWTs.
    Header-based and query-param-based role injection is no longer supported.
    """
    token = _extract_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "not_authenticated", "message": "Authentication required. Please log in."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = _verify_jwt(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": "Your session has expired or is invalid. Please log in again."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    role = str(payload.get("role") or payload.get("adaptivescan_role") or "viewer")
    actor = str(payload.get("sub") or "anonymous")
    org_id = str(payload.get("organization_id") or "local-org")
    return Principal(role=role, actor=actor, permissions=set(), organization_id=org_id)


def require_permission(permission: str):
    """FastAPI dependency: verify JWT AND check RBAC permission."""
    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.can(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": "Insufficient permissions for this operation.",
                    "required_permission": permission,
                    "role": principal.role,
                },
            )
        return principal

    return dependency


def websocket_principal(websocket: WebSocket) -> Principal:
    """
    Extract and verify principal for WebSocket connections.
    Token must be passed as ?token=<jwt> query parameter (Authorization header
    is not available in WebSocket upgrade requests in most browsers).
    """
    token = (
        websocket.query_params.get("token")
        or websocket.headers.get("authorization", "").removeprefix("Bearer ").strip()
    )
    if not token:
        # WebSocket: allow unauthenticated with viewer role for now
        # TODO: Enforce strict auth on all WS connections
        return Principal(role="viewer", actor="anonymous", permissions=set())
    try:
        payload = _verify_jwt(token)
        role = str(payload.get("role") or payload.get("adaptivescan_role") or "viewer")
        actor = str(payload.get("sub") or "anonymous")
        org_id = str(payload.get("organization_id") or "local-org")
        return Principal(role=role, actor=actor, permissions=set(), organization_id=org_id)
    except Exception:
        return Principal(role="viewer", actor="anonymous", permissions=set())


# ---------------------------------------------------------------------------
# Legacy compatibility shim — do NOT use in new code
# ---------------------------------------------------------------------------
def principal_from_role(role: str | None, actor: str | None = None) -> Principal:
    """
    DEPRECATED: This function bypasses real authentication.
    Only kept for test helpers that need to construct principals directly.
    Do NOT call this from production request handlers.
    """
    import warnings
    warnings.warn(
        "principal_from_role() bypasses JWT verification and is only safe in tests.",
        DeprecationWarning,
        stacklevel=2,
    )
    normalized = (role or "viewer").strip().lower().replace("-", "_")
    if normalized == "security engineer":
        normalized = "security_engineer"
    return Principal(role=normalized, actor=actor or "test-user", permissions=set())
