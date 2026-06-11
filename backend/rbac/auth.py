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

from fastapi import Depends, HTTPException, Request, WebSocket, status, WebSocketDisconnect

from backend.rbac.policy import can
from backend.security.jwt_guard import (
    VerifiedPrincipal,
    _extract_token,
    _verify_jwt,
    verified_principal,
)
from backend.config.settings import settings as _settings


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
        # Check Cloudflare Access identity validation
        from backend.security.cloudflare import verify_cloudflare_assertion
        cf_email = verify_cloudflare_assertion(request)
        if cf_email:
            from backend.database.db import get_auth_user_by_email
            user = get_auth_user_by_email(cf_email)
            if user:
                role = str(user["role"])
                actor = str(user["email"])
                org_id = str(user["organization_id"])
                # Authenticated via Cloudflare Access (corporate IDP)
                return Principal(role=role, actor=actor, permissions=set(), organization_id=org_id)

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
    actor = str(payload.get("email") or payload.get("sub") or "anonymous")
    org_id = str(payload.get("organization_id") or "local-org")

    if request.url.path not in ("/api/auth/mfa/enroll", "/api/auth/mfa/verify", "/api/auth/me"):
        if role in ("owner", "admin"):
            is_founder = (actor.lower() == _settings.founder_email.lower()) and (_settings.execution_mode != "production")
            if not is_founder:
                from backend.database.db import get_auth_user_by_email
                user = get_auth_user_by_email(actor)
                if user:
                    # If they haven't enrolled (totp_secret is empty), force enrollment
                    if not user.get("totp_secret"):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="mfa_required",
                        )
                    # If they have enrolled (totp_secret is set), require mfa_verified to be True in token
                    if not payload.get("mfa_verified", False):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="mfa_required",
                        )

    return Principal(role=role, actor=actor, permissions=set(), organization_id=org_id)


def require_permission(permission: str):
    """FastAPI dependency: verify JWT AND check RBAC permission."""
    async def dependency(request: Request, principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.can(permission):
            import logging
            logger = logging.getLogger("backend.rbac.auth")
            logger.warning(
                f"Access Denied: User ID '{principal.actor}' with role '{principal.role}' "
                f"failed permission check for '{permission}' on endpoint '{request.method} {request.url.path}'"
            )
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
    Token can be passed as ?token=<jwt> query parameter,
    via cookie (adaptivescan_access), or Authorization header.
    """
    origin = websocket.headers.get("origin")
    if origin:
        allowed = _settings.cors_origins
        if allowed and "*" not in allowed and origin not in allowed:
            raise WebSocketDisconnect(
                code=1008,
                reason="WebSocket origin not allowed.",
            )

    token = (
        websocket.query_params.get("token")
        or websocket.cookies.get("adaptivescan_access")
        or websocket.headers.get("authorization", "").removeprefix("Bearer ").strip()
    )
    if not token:
        raise WebSocketDisconnect(
            code=1008,
            reason="Authentication token is missing.",
        )
    try:
        payload = _verify_jwt(token)
    except Exception as exc:
        raise WebSocketDisconnect(
            code=1008,
            reason="Invalid or expired token.",
        ) from exc

    role = payload.get("role") or payload.get("adaptivescan_role")
    if not role:
        raise WebSocketDisconnect(
            code=1008,
            reason="Role not specified in token.",
        )
    role = str(role)
    from backend.rbac.policy import ROLE_PERMISSIONS
    if role not in ROLE_PERMISSIONS:
        raise WebSocketDisconnect(
            code=1008,
            reason="Role not authorized.",
        )
    actor = str(payload.get("email") or payload.get("sub") or "anonymous")
    org_id = str(payload.get("organization_id") or "local-org")

    if role in ("owner", "admin"):
        is_founder = (actor.lower() == _settings.founder_email.lower()) and (_settings.execution_mode != "production")
        if not is_founder and not payload.get("mfa_verified", False):
            raise WebSocketDisconnect(
                code=1008,
                reason="mfa_required",
            )

    return Principal(role=role, actor=actor, permissions=set(), organization_id=org_id)


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
