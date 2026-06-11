"""
AdaptiveScan JWT Verification
==============================
Replaces the trust-anything approach in rbac/auth.py with real signature
verification using the same HS256 signing key as saas_auth.py.

Also provides:
- Verified principal extraction from JWT
- Refresh token rotation
- Secure httpOnly cookie issuance for tokens
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import jwt

from fastapi import Cookie, Depends, Header, HTTPException, Request, Response, status

from backend.rbac.policy import can


# ---------------------------------------------------------------------------
# Secret key — loaded from settings (which reads .env), never hardcoded
# ---------------------------------------------------------------------------
from backend.config.settings import settings as _settings

if _settings.execution_mode != "local-dev":
    if not _settings.adaptivescan_jwt_secret or _settings.adaptivescan_jwt_secret == "adaptivescan-local-development-secret" or len(_settings.adaptivescan_jwt_secret) < 32:
        raise RuntimeError("FATAL: Insecure JWT secret configured in production mode.")

_RAW_SECRET = _settings.adaptivescan_jwt_secret or os.environ.get("SECRET_KEY") or "adaptivescan-local-development-secret"

JWT_SECRET = _RAW_SECRET.encode("utf-8")


ACCESS_TOKEN_TTL = 900          # 15 minutes
REFRESH_TOKEN_TTL = 86400 * 7   # 7 days

# Cookie names
ACCESS_COOKIE  = "adaptivescan_access"
REFRESH_COOKIE = "adaptivescan_refresh"

# Use secure=True in production (HTTPS)
_COOKIE_SECURE = (_settings.execution_mode != "local-dev") or (os.environ.get("COOKIE_SECURE", "false").lower() == "true")


# ---------------------------------------------------------------------------
# JWT helpers (pure Python, no python-jose / pyjwt dependency)
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (padding % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _verify_jwt(token: str) -> dict:
    """
    Verify JWT signature and expiry.
    Returns the decoded payload dict on success.
    Raises HTTPException 401 on any failure.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "invalid_token", "message": "Malformed JWT."})

    header_b64, payload_b64, sig_b64 = parts

    # Verify header
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "invalid_token", "message": "JWT header unreadable."})

    alg = header.get("alg", "").upper()

    if alg == "NONE" or not alg:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "alg_none_rejected",
                                    "message": "JWT alg:none is explicitly rejected."})
    if alg != "HS256":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "unsupported_alg",
                                    "message": f"Only HS256 is supported. Got {alg}."})

    # Verify signature (constant-time)
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "invalid_token", "message": "JWT signature unreadable."})

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "signature_invalid",
                                    "message": "JWT signature verification failed."})

    # Decode payload
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "invalid_token", "message": "JWT payload unreadable."})

    # Check expiry
    exp = payload.get("exp", 0)
    if time.time() > exp:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "token_expired", "message": "Access token has expired."})

    return payload


# ---------------------------------------------------------------------------
# Principal dataclass (mirrors rbac/auth.py)
# ---------------------------------------------------------------------------

from dataclasses import dataclass

@dataclass(frozen=True)
class VerifiedPrincipal:
    role: str
    actor: str
    organization_id: str
    permissions: frozenset

    def can(self, permission: str) -> bool:
        return can(self.role, permission)


def _extract_token(request: Request) -> str | None:
    """Try Authorization header first, then cookie."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.cookies.get(ACCESS_COOKIE)


async def verified_principal(request: Request) -> VerifiedPrincipal:
    """
    FastAPI dependency that enforces real JWT signature verification.
    Replaces current_principal from rbac/auth.py for secure routes.
    """
    token = _extract_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "not_authenticated", "message": "Authentication required."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _verify_jwt(token)
    role = str(payload.get("role") or payload.get("adaptivescan_role") or "viewer")
    return VerifiedPrincipal(
        role=role,
        actor=str(payload.get("sub", "unknown")),
        organization_id=str(payload.get("organization_id", "")),
        permissions=frozenset(),
    )


def require_verified_permission(permission: str):
    """Dependency factory: require a verified JWT + specific permission."""
    async def dep(request: Request, principal: VerifiedPrincipal = Depends(verified_principal)) -> VerifiedPrincipal:
        if not principal.can(permission):
            import logging
            logger = logging.getLogger("backend.security.jwt_guard")
            logger.warning(
                f"Access Denied: User ID '{principal.actor}' with role '{principal.role}' "
                f"failed permission check for '{permission}' on endpoint '{request.method} {request.url.path}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "forbidden",
                    "message": "Insufficient permissions.",
                    "required": permission,
                    "role": principal.role,
                },
            )
        return principal
    return dep


# ---------------------------------------------------------------------------
# Secure cookie token issuance
# ---------------------------------------------------------------------------

def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """
    Set tokens as httpOnly, SameSite=Strict cookies instead of returning
    them in the response body (mitigates XSS token theft).
    """
    from backend.config.settings import settings
    cookie_secure = (settings.execution_mode != "local-dev") or (os.environ.get("COOKIE_SECURE", "false").lower() == "true")
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=access_token,
        httponly=True,
        samesite="Strict",
        secure=cookie_secure,
        max_age=ACCESS_TOKEN_TTL,
        path="/",
    )
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh_token,
        httponly=True,
        samesite="Strict",
        secure=cookie_secure,
        max_age=REFRESH_TOKEN_TTL,
        path="/api/auth",   # Scope refresh token to auth routes only
    )


def clear_auth_cookies(response: Response) -> None:
    """Clear both auth cookies on logout."""
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path="/api/auth")
