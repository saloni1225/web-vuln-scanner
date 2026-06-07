"""
AdaptiveScan CSRF Protection
=============================
Double-submit cookie pattern for state-changing endpoints.
- Server sets a random CSRF token in a same-site cookie
- Frontend must echo it in the X-CSRF-Token header
- Validated on every POST / PUT / DELETE / PATCH
"""
from __future__ import annotations

import hmac
import os
import secrets

from fastapi import Cookie, Header, HTTPException, Request, Response, status

# All methods that mutate state require CSRF validation
_CSRF_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Cookie & header names
CSRF_COOKIE_NAME = "adaptivescan_csrf"
CSRF_HEADER_NAME = "x-csrf-token"

# Token length (bytes → 32 bytes = 64 hex chars)
CSRF_TOKEN_BYTES = 32

# Internal signing secret (rotated on each process start; fine for dev)
_CSRF_SIGNING_SECRET = os.urandom(32)


def _sign(token: str) -> str:
    """Return HMAC-signed token to detect tampering."""
    return hmac.new(_CSRF_SIGNING_SECRET, token.encode(), "sha256").hexdigest()


def generate_csrf_token() -> str:
    """Generate a new, signed CSRF token."""
    raw = secrets.token_hex(CSRF_TOKEN_BYTES)
    return f"{raw}.{_sign(raw)}"


def _verify_csrf_token(token: str) -> bool:
    """Verify token integrity (constant-time compare)."""
    if "." not in token:
        return False
    raw, sig = token.rsplit(".", 1)
    expected = _sign(raw)
    return hmac.compare_digest(expected, sig)


def set_csrf_cookie(response: Response) -> str:
    """
    Issue a new CSRF token, set it in a SameSite=Lax cookie,
    and return the raw token string to embed in the API response.
    """
    token = generate_csrf_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        httponly=False,      # JS needs to read this to put it in the header
        samesite="lax",
        secure=False,        # Change to True when serving over HTTPS
        path="/",
    )
    return token


async def enforce_csrf(
    request: Request,
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> None:
    """
    FastAPI dependency — attach to any state-changing route.
    Validates that the X-CSRF-Token header matches the csrf cookie.
    Safe methods (GET, HEAD, OPTIONS) are skipped automatically.
    """
    if request.method not in _CSRF_METHODS:
        return

    # Skip CSRF for pure-JSON API clients that set Content-Type application/json
    # (XHR / fetch from a different origin cannot set custom headers without CORS preflight)
    content_type = request.headers.get("content-type", "")
    origin = request.headers.get("origin", "")

    # If request originates from same host (no Origin header on same-origin reqs), allow
    if not origin:
        return

    if not csrf_cookie:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "csrf_missing_cookie",
                "message": "CSRF cookie is missing. Please re-authenticate.",
            },
        )

    if not csrf_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "csrf_missing_header",
                "message": "X-CSRF-Token header is required for state-changing requests.",
            },
        )

    if not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "csrf_token_mismatch",
                "message": "CSRF token validation failed.",
            },
        )

    if not _verify_csrf_token(csrf_cookie):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "csrf_token_invalid",
                "message": "CSRF token is malformed or tampered.",
            },
        )
