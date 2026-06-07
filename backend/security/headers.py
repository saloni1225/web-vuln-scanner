"""
AdaptiveScan Security Headers Middleware
=========================================
Adds comprehensive, production-grade HTTP security headers to every response.
Replaces the basic secure_headers middleware in app.py.
"""
from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# Nonce generation would be needed for script-src 'nonce-...' in production.
# For localhost dev, we keep 'unsafe-inline' for Vite HMR compatibility.

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "   # Relax for Vite HMR dev
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data: blob: https:; "
    "connect-src 'self' http://127.0.0.1:8000 ws://127.0.0.1:8000 "
    "http://localhost:8000 ws://localhost:8000; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none';"
)

_PERMISSIONS_POLICY = (
    "camera=(), "
    "microphone=(), "
    "geolocation=(), "
    "payment=(), "
    "usb=(), "
    "magnetometer=(), "
    "gyroscope=(), "
    "accelerometer=()"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Sets the full suite of recommended security headers on every HTTP response.
    Applied AFTER the response is generated so headers from route handlers
    are not overwritten unless we explicitly want to override.
    """

    def __init__(self, app: ASGIApp, hsts: bool = False) -> None:
        super().__init__(app)
        self._hsts = hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        h = response.headers

        # Prevent MIME sniffing
        h["X-Content-Type-Options"] = "nosniff"

        # Clickjacking protection
        h["X-Frame-Options"] = "DENY"

        # Disable legacy XSS filter (modern browsers ignore it, old IE respected it)
        h["X-XSS-Protection"] = "0"

        # Referrer policy
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Feature / permissions policy
        h["Permissions-Policy"] = _PERMISSIONS_POLICY

        # Content Security Policy
        h.setdefault("Content-Security-Policy", _CSP)

        # Cache control for API responses
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            h["Pragma"] = "no-cache"
            h["Expires"] = "0"

        # HSTS — only set when serving over HTTPS
        if self._hsts:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Hide server identity
        h["Server"] = "AdaptiveScan"

        # Cross-Origin policies (tighten resource isolation)
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Embedder-Policy"] = "require-corp"
        h["Cross-Origin-Resource-Policy"] = "same-origin"

        return response
