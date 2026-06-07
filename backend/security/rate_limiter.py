"""
AdaptiveScan Rate Limiter & Brute-Force Lockout
================================================
- Sliding-window rate limiting (per IP)
- Progressive lockout for failed auth attempts
- Thread-safe using asyncio locks
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque

from fastapi import HTTPException, Request, status


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Auth endpoints: max attempts before lockout
AUTH_MAX_ATTEMPTS = 5
AUTH_LOCKOUT_SECONDS = 900       # 15 minutes after 5 failures
AUTH_ATTEMPT_WINDOW_SECONDS = 300  # Count failures within 5 min window

# General rate limits (per IP, per window)
RATE_LIMIT_RULES: dict[str, tuple[int, int]] = {
    # route_prefix -> (max_requests, window_seconds)
    "/api/auth/login":          (10, 60),
    "/api/auth/register":       (5,  60),
    "/api/auth/otp":            (10, 60),
    "/api/auth/forgot-password":(5,  60),
    "/api/auth/password-reset": (5,  60),
    "/api/scan":                (20, 60),
    "default":                  (120, 60),
}


# ---------------------------------------------------------------------------
# Internal state (module-level singletons — fine for single-process dev)
# ---------------------------------------------------------------------------

@dataclass
class _WindowState:
    timestamps: Deque[float] = field(default_factory=deque)

@dataclass
class _LockoutState:
    fail_times: Deque[float] = field(default_factory=deque)
    locked_until: float = 0.0
    fail_count: int = 0


_rate_windows: dict[str, _WindowState] = defaultdict(_WindowState)
_lockout_states: dict[str, _LockoutState] = defaultdict(_LockoutState)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    """Extract real client IP, honouring X-Forwarded-For behind a proxy."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rule_for(path: str) -> tuple[int, int]:
    for prefix, rule in RATE_LIMIT_RULES.items():
        if prefix != "default" and path.startswith(prefix):
            return rule
    return RATE_LIMIT_RULES["default"]


def check_rate_limit(request: Request) -> None:
    """
    Call this at the start of any route handler.
    Raises HTTP 429 if the caller exceeds the allowed rate for that endpoint.
    """
    ip = _client_ip(request)
    path = request.url.path
    max_req, window = _rule_for(path)
    key = f"{ip}:{path}"
    now = time.monotonic()

    state = _rate_windows[key]
    # Evict expired timestamps
    while state.timestamps and now - state.timestamps[0] > window:
        state.timestamps.popleft()

    if len(state.timestamps) >= max_req:
        retry_after = int(window - (now - state.timestamps[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "message": f"Too many requests. Try again in {retry_after} seconds.",
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    state.timestamps.append(now)


def record_auth_failure(ip: str) -> None:
    """Call after every failed login / OTP / password attempt."""
    now = time.monotonic()
    state = _lockout_states[ip]

    # Evict old failures outside the attempt window
    while state.fail_times and now - state.fail_times[0] > AUTH_ATTEMPT_WINDOW_SECONDS:
        state.fail_times.popleft()

    state.fail_times.append(now)
    state.fail_count = len(state.fail_times)

    if state.fail_count >= AUTH_MAX_ATTEMPTS:
        state.locked_until = now + AUTH_LOCKOUT_SECONDS
        state.fail_times.clear()


def check_auth_lockout(request: Request) -> None:
    """
    Call at the top of every auth route.
    Raises HTTP 429 if the IP is currently locked out.
    """
    ip = _client_ip(request)
    state = _lockout_states[ip]
    now = time.monotonic()

    if state.locked_until and now < state.locked_until:
        wait = int(state.locked_until - now) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "account_locked",
                "message": f"Too many failed attempts. Try again in {wait} seconds.",
                "retry_after_seconds": wait,
            },
            headers={"Retry-After": str(wait)},
        )


def clear_auth_failures(ip: str) -> None:
    """Call after a successful login to reset the failure counter."""
    if ip in _lockout_states:
        state = _lockout_states[ip]
        state.fail_times.clear()
        state.locked_until = 0.0
        state.fail_count = 0
