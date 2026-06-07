"""
AdaptiveScan Input Validation & Sanitization
=============================================
- Password strength enforcement
- Email normalisation and validation
- Request body size limiting
- SQL injection / XSS pattern detection in free-text fields
"""
from __future__ import annotations

import re

from fastapi import HTTPException, Request, status


# ---------------------------------------------------------------------------
# Password strength
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH = 12
_PASSWORD_REQUIREMENTS = [
    (r"[A-Z]", "at least one uppercase letter"),
    (r"[a-z]", "at least one lowercase letter"),
    (r"[0-9]", "at least one digit"),
    (r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]", "at least one special character"),
]

# Commonly breached passwords — partial list, extend as needed
_COMMON_PASSWORDS = {
    "password", "password1", "123456789", "12345678", "qwerty123",
    "iloveyou", "admin123", "letmein1", "monkey123", "dragon123",
}


def validate_password_strength(password: str) -> None:
    """
    Enforce strong password requirements.
    Raises HTTP 400 with a descriptive message if the password is weak.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "weak_password",
                "message": f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.",
            },
        )

    if password.lower() in _COMMON_PASSWORDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "weak_password",
                "message": "This password is too common. Please choose a stronger password.",
            },
        )

    missing = []
    for pattern, description in _PASSWORD_REQUIREMENTS:
        if not re.search(pattern, password):
            missing.append(description)

    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "weak_password",
                "message": f"Password must contain: {', '.join(missing)}.",
            },
        )


# ---------------------------------------------------------------------------
# Email validation
# ---------------------------------------------------------------------------

_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "10minutemail.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "spam4.me", "trashmail.com", "fakeinbox.com",
}


def validate_email(email: str) -> str:
    """Validate and normalise an email address. Returns the lowercased email."""
    if not email or not isinstance(email, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_email", "message": "A valid email address is required."},
        )

    email = email.strip().lower()

    if len(email) > 254:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_email", "message": "Email address is too long."},
        )

    if not _EMAIL_PATTERN.match(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_email", "message": "Email address format is invalid."},
        )

    domain = email.split("@")[1]
    if domain in _DISPOSABLE_DOMAINS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "disposable_email",
                "message": "Disposable email addresses are not permitted.",
            },
        )

    return email


# ---------------------------------------------------------------------------
# Request body size limit
# ---------------------------------------------------------------------------

MAX_BODY_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


async def limit_request_size(request: Request) -> None:
    """
    FastAPI dependency — reject requests with bodies larger than MAX_BODY_SIZE_BYTES.
    Attach as Depends() to upload or scan endpoints.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
            if length > MAX_BODY_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail={
                        "error": "request_too_large",
                        "message": f"Request body must not exceed {MAX_BODY_SIZE_BYTES // 1024 // 1024} MB.",
                    },
                )
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# Basic injection pattern detection (defense-in-depth, not a WAF replacement)
# ---------------------------------------------------------------------------

_SQL_PATTERNS = re.compile(
    r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b"
    r"|\bEXEC\b|\bEXECUTE\b|--|;|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)",
    re.IGNORECASE,
)

_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|on\w+\s*=|<iframe|<object|<embed|vbscript:)",
    re.IGNORECASE,
)


def detect_injection(value: str, field_name: str = "input") -> None:
    """
    Raise HTTP 400 if obvious SQL injection or XSS patterns are detected.
    This is a defence-in-depth check — SQLAlchemy parameterisation is the
    primary protection against SQL injection.
    """
    if _SQL_PATTERNS.search(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_input",
                "message": f"Field '{field_name}' contains disallowed characters or patterns.",
            },
        )
    if _XSS_PATTERNS.search(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_input",
                "message": f"Field '{field_name}' contains disallowed HTML content.",
            },
        )
