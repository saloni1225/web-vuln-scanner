from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from threading import Lock

from backend.config.settings import settings

logger = logging.getLogger(__name__)


class OtpDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class OtpDeliveryResult:
    provider: str
    delivered: bool
    destination: str
    dev_visible: bool = False


_DEV_MAILBOX: list[dict[str, object]] = []
_MAILBOX_LOCK = Lock()


def deliver_otp(*, email: str, purpose: str, code: str, challenge_id: str, expires_at: int) -> OtpDeliveryResult:
    provider = settings.otp_delivery_provider.lower().strip()
    logger.info(
        "otp_send_attempted",
        extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": provider},
    )
    if provider in {"dev", "local", "mailbox"}:
        _capture_dev_otp(email=email, purpose=purpose, code=code, challenge_id=challenge_id, expires_at=expires_at)
        logger.info(f"otp_send_succeeded - email: {email}, purpose: {purpose}, code: {code}", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": "dev"})
        return OtpDeliveryResult(provider="dev", delivered=True, destination="dev_mailbox", dev_visible=True)
    if provider == "console":
        if settings.execution_mode == "production":
            raise OtpDeliveryError("Console OTP delivery is not allowed in production.")
        logger.warning(
            f"otp_console_delivery - email: {email}, purpose: {purpose}, code: {code}",
            extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "otp": code},
        )
        return OtpDeliveryResult(provider="console", delivered=True, destination="application_logs", dev_visible=True)
    if provider == "smtp":
        _send_smtp(email=email, purpose=purpose, code=code, challenge_id=challenge_id, expires_at=expires_at)
        logger.info("otp_send_succeeded", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": "smtp"})
        return OtpDeliveryResult(provider="smtp", delivered=True, destination=email)
    if provider == "disabled":
        logger.error("otp_send_failed", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": provider, "reason": "disabled"})
        raise OtpDeliveryError("OTP delivery is disabled.")
    logger.error("otp_send_failed", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": provider, "reason": "unsupported_provider"})
    raise OtpDeliveryError(f"Unsupported OTP delivery provider: {provider}")


def dev_mailbox() -> dict[str, object]:
    if settings.execution_mode not in {"local-dev", "staging", "test"} or not settings.expose_dev_otp:
        return {"enabled": False, "messages": []}
    with _MAILBOX_LOCK:
        return {"enabled": True, "messages": list(reversed(_DEV_MAILBOX[-20:]))}


def clear_dev_mailbox() -> None:
    with _MAILBOX_LOCK:
        _DEV_MAILBOX.clear()


def _capture_dev_otp(*, email: str, purpose: str, code: str, challenge_id: str, expires_at: int) -> None:
    if settings.execution_mode not in {"local-dev", "staging", "test"}:
        raise OtpDeliveryError("Dev OTP mailbox is not available in production.")
    with _MAILBOX_LOCK:
        _DEV_MAILBOX.append({
            "email": email,
            "purpose": purpose,
            "code": code,
            "challenge_id": challenge_id,
            "expires_at": expires_at,
            "provider": "dev",
        })


def _send_smtp(*, email: str, purpose: str, code: str, challenge_id: str, expires_at: int) -> None:
    missing = []
    if not settings.smtp_host:
        missing.append("SMTP_HOST")
    if not settings.otp_email_from:
        missing.append("OTP_EMAIL_FROM")
    if missing:
        logger.error("otp_send_failed", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": "smtp", "missing": missing})
        raise OtpDeliveryError(f"Missing SMTP configuration: {', '.join(missing)}")

    message = EmailMessage()
    message["From"] = settings.otp_email_from
    message["To"] = email
    message["Subject"] = "Your AdaptiveScan verification code"
    message.set_content(
        f"Your AdaptiveScan verification code is {code}.\n\n"
        f"Purpose: {purpose}\nChallenge: {challenge_id}\nExpires at: {expires_at}\n\n"
        "If you did not request this code, you can ignore this email."
    )
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_use_tls:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
    except Exception as exc:
        logger.error("otp_send_failed", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": "smtp", "reason": type(exc).__name__})
        raise OtpDeliveryError("OTP email delivery failed.") from exc
