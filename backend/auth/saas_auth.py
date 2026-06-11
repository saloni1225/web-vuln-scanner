from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone

_log = logging.getLogger(__name__)

from passlib.exc import MissingBackendError
from passlib.hash import argon2, pbkdf2_sha256

from backend.auth.otp_delivery import deliver_otp
from backend.database.db import create_auth_user, create_organization, create_refresh_session, create_workspace, consume_otp_challenge, get_auth_user_by_email, mark_auth_user_login, store_otp_challenge, update_auth_user_password, write_audit_log
from backend.rbac.policy import ROLE_PERMISSIONS, rbac_overview
from backend.config.settings import settings


# ── JWT secret ───────────────────────────────────────────────────────────────
# In an enterprise environment, use a robust 256-bit+ secret.
_RAW_JWT_SECRET = (
    settings.adaptivescan_jwt_secret
    or os.environ.get("SECRET_KEY")
    or ""
)
if not _RAW_JWT_SECRET:
    _FALLBACK = "adaptivescan-local-development-secret"
    warnings.warn(
        "\n  \n  [AdaptiveScan] ⚠️  ADAPTIVESCAN_JWT_SECRET is not set in your environment!\n"
        f"    Using insecure fallback: '{_FALLBACK}'\n"
        "    Set ADAPTIVESCAN_JWT_SECRET=<64 random hex chars> in your .env file before deployment.",
        UserWarning
    )
    _RAW_JWT_SECRET = _FALLBACK

JWT_SECRET: str = _RAW_JWT_SECRET
ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_SECONDS = 900       # 15 minutes
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7   # 7 days (was 14)


@dataclass(frozen=True)
class AuthUser:
    user_id: str
    email: str
    first_name: str
    last_name: str
    company_name: str
    role: str
    organization_id: str
    mfa_required: bool = True


def password_hash(password: str) -> str:
    try:
        return argon2.using(rounds=3, memory_cost=65536, parallelism=2).hash(password)
    except MissingBackendError:
        return pbkdf2_sha256.using(rounds=210_000).hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("$argon2"):
        return argon2.verify(password, stored_hash)
    if stored_hash.startswith("$pbkdf2"):
        return pbkdf2_sha256.verify(password, stored_hash)
    try:
        _, salt, digest = stored_hash.split("$", 2)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 150_000).hex()
    return hmac.compare_digest(candidate, digest)


def seed_founder_user() -> None:
    # Seeding must be environment-gated and strictly forbidden in production.
    if settings.execution_mode == "production" or not settings.enable_founder_seed:
        return

    email = settings.founder_email
    password = settings.founder_password
    if not email or not password:
        _log.warning("founder_seed_skipped", extra={"reason": "missing_credentials"})
        return

    user = get_auth_user_by_email(email)
    if user is not None:
        return

    # User does not exist, seed them
    org = create_organization("Founder Organization", plan="enterprise", actor="system")
    create_workspace(org["org_id"], "Production Workspace", default_allowlist=[], actor="system")
    
    user_id = str(uuid.uuid4())
    create_auth_user(
        user_id=user_id,
        org_id=org["org_id"],
        email=email,
        first_name="Founder",
        last_name="Admin",
        company_name="Founder Organization",
        role="owner",
        password_hash_value=password_hash(password),
        mfa_enabled=False,
    )
    _log.info("founder_seeded", extra={"email": email, "role": "owner"})


def issue_otp(email: str, purpose: str) -> dict[str, object]:
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = int(time.time()) + 600
    challenge = store_otp_challenge(email=email, purpose=purpose, code_hash=_otp_hash(email, purpose, code), expires_at=expires_at)
    challenge_id = str(challenge["challenge_id"])
    write_audit_log("auth.otp.issued", actor=email, target=email, details={"purpose": purpose, "expires_at": expires_at})
    _log.info("otp_generated", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "expires_at": expires_at})
    _log.info("otp_challenge_stored", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "expires_at": expires_at})
    
    try:
        delivery = deliver_otp(email=email, purpose=purpose, code=code, challenge_id=challenge_id, expires_at=expires_at)
        _log.info("otp_send_success", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "provider": delivery.provider})
    except Exception as exc:
        _log.error("otp_send_failure", extra={"email": email, "purpose": purpose, "challenge_id": challenge_id, "error": str(exc)})
        raise

    res = {
        "delivery": "email",
        "delivery_provider": delivery.provider,
        "delivery_destination": delivery.destination,
        "dev_visible": delivery.dev_visible,
        "email": email,
        "purpose": purpose,
        "challenge_id": challenge_id,
        "expires_at": expires_at,
    }
    return res


def verify_otp(email: str, code: str, purpose: str) -> dict[str, object]:
    normalized = code.strip()
    valid = len(normalized) == 6 and normalized.isdigit() and consume_otp_challenge(
        email=email,
        purpose=purpose,
        code_hash=_otp_hash(email, purpose, normalized),
        now=int(time.time()),
    )
    if valid:
        _log.info("otp_verify_success", extra={"email": email, "purpose": purpose})
    else:
        _log.warning("otp_verify_failure", extra={"email": email, "purpose": purpose})
    _log.info("otp_verify_result", extra={"email": email, "purpose": purpose, "valid": valid})
    write_audit_log("auth.otp.verified", actor=email, target=email, details={"purpose": purpose, "valid": valid})
    return {"verified": valid, "email": email, "purpose": purpose}


def create_registration(payload: dict[str, str]) -> dict[str, object]:
    email = payload["work_email"].strip().lower()
    company = payload["company_name"].strip()
    if get_auth_user_by_email(email) is not None:
        return {"registered": False, "reason": "An account already exists for this work email.", "next_step": "login"}
    org = create_organization(company, plan="starter", actor=email)
    workspace = create_workspace(org["org_id"], "Production", default_allowlist=[], actor=email)
    user = create_auth_user(
        user_id=str(uuid.uuid4()),
        org_id=str(org["org_id"]),
        email=email,
        first_name=payload["first_name"].strip(),
        last_name=payload["last_name"].strip(),
        company_name=company,
        role="owner",
        password_hash_value=password_hash(payload["password"]),
        mfa_enabled=True,
    )
    write_audit_log(
        "auth.user.registered",
        actor=email,
        target=str(user["user_id"]),
        details={"organization_id": org["org_id"], "workspace_id": workspace["workspace_id"]},
    )
    return {
        "registered": True,
        "user": user,
        "organization": org,
        "workspace": workspace,
        "verification": issue_otp(email, "email_verification"),
        "next_step": "verify-email",
    }


def issue_tokens(email: str, role: str = "owner", organization_id: str = "local-org", mfa_verified: bool = False) -> dict[str, object]:
    now = int(time.time())
    access_payload = {
        "sub": email,
        "role": role,
        "adaptivescan_role": role,
        "organization_id": organization_id,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
        "mfa_verified": mfa_verified,
    }
    refresh_payload = {
        "sub": email,
        "typ": "refresh",
        "role": role,
        "organization_id": organization_id,
        "iat": now,
        "exp": now + REFRESH_TOKEN_TTL_SECONDS,
        "mfa_verified": mfa_verified,
        "jti": str(uuid.uuid4()),
    }
    access_token = _encode_jwt(access_payload)
    refresh_token = _encode_jwt(refresh_payload)
    user = get_auth_user_by_email(email)
    if user is not None:
        create_refresh_session(
            user_id=str(user["user_id"]),
            refresh_token_hash=hashlib.sha256(refresh_token.encode("utf-8")).hexdigest(),
            expires_at=int(refresh_payload["exp"]),
        )
    return {
        "token_type": "Bearer",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "refresh_expires_in": REFRESH_TOKEN_TTL_SECONDS,
    }


def login_response(email: str, password: str | None = None, passwordless: bool = False) -> dict[str, object]:
    if passwordless:
        return {"requires_otp": True, "otp": issue_otp(email, "passwordless_login")}
    user = get_auth_user_by_email(email)
    if user is None:
        write_audit_log("auth.login.failed", actor=email, target=email, details={"reason": "unknown_user"})
        return {"authenticated": False, "reason": "Invalid email or password."}
    if not password or not verify_password(password, str(user["password_hash"])):
        write_audit_log("auth.login.failed", actor=email, target=email, details={"reason": "bad_password"})
        return {"authenticated": False, "reason": "Invalid email or password."}
    mark_auth_user_login(email)
    write_audit_log("auth.login.succeeded", actor=email, target=str(user["user_id"]), details={"role": user["role"]})

    is_founder = (email.lower() == settings.founder_email.lower()) and (settings.execution_mode != "production")

    # If the user has TOTP configured, enforce TOTP MFA:
    if user.get("totp_secret") and not is_founder:
        return {
            "authenticated": False,
            "requires_mfa": True,
            "mfa": {"methods": ["totp", "backup_code"]},
            "pending_mfa_email": email,
        }

    # Otherwise, if mfa_required or mfa_enabled is true, use email OTP fallback
    mfa_required = bool(user.get("mfa_required") or user.get("mfa_enabled")) and not is_founder

    if mfa_required:
        # SECURITY: Do NOT issue real tokens until MFA step is completed.
        # Return a short-lived MFA challenge; real tokens are issued after OTP verification.
        _log.info("mfa_required_triggered", extra={"email": email})
        return {
            "authenticated": False,
            "requires_mfa": True,
            "mfa": {"methods": ["email_otp", "totp", "backup_code"], "challenge": issue_otp(email, "login_mfa")},
            # pending_mfa_email is used by the verify-otp endpoint to know which user to finalize
            "pending_mfa_email": email,
        }

    # No MFA — issue tokens immediately (mark mfa_verified=True for non-admins and the non-production founder since they don't require MFA)
    mfa_verified = (user["role"] not in ("owner", "admin")) or is_founder
    return {
        "authenticated": True,
        "requires_mfa": False,
        "tokens": issue_tokens(email, role=str(user["role"]), organization_id=str(user["organization_id"]), mfa_verified=mfa_verified),
        "user": {"email": email, "role": str(user["role"]), "first_name": str(user.get("first_name", ""))},
    }


def logout_response(email: str) -> dict[str, object]:
    write_audit_log("auth.logout", actor=email, target=email, details={"session_state": "client_tokens_discarded"})
    return {"logged_out": True, "email": email, "next_step": "login"}


def password_reset_response(email: str, code: str, new_password: str) -> dict[str, object]:
    verified = verify_otp(email, code, "password_reset")["verified"]
    if not verified:
        return {"reset": False, "reason": "Invalid or expired password reset code."}
    updated = update_auth_user_password(email, password_hash(new_password))
    write_audit_log("auth.password_reset.completed", actor=email, target=email, details={"hash_algorithm": "argon2", "updated": updated})
    return {"reset": True, "email": email, "next_step": "login"}


def auth_architecture() -> dict[str, object]:
    return {
        "flows": ["registration", "email_otp_verification", "password_login", "passwordless_otp", "forgot_password", "totp_mfa", "backup_codes", "social_login"],
        "providers": ["google", "github", "microsoft"],
        "token_strategy": {"access_token_ttl_seconds": ACCESS_TOKEN_TTL_SECONDS, "refresh_token_ttl_seconds": REFRESH_TOKEN_TTL_SECONDS, "algorithm": "HS256"},
        "security_controls": ["Argon2 password hashing", "JWT access tokens", "refresh token rotation boundary", "MFA challenges", "audit logging", "rate limiting ready", "CSRF header boundary"],
        "rbac": rbac_overview(),
    }


def onboarding_state() -> dict[str, object]:
    return {
        "steps": [
            {"id": "organization", "title": "Create organization", "status": "complete", "owner": "Founder / CISO"},
            {"id": "domain", "title": "Add primary asset", "status": "ready", "placeholder": "example.com"},
            {"id": "mode", "title": "Choose monitoring cadence", "options": ["Daily exposure monitoring", "Weekly executive review", "On-demand assessment"]},
            {"id": "team", "title": "Invite security and engineering owners", "roles": sorted(ROLE_PERMISSIONS)},
            {"id": "notifications", "title": "Route alerts", "options": ["Email", "Slack", "Webhook", "Jira"]},
            {"id": "launch", "title": "Start continuous monitoring", "status": "ready"},
        ]
    }


def billing_catalog() -> dict[str, object]:
    return {
        "plans": [
            {"name": "Starter", "price": "$99/mo", "monitored_assets": 50, "team_members": 3, "api_access": "limited", "monitoring": "weekly", "support": "community"},
            {"name": "Professional", "price": "$399/mo", "monitored_assets": 500, "team_members": 10, "api_access": "standard", "monitoring": "daily", "support": "business hours"},
            {"name": "Business", "price": "$999/mo", "monitored_assets": 2500, "team_members": 30, "api_access": "advanced", "monitoring": "continuous", "support": "priority"},
            {"name": "Enterprise", "price": "Custom", "monitored_assets": "unlimited", "team_members": "unlimited", "api_access": "enterprise", "monitoring": "continuous", "support": "dedicated"},
        ],
        "billing_ready": ["subscription_id", "usage_metering", "invoice_history", "plan_entitlements", "payment_provider_customer_id"],
    }


def subscription_status() -> dict[str, object]:
    return {
        "plan": "Professional",
        "status": "trialing",
        "trial_days_remaining": 14,
        "usage": {
            "monitored_assets": 128,
            "asset_limit": 500,
            "team_members": 6,
            "team_member_limit": 10,
            "api_calls_this_month": 18420,
        },
        "entitlements": ["daily_monitoring", "executive_reports", "api_access", "mfa", "rbac", "notification_routing"],
        "billing_architecture": {
            "metering": "asset and API usage events",
            "provider_boundary": "payment_provider_customer_id",
            "renewal_workflow": "trial -> active subscription -> invoice lifecycle",
        },
    }


def team_directory() -> dict[str, object]:
    return {
        "members": [
            {"name": "Anmol Singh", "email": "owner@example.com", "role": "owner", "status": "active", "mfa": "enabled"},
            {"name": "AppSec Lead", "email": "appsec@example.com", "role": "admin", "status": "active", "mfa": "enabled"},
            {"name": "Platform Engineer", "email": "platform@example.com", "role": "security_engineer", "status": "invited", "mfa": "pending"},
            {"name": "Executive Viewer", "email": "ciso@example.com", "role": "viewer", "status": "active", "mfa": "enabled"},
        ],
        "roles": [{"role": role, "permissions": sorted(permissions)} for role, permissions in ROLE_PERMISSIONS.items()],
        "invite_flow": ["enter work email", "assign role", "send invite", "enforce MFA on first login"],
    }


def notification_center() -> dict[str, object]:
    return {
        "channels": [
            {"name": "Security email", "type": "email", "status": "connected", "routing": "critical and weekly digest"},
            {"name": "Slack security-alerts", "type": "slack", "status": "ready", "routing": "high and drift alerts"},
            {"name": "Webhook", "type": "webhook", "status": "configured", "routing": "all exposure events"},
            {"name": "Jira", "type": "ticketing", "status": "planned", "routing": "validated findings"},
        ],
        "rules": [
            {"name": "Critical exposure", "condition": "score >= 80 or critical finding", "severity": "critical", "channels": ["email", "slack", "webhook"]},
            {"name": "Asset drift", "condition": "new internet-facing service", "severity": "high", "channels": ["slack", "webhook"]},
            {"name": "Executive digest", "condition": "weekly posture summary", "severity": "info", "channels": ["email"]},
        ],
    }


def monitoring_workflows() -> dict[str, object]:
    return {
        "workflows": [
            {"name": "Continuous external monitoring", "cadence": "daily", "scope": "owned domains and APIs", "status": "active"},
            {"name": "New asset discovery", "cadence": "hourly", "scope": "DNS and certificate drift", "status": "ready"},
            {"name": "Executive reporting", "cadence": "weekly", "scope": "exposure score and top remediation", "status": "active"},
            {"name": "Finding retest", "cadence": "on lifecycle change", "scope": "assigned findings", "status": "ready"},
        ],
        "operating_model": ["organization", "assets", "monitoring", "exposure", "findings", "reports"],
    }


def trust_center() -> dict[str, object]:
    return {
        "security": ["MFA enforcement", "Role-based access control", "Audit logging", "Scoped scan authorization", "Credential isolation"],
        "compliance": ["SOC 2 readiness", "ISO 27001 control mapping", "OWASP evidence exports", "PCI evidence support"],
        "privacy": ["Tenant data isolation", "Least-privilege API tokens", "Report artifact retention controls"],
        "status": "Trust center content ready for customer-facing publication",
    }


def _encode_jwt(payload: dict[str, object]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64_json(header)}.{_b64_json(payload)}"
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')}"


def _b64_json(value: dict[str, object]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _otp_hash(email: str, purpose: str, code: str) -> str:
    return hashlib.sha256(f"{email.lower()}:{purpose}:{code}:{JWT_SECRET}".encode("utf-8")).hexdigest()


def enroll_mfa(email: str) -> dict[str, object]:
    import pyotp
    from backend.database.db import update_user_mfa
    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="AdaptiveScan")
    # Store TOTP secret in DB but keep mfa_enabled = False until verified
    update_user_mfa(email, totp_secret, recovery_codes="", mfa_enabled=False)
    write_audit_log("auth.mfa.enrollment.started", actor=email, target=email, details={})
    return {"totp_secret": totp_secret, "provisioning_uri": provisioning_uri}


def verify_mfa(email: str, code: str) -> dict[str, object]:
    import pyotp
    import secrets
    from backend.database.db import get_auth_user_by_email, update_user_mfa
    user = get_auth_user_by_email(email)
    if not user or not user.get("totp_secret"):
        return {"verified": False, "reason": "MFA enrollment not initialized."}
    
    totp = pyotp.TOTP(str(user["totp_secret"]))
    if not totp.verify(code.strip(), valid_window=1):
        write_audit_log("auth.mfa.verification.failed", actor=email, target=email, details={"reason": "invalid_code"})
        return {"verified": False, "reason": "Invalid TOTP code."}

    # Generate 8 recovery codes formatted as xxxx-xxxx
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(8)]
    update_user_mfa(email, str(user["totp_secret"]), recovery_codes=",".join(codes), mfa_enabled=True)
    write_audit_log("auth.mfa.enabled", actor=email, target=email, details={"method": "totp"})
    return {"verified": True, "recovery_codes": codes}


def verify_mfa_login(email: str, code: str) -> dict[str, object]:
    import pyotp
    from backend.database.db import get_auth_user_by_email, update_user_mfa, mark_auth_user_login
    user = get_auth_user_by_email(email)
    if not user or not user.get("totp_secret"):
        return {"authenticated": False, "reason": "MFA is not configured for this user."}

    # Verify TOTP code
    totp = pyotp.TOTP(str(user["totp_secret"]))
    if totp.verify(code.strip(), valid_window=1):
        mark_auth_user_login(email)
        write_audit_log("auth.mfa.login.succeeded", actor=email, target=str(user["user_id"]), details={"method": "totp"})
        tokens = issue_tokens(email, role=str(user["role"]), organization_id=str(user["organization_id"]), mfa_verified=True)
        return {
            "authenticated": True,
            "tokens": tokens,
            "user": {"email": email, "role": str(user["role"]), "first_name": str(user.get("first_name", ""))},
        }

    # Verify recovery code
    recovery_codes_str = user.get("recovery_codes", "")
    if recovery_codes_str:
        codes_list = [c.strip() for c in recovery_codes_str.split(",") if c.strip()]
        if code.strip() in codes_list:
            codes_list.remove(code.strip())
            update_user_mfa(email, str(user["totp_secret"]), recovery_codes=",".join(codes_list), mfa_enabled=True)
            mark_auth_user_login(email)
            write_audit_log("auth.mfa.login.succeeded", actor=email, target=str(user["user_id"]), details={"method": "recovery_code"})
            tokens = issue_tokens(email, role=str(user["role"]), organization_id=str(user["organization_id"]), mfa_verified=True)
            return {
                "authenticated": True,
                "tokens": tokens,
                "user": {"email": email, "role": str(user["role"]), "first_name": str(user.get("first_name", ""))},
            }

    write_audit_log("auth.mfa.login.failed", actor=email, target=str(user["user_id"]), details={"reason": "invalid_code"})
    return {"authenticated": False, "reason": "Invalid TOTP or recovery code."}
