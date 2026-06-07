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


def issue_otp(email: str, purpose: str) -> dict[str, object]:
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = int(time.time()) + 600
    challenge = store_otp_challenge(email=email, purpose=purpose, code_hash=_otp_hash(email, purpose, code), expires_at=expires_at)
    write_audit_log("auth.otp.issued", actor=email, target=email, details={"purpose": purpose, "expires_at": expires_at})
    return {"delivery": "email", "email": email, "purpose": purpose, "challenge_id": challenge["challenge_id"], "expires_at": expires_at, "dev_code": code}


def verify_otp(email: str, code: str, purpose: str) -> dict[str, object]:
    normalized = code.strip()
    valid = len(normalized) == 6 and normalized.isdigit() and consume_otp_challenge(
        email=email,
        purpose=purpose,
        code_hash=_otp_hash(email, purpose, normalized),
        now=int(time.time()),
    )
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


def issue_tokens(email: str, role: str = "owner", organization_id: str = "local-org") -> dict[str, object]:
    now = int(time.time())
    access_payload = {
        "sub": email,
        "role": role,
        "adaptivescan_role": role,
        "organization_id": organization_id,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    refresh_payload = {
        "sub": email,
        "typ": "refresh",
        "role": role,
        "organization_id": organization_id,
        "iat": now,
        "exp": now + REFRESH_TOKEN_TTL_SECONDS,
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
    return {
        "authenticated": True,
        "requires_mfa": bool(user["mfa_required"]),
        "mfa": {"methods": ["email_otp", "totp", "backup_code"], "challenge": issue_otp(email, "login_mfa")},
        "tokens": issue_tokens(email, role=str(user["role"]), organization_id=str(user["organization_id"])),
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
