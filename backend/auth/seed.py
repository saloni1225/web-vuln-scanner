from __future__ import annotations

import logging
import uuid

from backend.auth.saas_auth import password_hash
from backend.config.settings import settings
from backend.database.db import create_auth_user, create_organization, create_workspace, get_auth_user_by_email

logger = logging.getLogger(__name__)


def seed_founder_user() -> dict[str, object]:
    if not settings.enable_founder_seed:
        return {"seeded": False, "reason": "disabled"}
    if settings.execution_mode == "production":
        return {"seeded": False, "reason": "production_disabled"}
    email = settings.founder_email.strip().lower()
    password = settings.founder_password
    if not email or not password:
        return {"seeded": False, "reason": "missing_credentials"}
    existing = get_auth_user_by_email(email)
    if existing:
        return {"seeded": False, "reason": "already_exists", "email": email, "role": existing.get("role")}

    org = create_organization("AdaptiveScan Founder", plan="enterprise", actor="system")
    create_workspace(org["org_id"], "Founder Workspace", default_allowlist=[], actor="system")
    user = create_auth_user(
        user_id=str(uuid.uuid4()),
        org_id=str(org["org_id"]),
        email=email,
        first_name="Founder",
        last_name="Admin",
        company_name="AdaptiveScan",
        role="owner",
        password_hash_value=password_hash(password),
        mfa_enabled=False,
    )
    logger.info("founder_seed_created", extra={"email": email, "organization_id": org["org_id"], "role": "owner"})
    return {"seeded": True, "email": email, "role": "owner", "organization_id": org["org_id"], "user_id": user["user_id"]}
