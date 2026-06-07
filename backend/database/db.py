import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.config.settings import ROOT_DIR


DB_PATH = ROOT_DIR / "scanner.db"


def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                raw_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_lifecycle (
                scan_id TEXT NOT NULL,
                finding_index INTEGER NOT NULL,
                state TEXT NOT NULL,
                owner TEXT NOT NULL,
                sla_due_at TEXT NOT NULL,
                comments_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (scan_id, finding_index)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                org_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                plan TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                workspace_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                default_allowlist_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS team_members (
                member_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(workspace_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_users (
                user_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                company_name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_enabled INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_otp_challenges (
                challenge_id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                purpose TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_refresh_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                refresh_token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES auth_users(user_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_started ON scans(target_url, started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_workspaces_org ON workspaces(org_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_workspace ON api_keys(workspace_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_otp_email_purpose ON auth_otp_challenges(email, purpose, expires_at)")


def save_scan(scan: dict[str, object]) -> None:
    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
            (scan_id, target_url, started_at, finished_at, findings_count, raw_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan["scan_id"],
                scan["target_url"],
                scan["started_at"],
                scan["finished_at"],
                len(scan.get("findings", [])),
                json.dumps(scan),
            ),
        )


def list_scans() -> list[dict[str, object]]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT scan_id, target_url, started_at, finished_at, findings_count, raw_json FROM scans ORDER BY started_at DESC"
        ).fetchall()
    reports: list[dict[str, object]] = []
    for row in rows:
        scan = json.loads(row[5])
        summary = scan.get("summary", {}) if isinstance(scan, dict) else {}
        scan_options = scan.get("scan_options", {}) if isinstance(scan, dict) else {}
        risk_gate = scan.get("risk_gate", {}) if isinstance(scan, dict) else {}
        findings = scan.get("findings", []) if isinstance(scan, dict) else []
        confirmed_high = int(summary.get("confirmed_high_severity_count") if summary.get("confirmed_high_severity_count") is not None else sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "high" and f.get("validation_state") in ("confirmed", "validated")))
        confirmed_medium = int(summary.get("confirmed_medium_severity_count") if summary.get("confirmed_medium_severity_count") is not None else sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "medium" and f.get("validation_state") in ("confirmed", "validated")))
        confirmed_low = int(summary.get("confirmed_low_severity_count") if summary.get("confirmed_low_severity_count") is not None else sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "low" and f.get("validation_state") in ("confirmed", "validated")))

        reports.append({
            "scan_id": row[0],
            "target_url": row[1],
            "started_at": row[2],
            "finished_at": row[3],
            "findings_count": row[4],
            "high_severity_count": int(summary.get("high_severity_count", 0) or 0) if isinstance(summary, dict) else 0,
            "medium_severity_count": int(summary.get("medium_severity_count", 0) or 0) if isinstance(summary, dict) else 0,
            "low_severity_count": int(summary.get("low_severity_count", 0) or 0) if isinstance(summary, dict) else 0,
            "confirmed_high_severity_count": confirmed_high,
            "confirmed_medium_severity_count": confirmed_medium,
            "confirmed_low_severity_count": confirmed_low,
            "endpoint_count": int(summary.get("endpoint_count", 0) or 0) if isinstance(summary, dict) else 0,
            "high_risk_endpoint_count": int(summary.get("high_risk_endpoint_count", 0) or 0) if isinstance(summary, dict) else 0,
            "scan_profile": scan_options.get("scan_profile", "deep") if isinstance(scan_options, dict) else "deep",
            "risk_gate_status": risk_gate.get("status", "unknown") if isinstance(risk_gate, dict) else "unknown",
        })
    return reports


def get_scan_history(limit: int = 25) -> dict[str, object]:
    scans = list(reversed(list_scans()[:limit]))
    return {
        "scans": scans,
        "severity_trends": [
            {
                "scan_id": scan["scan_id"],
                "target_url": scan["target_url"],
                "finished_at": scan["finished_at"],
                "high": scan["high_severity_count"],
                "medium": scan["medium_severity_count"],
                "low": scan["low_severity_count"],
                "endpoints": scan["endpoint_count"],
                "high_risk_endpoints": scan["high_risk_endpoint_count"],
                "total": scan["findings_count"],
                "risk_gate_status": scan["risk_gate_status"],
            }
            for scan in scans
        ],
    }


def get_scan(scan_id: str) -> dict[str, object] | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def get_finding_lifecycle(scan_id: str, finding_index: int) -> dict[str, object]:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT state, owner, sla_due_at, comments_json, updated_at
            FROM finding_lifecycle
            WHERE scan_id = ? AND finding_index = ?
            """,
            (scan_id, finding_index),
        ).fetchone()
    if row is None:
        return {
            "scan_id": scan_id,
            "finding_index": finding_index,
            "state": "open",
            "owner": "",
            "sla_due_at": "",
            "comments": [],
            "updated_at": "",
        }
    return {
        "scan_id": scan_id,
        "finding_index": finding_index,
        "state": row[0],
        "owner": row[1],
        "sla_due_at": row[2],
        "comments": json.loads(row[3] or "[]"),
        "updated_at": row[4],
    }


def update_finding_lifecycle(
    scan_id: str,
    finding_index: int,
    *,
    state: str,
    owner: str = "",
    sla_due_at: str = "",
    actor: str = "local-user",
) -> dict[str, object]:
    init_db()
    current = get_finding_lifecycle(scan_id, finding_index)
    updated_at = datetime.now(timezone.utc).isoformat()
    comments = current.get("comments", [])
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO finding_lifecycle
            (scan_id, finding_index, state, owner, sla_due_at, comments_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, finding_index, state, owner, sla_due_at, json.dumps(comments), updated_at),
        )
    write_audit_log(
        "finding.lifecycle.updated",
        actor=actor,
        target=f"{scan_id}:{finding_index}",
        details={"state": state, "owner": owner, "sla_due_at": sla_due_at},
    )
    return get_finding_lifecycle(scan_id, finding_index)


def add_finding_comment(
    scan_id: str,
    finding_index: int,
    *,
    body: str,
    actor: str = "local-user",
) -> dict[str, object]:
    init_db()
    current = get_finding_lifecycle(scan_id, finding_index)
    comments = list(current.get("comments", []))
    comments.append(
        {
            "body": body,
            "actor": actor,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    updated_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO finding_lifecycle
            (scan_id, finding_index, state, owner, sla_due_at, comments_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding_index,
                str(current.get("state") or "open"),
                str(current.get("owner") or ""),
                str(current.get("sla_due_at") or ""),
                json.dumps(comments),
                updated_at,
            ),
        )
    write_audit_log(
        "finding.comment.created",
        actor=actor,
        target=f"{scan_id}:{finding_index}",
        details={"body": body},
    )
    return get_finding_lifecycle(scan_id, finding_index)


def write_audit_log(event_type: str, *, actor: str, target: str, details: dict[str, object]) -> None:
    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (event_type, actor, target, details_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_type, actor, target, json.dumps(details), datetime.now(timezone.utc).isoformat()),
        )


def list_audit_logs(limit: int = 100) -> list[dict[str, object]]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT event_type, actor, target, details_json, created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "event_type": row[0],
            "actor": row[1],
            "target": row[2],
            "details": json.loads(row[3] or "{}"),
            "created_at": row[4],
        }
        for row in rows
    ]


def create_organization(name: str, *, plan: str = "team", actor: str = "local-user") -> dict[str, object]:
    init_db()
    org_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO organizations (org_id, name, plan, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (org_id, name, plan, created_at),
        )
        conn.execute(
            """
            INSERT INTO team_members (member_id, org_id, email, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), org_id, "owner@local.adaptivescan", "owner", created_at),
        )
    write_audit_log("organization.created", actor=actor, target=org_id, details={"name": name, "plan": plan})
    return {"org_id": org_id, "name": name, "plan": plan, "created_at": created_at}


def create_workspace(
    org_id: str,
    name: str,
    *,
    default_allowlist: list[str] | None = None,
    actor: str = "local-user",
) -> dict[str, object]:
    init_db()
    if get_organization(org_id) is None:
        raise ValueError("Organization not found")
    workspace_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    allowlist = default_allowlist or []
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO workspaces (workspace_id, org_id, name, default_allowlist_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (workspace_id, org_id, name, json.dumps(allowlist), created_at),
        )
    write_audit_log(
        "workspace.created",
        actor=actor,
        target=workspace_id,
        details={"org_id": org_id, "name": name, "default_allowlist": allowlist},
    )
    return {
        "workspace_id": workspace_id,
        "org_id": org_id,
        "name": name,
        "default_allowlist": allowlist,
        "created_at": created_at,
    }


def create_api_key(
    workspace_id: str,
    name: str,
    *,
    scopes: list[str] | None = None,
    actor: str = "local-user",
) -> dict[str, object]:
    init_db()
    if get_workspace(workspace_id) is None:
        raise ValueError("Workspace not found")
    key_id = str(uuid.uuid4())
    raw_secret = f"ascan_{secrets.token_urlsafe(32)}"
    key_prefix = raw_secret[:14]
    key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
    created_at = datetime.now(timezone.utc).isoformat()
    requested_scopes = scopes or ["scan:run", "scan:read", "report:read"]
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO api_keys (key_id, workspace_id, name, key_prefix, key_hash, scopes_json, created_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (key_id, workspace_id, name, key_prefix, key_hash, json.dumps(requested_scopes), created_at, ""),
        )
    write_audit_log(
        "api_key.created",
        actor=actor,
        target=key_id,
        details={"workspace_id": workspace_id, "name": name, "scopes": requested_scopes},
    )
    return {
        "key_id": key_id,
        "workspace_id": workspace_id,
        "name": name,
        "key_prefix": key_prefix,
        "secret": raw_secret,
        "scopes": requested_scopes,
        "created_at": created_at,
        "revoked_at": "",
    }


def get_organization(org_id: str) -> dict[str, object] | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT org_id, name, plan, created_at FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
    if row is None:
        return None
    return {"org_id": row[0], "name": row[1], "plan": row[2], "created_at": row[3]}


def get_workspace(workspace_id: str) -> dict[str, object] | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT workspace_id, org_id, name, default_allowlist_json, created_at
            FROM workspaces
            WHERE workspace_id = ?
            """,
            (workspace_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "workspace_id": row[0],
        "org_id": row[1],
        "name": row[2],
        "default_allowlist": json.loads(row[3] or "[]"),
        "created_at": row[4],
    }


def get_tenancy_overview() -> dict[str, object]:
    init_db()
    with get_connection() as conn:
        org_rows = conn.execute("SELECT org_id, name, plan, created_at FROM organizations ORDER BY created_at DESC").fetchall()
        workspace_rows = conn.execute(
            """
            SELECT workspace_id, org_id, name, default_allowlist_json, created_at
            FROM workspaces
            ORDER BY created_at DESC
            """
        ).fetchall()
        member_rows = conn.execute(
            "SELECT member_id, org_id, email, role, created_at FROM team_members ORDER BY created_at DESC"
        ).fetchall()
        key_rows = conn.execute(
            """
            SELECT key_id, workspace_id, name, key_prefix, scopes_json, created_at, revoked_at
            FROM api_keys
            ORDER BY created_at DESC
            """
        ).fetchall()
    return {
        "organizations": [
            {"org_id": row[0], "name": row[1], "plan": row[2], "created_at": row[3]}
            for row in org_rows
        ],
        "workspaces": [
            {
                "workspace_id": row[0],
                "org_id": row[1],
                "name": row[2],
                "default_allowlist": json.loads(row[3] or "[]"),
                "created_at": row[4],
            }
            for row in workspace_rows
        ],
        "team_members": [
            {"member_id": row[0], "org_id": row[1], "email": row[2], "role": row[3], "created_at": row[4]}
            for row in member_rows
        ],
        "api_keys": [
            {
                "key_id": row[0],
                "workspace_id": row[1],
                "name": row[2],
                "key_prefix": row[3],
                "scopes": json.loads(row[4] or "[]"),
                "created_at": row[5],
                "revoked_at": row[6],
            }
            for row in key_rows
        ],
        "rbac_roles": [
            {"role": "owner", "permissions": ["org:admin", "workspace:admin", "scan:run", "report:read"]},
            {"role": "analyst", "permissions": ["workspace:read", "scan:run", "finding:manage", "report:read"]},
            {"role": "viewer", "permissions": ["workspace:read", "report:read"]},
            {"role": "ci-bot", "permissions": ["scan:run", "scan:read", "report:read"]},
        ],
    }


def create_auth_user(
    *,
    user_id: str,
    org_id: str,
    email: str,
    first_name: str,
    last_name: str,
    company_name: str,
    role: str,
    password_hash_value: str,
    mfa_enabled: bool = True,
) -> dict[str, object]:
    init_db()
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO auth_users
            (user_id, org_id, email, first_name, last_name, company_name, role, password_hash, mfa_enabled, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                org_id,
                email,
                first_name,
                last_name,
                company_name,
                role,
                password_hash_value,
                1 if mfa_enabled else 0,
                created_at,
                "",
            ),
        )
    return {
        "user_id": user_id,
        "organization_id": org_id,
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "company_name": company_name,
        "role": role,
        "mfa_required": mfa_enabled,
        "created_at": created_at,
    }


def get_auth_user_by_email(email: str) -> dict[str, object] | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT user_id, org_id, email, first_name, last_name, company_name, role, password_hash, mfa_enabled, created_at, last_login_at
            FROM auth_users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
    if row is None:
        return None
    return {
        "user_id": row[0],
        "organization_id": row[1],
        "email": row[2],
        "first_name": row[3],
        "last_name": row[4],
        "company_name": row[5],
        "role": row[6],
        "password_hash": row[7],
        "mfa_required": bool(row[8]),
        "created_at": row[9],
        "last_login_at": row[10],
    }


def mark_auth_user_login(email: str) -> None:
    init_db()
    with get_connection() as conn:
        conn.execute(
            "UPDATE auth_users SET last_login_at = ? WHERE email = ?",
            (datetime.now(timezone.utc).isoformat(), email),
        )


def update_auth_user_password(email: str, password_hash_value: str) -> bool:
    init_db()
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE auth_users SET password_hash = ? WHERE email = ?",
            (password_hash_value, email),
        )
    return cursor.rowcount > 0


def store_otp_challenge(*, email: str, purpose: str, code_hash: str, expires_at: int) -> dict[str, object]:
    init_db()
    challenge_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO auth_otp_challenges
            (challenge_id, email, purpose, code_hash, expires_at, consumed_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (challenge_id, email, purpose, code_hash, expires_at, "", created_at),
        )
    return {"challenge_id": challenge_id, "email": email, "purpose": purpose, "expires_at": expires_at, "created_at": created_at}


def consume_otp_challenge(*, email: str, purpose: str, code_hash: str, now: int) -> bool:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT challenge_id, code_hash
            FROM auth_otp_challenges
            WHERE email = ? AND purpose = ? AND consumed_at = '' AND expires_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (email, purpose, now),
        ).fetchone()
        if row is None or not secrets.compare_digest(str(row[1]), code_hash):
            return False
        conn.execute(
            "UPDATE auth_otp_challenges SET consumed_at = ? WHERE challenge_id = ?",
            (datetime.now(timezone.utc).isoformat(), row[0]),
        )
    return True


def create_refresh_session(*, user_id: str, refresh_token_hash: str, expires_at: int) -> dict[str, object]:
    init_db()
    session_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO auth_refresh_sessions
            (session_id, user_id, refresh_token_hash, expires_at, revoked_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, user_id, refresh_token_hash, expires_at, "", created_at),
        )
    return {"session_id": session_id, "user_id": user_id, "expires_at": expires_at, "created_at": created_at}


def compare_scans(left_scan_id: str, right_scan_id: str) -> dict[str, object] | None:
    left = get_scan(left_scan_id)
    right = get_scan(right_scan_id)
    if left is None or right is None:
        return None

    def _finding_key(finding: dict[str, object]) -> tuple[str, str, str, str]:
        return (
            str(finding.get("detector", "")),
            str(finding.get("url", "")),
            str(finding.get("parameter", "")),
            str(finding.get("payload", "")),
        )

    left_findings = {_finding_key(item): item for item in left.get("findings", [])}
    right_findings = {_finding_key(item): item for item in right.get("findings", [])}

    new_keys = sorted(set(right_findings) - set(left_findings))
    resolved_keys = sorted(set(left_findings) - set(right_findings))

    return {
        "left_scan_id": left_scan_id,
        "right_scan_id": right_scan_id,
        "left_target_url": left.get("target_url"),
        "right_target_url": right.get("target_url"),
        "new_findings": [right_findings[key] for key in new_keys],
        "resolved_findings": [left_findings[key] for key in resolved_keys],
        "summary_delta": {
            "finding_delta": int(right.get("summary", {}).get("finding_count", 0)) - int(left.get("summary", {}).get("finding_count", 0)),
            "page_delta": int(right.get("summary", {}).get("page_count", 0)) - int(left.get("summary", {}).get("page_count", 0)),
            "endpoint_delta": int(right.get("summary", {}).get("endpoint_count", 0)) - int(left.get("summary", {}).get("endpoint_count", 0)),
            "validated_delta": int(right.get("summary", {}).get("validated_finding_count", 0)) - int(left.get("summary", {}).get("validated_finding_count", 0)),
        },
    }
