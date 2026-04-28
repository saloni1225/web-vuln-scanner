import json
import sqlite3
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
            "SELECT scan_id, target_url, started_at, finished_at, findings_count FROM scans ORDER BY started_at DESC"
        ).fetchall()
    return [
        {
            "scan_id": row[0],
            "target_url": row[1],
            "started_at": row[2],
            "finished_at": row[3],
            "findings_count": row[4],
        }
        for row in rows
    ]


def get_scan(scan_id: str) -> dict[str, object] | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


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
