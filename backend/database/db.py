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
