from backend.database import db


def test_finding_lifecycle_updates_comments_and_audit_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "scanner.db")

    lifecycle = db.update_finding_lifecycle(
        "scan-1",
        0,
        state="assigned",
        owner="security@example.test",
        sla_due_at="2026-05-30",
        actor="analyst",
    )
    assert lifecycle["state"] == "assigned"
    assert lifecycle["owner"] == "security@example.test"

    lifecycle = db.add_finding_comment("scan-1", 0, body="Retest after patch.", actor="analyst")
    assert lifecycle["comments"][0]["body"] == "Retest after patch."

    audit_logs = db.list_audit_logs()
    assert [item["event_type"] for item in audit_logs] == [
        "finding.comment.created",
        "finding.lifecycle.updated",
    ]
