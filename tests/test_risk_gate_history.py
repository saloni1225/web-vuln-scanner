from backend.core.risk_gate import evaluate_risk_gate
from backend.database import db


def test_risk_gate_fails_when_high_findings_exceed_policy():
    result = evaluate_risk_gate({"finding_count": 3, "high_severity_count": 1}, fail_on_high=True, max_high=0)

    assert result["status"] == "failed"
    assert result["passed"] is False
    assert "high severity" in result["failures"][0]


def test_scan_history_includes_severity_trend_and_risk_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "scanner.db")
    db.save_scan(
        {
            "scan_id": "scan-1",
            "target_url": "https://example.test",
            "started_at": "2026-05-16T00:00:00+00:00",
            "finished_at": "2026-05-16T00:01:00+00:00",
            "findings": [{"severity": "high"}],
            "summary": {
                "finding_count": 2,
                "high_severity_count": 1,
                "medium_severity_count": 1,
                "low_severity_count": 0,
                "endpoint_count": 12,
                "high_risk_endpoint_count": 2,
            },
            "scan_options": {"scan_profile": "quick"},
            "risk_gate": {"status": "failed"},
        }
    )

    history = db.get_scan_history()

    assert history["severity_trends"][0]["high"] == 1
    assert history["severity_trends"][0]["endpoints"] == 12
    assert history["severity_trends"][0]["high_risk_endpoints"] == 2
    assert history["severity_trends"][0]["risk_gate_status"] == "failed"
