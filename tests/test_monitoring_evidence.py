import json

from backend.monitoring.policies import monitoring_overview
from backend.reports.report_generator import generate_evidence_bundle
from backend.validation.engine import build_validation_summary


def test_monitoring_overview_builds_recurring_targets():
    overview = monitoring_overview([{"target_url": "https://example.com"}])
    assert overview["scheduler"]["recurring_scan_count"] == 1
    assert overview["alert_policies"]
    assert overview["continuous_asset_monitoring"]["enabled"] is True


def test_validation_summary_scores_and_clusters():
    summary = build_validation_summary(
        [
            {
                "detector": "sqli",
                "category": "injection",
                "url": "https://example.com",
                "parameter": "id",
                "payload": "'",
                "confidence": "high",
                "validation_state": "validated",
                "baseline_status": 200,
                "mutated_status": 500,
                "baseline_length": 10,
                "mutated_length": 100,
            }
        ]
    )
    assert summary["validated_count"] == 1
    assert summary["high_proof_count"] == 1
    assert summary["anomaly_clusters"][0]["cluster"] == "injection"


def test_evidence_bundle_export(tmp_path, monkeypatch):
    from backend.reports import report_generator

    monkeypatch.setattr(report_generator, "EXPORT_DIR", tmp_path)
    path = generate_evidence_bundle(
        {
            "scan_id": "scan-test",
            "target_url": "https://example.com",
            "summary": {"finding_count": 1},
            "findings": [{"detector": "sqli", "replay_plan": {"curl": "curl -i https://example.com"}}],
        }
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["scan_id"] == "scan-test"
    assert payload["replay_plans"]
