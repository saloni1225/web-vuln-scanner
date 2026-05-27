from __future__ import annotations

from datetime import datetime, timezone


DEFAULT_ALERT_POLICIES = [
    {"name": "critical-or-high-finding", "condition": "high_severity_count > 0", "channels": ["webhook", "email"], "severity": "high"},
    {"name": "attack-surface-drift", "condition": "new_assets > 0 or removed_assets > 0", "channels": ["webhook"], "severity": "medium"},
    {"name": "new-graphql-or-admin-surface", "condition": "exposure_tags contains graphql/admin-panel", "channels": ["webhook"], "severity": "medium"},
    {"name": "ci-risk-gate-failure", "condition": "risk_gate_status == failed", "channels": ["ci"], "severity": "high"},
]


def monitoring_overview(scans: list[dict[str, object]]) -> dict[str, object]:
    recurring_targets = sorted({str(scan.get("target_url", "")) for scan in scans if scan.get("target_url")})
    return {
        "scheduler": {
            "engine": "apscheduler/celery-ready",
            "default_frequency": "daily",
            "recurring_scan_count": len(recurring_targets),
            "targets": recurring_targets[:100],
        },
        "alert_policies": DEFAULT_ALERT_POLICIES,
        "continuous_asset_monitoring": {
            "enabled": True,
            "drift_detection": "endpoint and asset inventory comparisons across scan history",
            "last_evaluated_at": datetime.now(timezone.utc).isoformat(),
        },
        "notification_engine": {
            "channels": ["Slack webhook", "Discord webhook", "email-ready", "CI annotations"],
            "dedupe_window_minutes": 60,
        },
    }
