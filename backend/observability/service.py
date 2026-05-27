from __future__ import annotations

from datetime import datetime, timezone

from backend.config.settings import settings


def observability_status() -> dict[str, object]:
    return {
        "prometheus": {
            "enabled": settings.enable_prometheus_metrics,
            "endpoint": "/api/metrics",
            "metric_families": [
                "adaptivescan_scans_total",
                "adaptivescan_findings_total",
                "adaptivescan_queue_depth",
                "adaptivescan_worker_heartbeat_age_seconds",
                "adaptivescan_scan_duration_ms",
            ],
        },
        "opentelemetry": {
            "enabled": settings.enable_opentelemetry,
            "trace_boundaries": ["api_gateway", "orchestrator", "worker", "detector", "reporting"],
        },
        "retention": {
            "telemetry_days": settings.telemetry_retention_days,
            "evidence_days": settings.evidence_retention_days,
        },
        "dashboards": [
            "queue health",
            "worker fleet",
            "scan throughput",
            "finding velocity",
            "attack surface drift",
        ],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def prometheus_metrics(scans: list[dict[str, object]], queue_health: dict[str, object]) -> str:
    finding_total = sum(int(scan.get("findings_count", 0) or 0) for scan in scans)
    high_total = sum(int(scan.get("high_severity_count", 0) or 0) for scan in scans)
    lines = [
        "# HELP adaptivescan_scans_total Total scans stored by AdaptiveScan.",
        "# TYPE adaptivescan_scans_total counter",
        f"adaptivescan_scans_total {len(scans)}",
        "# HELP adaptivescan_findings_total Total findings stored by AdaptiveScan.",
        "# TYPE adaptivescan_findings_total counter",
        f'adaptivescan_findings_total{{severity="all"}} {finding_total}',
        f'adaptivescan_findings_total{{severity="high"}} {high_total}',
        "# HELP adaptivescan_queue_depth Current queued tasks by logical queue.",
        "# TYPE adaptivescan_queue_depth gauge",
    ]
    for queue in queue_health.get("queues", []):
        if isinstance(queue, dict):
            lines.append(f'adaptivescan_queue_depth{{queue="{queue.get("name")}"}} {int(queue.get("queued", 0) or 0)}')
    return "\n".join(lines) + "\n"

