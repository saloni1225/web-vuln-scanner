from __future__ import annotations


def scheduler_architecture() -> dict[str, object]:
    return {
        "scheduler": "celery-beat-compatible",
        "queue": "redis",
        "worker": "celery",
        "supported_cadences": ["daily", "weekly", "monthly", "custom_cron"],
        "job_tables": ["monitoring_jobs", "monitoring_runs"],
        "detections": [
            "new_asset",
            "new_api",
            "new_subdomain",
            "certificate_change",
            "exposure_drift",
            "new_finding",
        ],
    }


def monitoring_jobs() -> dict[str, object]:
    return {
        "jobs": [
            {"id": "daily-external-asm", "name": "Daily external ASM", "cadence": "daily", "status": "active", "target": "owned domains"},
            {"id": "weekly-exec-review", "name": "Weekly executive review", "cadence": "weekly", "status": "active", "target": "executive report"},
            {"id": "monthly-compliance", "name": "Monthly compliance export", "cadence": "monthly", "status": "ready", "target": "evidence package"},
        ],
        "recent_runs": [
            {"job_id": "daily-external-asm", "status": "completed", "signals": ["new_api", "exposure_drift"]},
            {"job_id": "weekly-exec-review", "status": "completed", "signals": ["executive_summary"]},
        ],
        "architecture": scheduler_architecture(),
    }
