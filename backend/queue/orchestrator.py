from __future__ import annotations

from datetime import datetime, timezone

from backend.config.settings import settings


QUEUE_DEFINITIONS: list[dict[str, object]] = [
    {
        "name": "recon",
        "purpose": "passive attack surface intelligence",
        "routing_key": "scan.recon",
        "stages": ["asn", "dns", "ct", "waf", "cloud"],
        "desired_concurrency": 4,
        "max_retries": 2,
    },
    {
        "name": "crawl",
        "purpose": "browser, SPA, API, and form crawling",
        "routing_key": "scan.crawl",
        "stages": ["http-crawl", "browser-crawl", "api-discovery"],
        "desired_concurrency": 6,
        "max_retries": 2,
    },
    {
        "name": "detect",
        "purpose": "modular detector execution",
        "routing_key": "scan.detect",
        "stages": ["injection", "auth", "access-control", "client-side", "infrastructure"],
        "desired_concurrency": 8,
        "max_retries": 1,
    },
    {
        "name": "validate",
        "purpose": "safe replay validation and false-positive suppression",
        "routing_key": "scan.validate",
        "stages": ["replay", "timing", "differential-analysis", "confidence-scoring"],
        "desired_concurrency": 4,
        "max_retries": 1,
    },
    {
        "name": "telemetry",
        "purpose": "websocket events, worker heartbeats, and scan analytics",
        "routing_key": "scan.telemetry",
        "stages": ["events", "metrics", "drift"],
        "desired_concurrency": 2,
        "max_retries": 3,
    },
    {
        "name": "report",
        "purpose": "HTML/PDF/evidence bundle generation",
        "routing_key": "scan.report",
        "stages": ["executive-report", "technical-report", "evidence-bundle"],
        "desired_concurrency": 2,
        "max_retries": 2,
    },
    {
        "name": "ai",
        "purpose": "risk prioritization, attack-chain analysis, and remediation intelligence",
        "routing_key": "scan.ai",
        "stages": ["dedupe", "exploitability", "remediation", "summaries"],
        "desired_concurrency": 2,
        "max_retries": 1,
    },
]


def queue_topology() -> dict[str, object]:
    return {
        "broker": settings.queue_backend,
        "broker_url": settings.redis_url,
        "worker_runtime": settings.worker_runtime,
        "execution_mode": settings.execution_mode,
        "queues": QUEUE_DEFINITIONS,
        "routing": {
            "scan.created": "recon",
            "recon.completed": "crawl",
            "crawl.completed": "detect",
            "detect.completed": "validate",
            "validate.completed": "ai",
            "ai.completed": "report",
            "all.events": "telemetry",
        },
        "fault_tolerance": {
            "ack_late": True,
            "retry_backoff": True,
            "dead_letter_queue": "scan.dead-letter",
            "idempotency_key": "scan_id + phase + target_url",
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def build_scan_job(scan_id: str, target_url: str, scan_options: dict[str, object] | None = None) -> dict[str, object]:
    scan_options = scan_options or {}
    routed_queue = route_scan_job(scan_options)
    return {
        "job_id": scan_id,
        "target_url": target_url,
        "status": "queued",
        "queue": routed_queue,
        "routing_key": next((str(item["routing_key"]) for item in QUEUE_DEFINITIONS if item["name"] == routed_queue), "scan.crawl"),
        "scan_options": scan_options,
        "execution_plan": build_distributed_execution_plan(scan_id, target_url, scan_options),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def route_scan_job(scan_options: dict[str, object] | None = None) -> str:
    options = scan_options or {}
    if options.get("enable_subdomain_recon") or options.get("enable_dns_analysis") or options.get("enable_cloud_asset_recon"):
        return "recon"
    if options.get("resume_from_scan_id"):
        return "detect"
    return "crawl"


def build_distributed_execution_plan(
    scan_id: str,
    target_url: str,
    scan_options: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    options = scan_options or {}
    phases = ["recon", "crawl", "detect", "validate", "ai", "report"]
    if options.get("enable_finding_validator") is False:
        phases.remove("validate")
    if options.get("enable_api_fuzzing") is False and options.get("enable_graphql_checks") is False:
        detector_scope = "web-detectors"
    else:
        detector_scope = "web-api-detectors"
    return [
        {
            "phase": phase,
            "task_id": f"{scan_id}:{phase}",
            "queue": phase,
            "target_url": target_url,
            "detector_scope": detector_scope if phase == "detect" else None,
            "depends_on": f"{scan_id}:{phases[index - 1]}" if index else None,
            "status": "planned",
        }
        for index, phase in enumerate(phases)
    ]


def queue_health_snapshot(active_jobs: list[dict[str, object]] | None = None) -> dict[str, object]:
    jobs = active_jobs or []
    queued_by_name = {queue["name"]: 0 for queue in QUEUE_DEFINITIONS}
    for job in jobs:
        queue_name = str(job.get("queue") or "crawl")
        queued_by_name[queue_name] = queued_by_name.get(queue_name, 0) + 1
    return {
        "status": "ready",
        "broker": settings.queue_backend,
        "execution_mode": settings.execution_mode,
        "queues": [
            {
                "name": str(queue["name"]),
                "queued": queued_by_name.get(str(queue["name"]), 0),
                "desired_concurrency": queue["desired_concurrency"],
                "max_retries": queue["max_retries"],
            }
            for queue in QUEUE_DEFINITIONS
        ],
        "active_job_count": len(jobs),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
