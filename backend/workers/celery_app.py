from __future__ import annotations

import asyncio
from typing import Any

from backend.config.settings import settings
from backend.core.scanner_engine import ScannerEngine
from backend.queue.orchestrator import build_scan_job

try:
    from celery import Celery
except Exception:  # pragma: no cover - keeps local test environments lightweight.
    Celery = None  # type: ignore[assignment]


def create_celery_app():
    if Celery is None:
        return None
    app = Celery(
        "adaptivescan",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=["backend.workers.celery_app"],
    )
    app.conf.update(
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_default_retry_delay=10,
        worker_prefetch_multiplier=1,
        task_routes={
            "adaptivescan.recon": {"queue": "recon", "routing_key": "scan.recon"},
            "adaptivescan.crawl": {"queue": "crawl", "routing_key": "scan.crawl"},
            "adaptivescan.detect": {"queue": "detect", "routing_key": "scan.detect"},
            "adaptivescan.validate": {"queue": "validate", "routing_key": "scan.validate"},
            "adaptivescan.report": {"queue": "report", "routing_key": "scan.report"},
            "adaptivescan.ai": {"queue": "ai", "routing_key": "scan.ai"},
        },
    )
    return app


celery_app = create_celery_app()


if celery_app is not None:

    @celery_app.task(name="adaptivescan.crawl", bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=2)
    def run_scan_task(self, scan_id: str, target_url: str, scan_options: dict[str, Any] | None = None) -> dict[str, Any]:
        job = build_scan_job(scan_id, target_url, scan_options or {})
        engine = ScannerEngine()
        result = asyncio.run(engine.scan(target_url, scan_id=scan_id, scan_options=scan_options or {}))
        return {"job": job, "scan_id": result["scan_id"], "summary": result.get("summary", {})}

