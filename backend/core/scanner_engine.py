import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable

from backend.core.crawler import Crawler
from backend.core.request_handler import RequestHandler
from backend.database.db import save_scan
from backend.detection.auth_bypass import AuthBypassDetector
from backend.detection.base_detector import Finding
from backend.detection.csrf_detector import CsrfDetector
from backend.detection.sqli_detector import SQLiDetector
from backend.detection.xss_detector import XSSDetector
from backend.utils.helpers import build_target_advisory


ProgressCallback = Callable[[dict[str, object]], Awaitable[None]]


class ScannerEngine:
    def __init__(self) -> None:
        self.detectors = [SQLiDetector(), XSSDetector(), CsrfDetector(), AuthBypassDetector()]

    async def scan(
        self,
        target_url: str,
        scan_id: str | None = None,
        progress_callback: ProgressCallback | None = None,
        auth_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        scan_id = scan_id or str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        request_handler = RequestHandler(auth=auth_context)
        try:
            await self._ensure_target_reachable(target_url, request_handler, progress_callback)
            if progress_callback:
                await progress_callback(
                    {
                        "event": "scan_started",
                        "status": "running",
                        "progress": 5,
                        "message": f"Initializing scan for {target_url}",
                    }
                )
            crawler = Crawler(request_handler)
            site_map = await crawler.crawl(target_url)
            if progress_callback:
                await progress_callback(
                    {
                        "event": "crawl_completed",
                        "status": "running",
                        "progress": 30,
                        "message": f"Crawled {len(site_map['pages'])} pages and discovered {len(site_map['forms'])} forms",
                        "page_count": len(site_map["pages"]),
                        "form_count": len(site_map["forms"]),
                        "endpoint_count": len(site_map.get("endpoints", [])),
                    }
                )
            findings: list[Finding] = []
            detector_timings: list[dict[str, object]] = []
            detector_count = max(1, len(self.detectors))

            for index, detector in enumerate(self.detectors, start=1):
                started = time.perf_counter()
                if progress_callback:
                    await progress_callback(
                        {
                            "event": "detector_started",
                            "status": "running",
                            "progress": 30 + int(((index - 1) / detector_count) * 55),
                            "detector": detector.name,
                            "message": f"Running {detector.name} detector",
                        }
                    )
                detector_findings = await detector.detect(target_url, site_map, request_handler)
                findings.extend(detector_findings)
                elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                detector_timings.append(
                    {
                        "detector": detector.name,
                        "elapsed_ms": elapsed_ms,
                        "finding_count": len(detector_findings),
                    }
                )
                if progress_callback:
                    await progress_callback(
                        {
                            "event": "detector_completed",
                            "status": "running",
                            "progress": 30 + int((index / detector_count) * 55),
                            "detector": detector.name,
                            "elapsed_ms": elapsed_ms,
                            "finding_count": len(detector_findings),
                            "message": f"{detector.name} detector finished in {elapsed_ms} ms",
                        }
                    )

            summary = {
                "page_count": len(site_map["pages"]),
                "form_count": len(site_map["forms"]),
                "endpoint_count": len(site_map.get("endpoints", [])),
                "finding_count": len(findings),
                "high_severity_count": sum(1 for finding in findings if finding.severity == "high"),
                "medium_severity_count": sum(1 for finding in findings if finding.severity == "medium"),
                "low_severity_count": sum(1 for finding in findings if finding.severity == "low"),
                "duration_ms": round((datetime.now(timezone.utc) - datetime.fromisoformat(started_at)).total_seconds() * 1000, 2),
            }
            result = {
                "scan_id": scan_id,
                "target_url": target_url,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "pages": site_map["pages"],
                "page_details": site_map.get("page_details", []),
                "forms": site_map["forms"],
                "endpoints": site_map.get("endpoints", []),
                "findings": [finding.to_dict() for finding in findings],
                "summary": summary,
                "detector_timings": detector_timings,
                "target_advisory": build_target_advisory(target_url),
                "auth_used": bool(auth_context and (auth_context.get("headers") or auth_context.get("cookies"))),
            }
            save_scan(result)
            if progress_callback:
                await progress_callback(
                    {
                        "event": "scan_completed",
                        "status": "completed",
                        "progress": 100,
                        "message": f"Scan complete with {summary['finding_count']} findings",
                        "summary": summary,
                        "detector_timings": detector_timings,
                    }
                )
            return result
        finally:
            await request_handler.close()

    async def _ensure_target_reachable(
        self,
        target_url: str,
        request_handler: RequestHandler,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        try:
            response = await request_handler.get(target_url)
        except Exception as exc:
            if progress_callback:
                await progress_callback(
                    {
                        "event": "scan_failed",
                        "status": "failed",
                        "progress": 100,
                        "message": (
                            f"Target is unreachable: {target_url}. "
                            "Start the target app/container and retry."
                        ),
                    }
                )
            raise RuntimeError(
                f"Target is unreachable: {target_url}. "
                "Ensure Juice Shop (or your target app) is running before scanning."
            ) from exc
        if response.status_code >= 500:
            if progress_callback:
                await progress_callback(
                    {
                        "event": "scan_failed",
                        "status": "failed",
                        "progress": 100,
                        "message": (
                            f"Target responded with HTTP {response.status_code} at startup check. "
                            "Resolve server-side errors and retry the scan."
                        ),
                    }
                )
            raise RuntimeError(
                f"Target startup check failed with HTTP {response.status_code} for {target_url}. "
                "Resolve server errors before scanning."
            )

    def scan_sync(self, target_url: str, auth_context: dict[str, object] | None = None) -> dict[str, object]:
        return asyncio.run(self.scan(target_url, auth_context=auth_context))
