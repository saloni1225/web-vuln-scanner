import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlparse

from backend.config.settings import settings
from backend.core.crawler import Crawler
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.database.db import save_scan
from backend.detection.base_detector import Finding
from backend.detection.registry import describe_loaded_detectors
from backend.detection.registry import load_detectors
from backend.utils.helpers import build_target_advisory
from backend.utils.helpers import is_private_host


ProgressCallback = Callable[[dict[str, object]], Awaitable[None]]


class ScannerEngine:
    def __init__(self) -> None:
        self.detectors = load_detectors()

    async def scan(
        self,
        target_url: str,
        scan_id: str | None = None,
        progress_callback: ProgressCallback | None = None,
        auth_context: dict[str, object] | None = None,
        scan_options: dict[str, object] | None = None,
    ) -> dict[str, object]:
        scan_id = scan_id or str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        request_handler = RequestHandler(auth=auth_context)
        scan_options = scan_options or {}
        selected_detectors = load_detectors(list(scan_options.get("detector_names", [])) or None)
        selected_detector_names = [detector.name for detector in selected_detectors]
        try:
            await self._ensure_target_reachable(target_url, request_handler, progress_callback, auth_context)
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
            detector_site_map = self._apply_scan_options_to_site_map(site_map, scan_options)
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
            detector_count = max(1, len(selected_detectors))

            for index, detector in enumerate(selected_detectors, start=1):
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
                detector_findings = await detector.detect(target_url, detector_site_map, request_handler)
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

            findings = self._enrich_findings(findings)
            api_summary = site_map.get("api_summary", {})
            behavioral_summary = self._build_behavioral_summary(site_map, findings)
            summary = {
                "page_count": len(site_map["pages"]),
                "form_count": len(site_map["forms"]),
                "endpoint_count": len(site_map.get("endpoints", [])),
                "finding_count": len(findings),
                "high_severity_count": sum(1 for finding in findings if finding.severity == "high"),
                "medium_severity_count": sum(1 for finding in findings if finding.severity == "medium"),
                "low_severity_count": sum(1 for finding in findings if finding.severity == "low"),
                "api_endpoint_count": api_summary.get("api_endpoint_count", 0),
                "graphql_endpoint_count": api_summary.get("graphql_endpoint_count", 0),
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
                "api_summary": api_summary,
                "behavioral_summary": behavioral_summary,
                "detector_timings": detector_timings,
                "detector_registry": describe_loaded_detectors(selected_detector_names),
                "target_advisory": build_target_advisory(target_url),
                "auth_used": bool(auth_context and (auth_context.get("headers") or auth_context.get("cookies"))),
                "safety_controls": {
                    "rate_limit_per_second": auth_context.get("rate_limit_per_second") if auth_context else settings.default_rate_limit_per_second,
                    "authorization_confirmed": bool(auth_context and auth_context.get("authorization_confirmed")),
                    "domain_allowlist": auth_context.get("domain_allowlist", []) if auth_context else [],
                },
                "scan_options": {
                    "detector_names": selected_detector_names,
                    "enable_api_fuzzing": bool(scan_options.get("enable_api_fuzzing", True)),
                    "enable_graphql_checks": bool(scan_options.get("enable_graphql_checks", True)),
                },
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
        auth_context: dict[str, object] | None = None,
    ) -> None:
        auth_context = auth_context or {}
        if not is_private_host(target_url):
            if settings.enforce_authorization_for_external and not auth_context.get("authorization_confirmed"):
                raise RuntimeError(
                    "External scanning requires explicit authorization confirmation. "
                    "Use only targets you own or are allowed to test."
                )
            allowlist = {item.lower() for item in auth_context.get("domain_allowlist", []) if item}
            host = urlparse(target_url).hostname or ""
            if allowlist and host.lower() not in allowlist:
                raise RuntimeError(
                    f"Target host {host} is not in the requested domain allowlist."
                )
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

    @staticmethod
    def _enrich_findings(findings: list[Finding]) -> list[Finding]:
        severity_base = {"high": 8.6, "medium": 6.1, "low": 3.8}
        confidence_mod = {"high": 0.4, "medium": 0.0, "low": -0.5}
        for finding in findings:
            score = severity_base.get(finding.severity, 5.0) + confidence_mod.get(finding.confidence or "medium", 0.0)
            finding.cvss_score = round(min(10.0, max(0.1, score)), 1)
            finding.remediation_priority = "P1" if finding.cvss_score >= 8.5 else "P2" if finding.cvss_score >= 6.0 else "P3"
            finding.validation_state = "validated" if finding.confidence == "high" else "requires-review"
            finding.poc = (
                f"{finding.method.upper()} {finding.url} with parameter {finding.parameter or '-'} "
                f"using payload {finding.payload or '-'}"
            )
        return findings

    @staticmethod
    def _build_behavioral_summary(site_map: dict[str, object], findings: list[Finding]) -> dict[str, object]:
        analyzer = ResponseAnalyzer()
        anomaly_scores: list[float] = []
        evidence_categories: dict[str, int] = {}
        for finding in findings:
            if finding.baseline_status is None or finding.mutated_status is None:
                continue
            baseline = type("Baseline", (), {"status_code": finding.baseline_status, "text": "x" * (finding.baseline_length or 0), "elapsed_ms": 0, "headers": {}})
            candidate = type("Candidate", (), {"status_code": finding.mutated_status, "text": "x" * (finding.mutated_length or 0), "elapsed_ms": 0, "headers": {}})
            anomaly_scores.append(analyzer.anomaly_score(baseline, candidate))
            category = finding.category or "generic"
            evidence_categories[category] = evidence_categories.get(category, 0) + 1
        average_anomaly = round(sum(anomaly_scores) / len(anomaly_scores), 2) if anomaly_scores else 0.0
        return {
            "average_anomaly_score": average_anomaly,
            "highest_anomaly_score": max(anomaly_scores, default=0.0),
            "categories": evidence_categories,
            "surface_mix": {
                "pages": len(site_map.get("pages", [])),
                "forms": len(site_map.get("forms", [])),
                "endpoints": len(site_map.get("endpoints", [])),
            },
        }

    @staticmethod
    def _apply_scan_options_to_site_map(site_map: dict[str, object], scan_options: dict[str, object]) -> dict[str, object]:
        endpoints = list(site_map.get("endpoints", []))
        forms = list(site_map.get("forms", []))

        if not scan_options.get("enable_api_fuzzing", True):
            endpoints = [item for item in endpoints if str(item.get("type")) == "page"]
            forms = [item for item in forms if str(item.get("content_type", "form")) != "json"]

        if not scan_options.get("enable_graphql_checks", True):
            endpoints = [item for item in endpoints if str(item.get("type")) != "graphql"]
            forms = [item for item in forms if "graphql" not in str(item.get("action", "")).lower()]

        return {
            **site_map,
            "endpoints": endpoints,
            "forms": forms,
        }
