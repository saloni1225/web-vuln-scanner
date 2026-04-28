import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlparse

from backend.config.settings import settings
from backend.core.crawler import Crawler
from backend.core.recon import build_replay_plan
from backend.core.recon import run_recon
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.core.resume_store import load_checkpoint
from backend.core.resume_store import save_checkpoint
from backend.core.scan_profiles import apply_scan_profile
from backend.core.schema_fuzzer import run_schema_fuzzing
from backend.database.db import save_scan
from backend.database.db import list_scans
from backend.detection.base_detector import Finding
from backend.detection.registry import describe_loaded_detectors
from backend.detection.registry import load_detectors
from backend.utils.helpers import is_private_host
from backend.utils.helpers import map_cwe
from backend.detection.validator import FindingValidator
from backend.utils.helpers import build_target_advisory
from backend.utils.remediation import get_remediation


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
        scan_options = apply_scan_profile(scan_options or {})
        auth_context = self._apply_profile_to_auth_context(auth_context, scan_options)
        request_handler = RequestHandler(auth=auth_context)
        timeline: list[dict[str, object]] = []
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
            self._timeline(timeline, "startup", "Target reachable and scan initialized", 5)
            checkpoint = load_checkpoint(str(scan_options.get("resume_from_scan_id", ""))) if scan_options.get("resume_from_scan_id") else None
            cached_site_map = checkpoint.get("crawl") if isinstance(checkpoint, dict) else None
            if isinstance(cached_site_map, dict):
                site_map = cached_site_map
                self._timeline(timeline, "resume", "Loaded crawl checkpoint and resumed from detection phase", 24)
            else:
                crawler = Crawler(request_handler, scan_options=scan_options)
                site_map = await crawler.crawl(target_url)
                save_checkpoint(scan_id, "crawl", site_map)
            detector_site_map = self._apply_scan_options_to_site_map(site_map, scan_options)
            schema_fuzz_summary = await run_schema_fuzzing(
                detector_site_map,
                request_handler,
                enabled=bool(scan_options.get("enable_api_fuzzing", True)),
            )
            self._timeline(
                timeline,
                "crawl",
                f"Mapped {len(site_map['pages'])} pages, {len(site_map['forms'])} forms, and {len(site_map.get('endpoints', []))} endpoints",
                30,
            )
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

            if scan_options.get("enable_finding_validator", settings.enable_finding_validator):
                validator = FindingValidator(request_handler)
                await validator.validate_all(findings)
                self._timeline(timeline, "validation", f"Validated {len(findings)} candidate findings", 88)
                
            findings = self._enrich_findings(findings)
            finding_dicts = [finding.to_dict() for finding in findings]
            for index, finding in enumerate(finding_dicts):
                finding["replay_plan"] = build_replay_plan(finding)
                finding["finding_index"] = index
            recon_summary = await run_recon(target_url, request_handler, site_map, scan_id, scan_options)
            self._timeline(timeline, "recon", "Passive recon, endpoint risk, TLS, and low-impact discovery completed", 92)
            api_summary = site_map.get("api_summary", {})
            behavioral_summary = self._build_behavioral_summary(site_map, findings)
            auth_summary = self._build_auth_summary(request_handler, detector_site_map)
            attack_chain_summary = self._build_attack_chain_summary(detector_site_map, findings, auth_summary)
            summary = {
                "page_count": len(site_map["pages"]),
                "form_count": len(site_map["forms"]),
                "endpoint_count": len(site_map.get("endpoints", [])),
                "finding_count": len(findings),
                "high_severity_count": sum(1 for finding in findings if finding.severity == "high"),
                "medium_severity_count": sum(1 for finding in findings if finding.severity == "medium"),
                "low_severity_count": sum(1 for finding in findings if finding.severity == "low"),
                "validated_finding_count": sum(1 for finding in findings if finding.validation_state == "validated"),
                "passive_security_score": recon_summary.get("passive_security", {}).get("score", 0),
                "open_port_count": len(recon_summary.get("port_summary", {}).get("open_ports", [])),
                "high_risk_endpoint_count": sum(1 for item in recon_summary.get("endpoint_risk_ranking", []) if int(item.get("risk_score", 0)) >= 50),
                "api_endpoint_count": api_summary.get("api_endpoint_count", 0),
                "graphql_endpoint_count": api_summary.get("graphql_endpoint_count", 0),
                "schema_modeled_endpoint_count": api_summary.get("schema_modeled_endpoint_count", 0),
                "schema_fuzz_probe_count": schema_fuzz_summary.get("probe_count", 0),
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
                "findings": finding_dicts,
                "summary": summary,
                "api_summary": api_summary,
                "schema_fuzz_summary": schema_fuzz_summary,
                "recon_summary": recon_summary,
                "behavioral_summary": behavioral_summary,
                "auth_summary": auth_summary,
                "attack_chain_summary": attack_chain_summary,
                "role_summary": self._build_role_summary(auth_context, target_url),
                "detector_timings": detector_timings,
                "detector_registry": describe_loaded_detectors(selected_detector_names),
                "target_advisory": build_target_advisory(target_url),
                "auth_used": bool(
                    auth_context
                    and (
                        auth_context.get("headers")
                        or auth_context.get("cookies")
                        or auth_context.get("jwt_token")
                        or auth_context.get("login_url")
                    )
                ),
                "safety_controls": {
                    "rate_limit_per_second": auth_context.get("rate_limit_per_second") if auth_context else settings.default_rate_limit_per_second,
                    "authorization_confirmed": bool(auth_context and auth_context.get("authorization_confirmed")),
                    "domain_allowlist": auth_context.get("domain_allowlist", []) if auth_context else [],
                },
                "scan_options": {
                    "detector_names": selected_detector_names,
                    "scan_profile": scan_options.get("scan_profile"),
                    "scan_profile_label": scan_options.get("scan_profile_label"),
                    "scan_profile_description": scan_options.get("scan_profile_description"),
                    "enable_api_fuzzing": bool(scan_options.get("enable_api_fuzzing", True)),
                    "enable_graphql_checks": bool(scan_options.get("enable_graphql_checks", True)),
                    "enable_finding_validator": bool(scan_options.get("enable_finding_validator", settings.enable_finding_validator)),
                    "enable_directory_fuzzing": bool(scan_options.get("enable_directory_fuzzing", settings.enable_directory_fuzzing)),
                    "enable_safe_port_scan": bool(scan_options.get("enable_safe_port_scan", settings.enable_safe_port_scan)),
                    "enable_subdomain_recon": bool(scan_options.get("enable_subdomain_recon", settings.enable_subdomain_recon)),
                    "enable_screenshot_recon": bool(scan_options.get("enable_screenshot_recon", settings.enable_screenshot_recon)),
                },
                "timeline": timeline,
                "resume_state": {
                    "available": True,
                    "last_completed_phase": "reporting",
                    "target_url": target_url,
                    "scan_options": scan_options,
                    "checkpoint_scan_id": scan_id,
                    "checkpoint_phases": ["crawl"],
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
            diagnostics = self._diagnose_target_url(target_url)
            if progress_callback:
                await progress_callback(
                    {
                        "event": "scan_failed",
                        "status": "failed",
                        "progress": 100,
                        "message": (
                            f"Target is unreachable: {target_url}. "
                            f"{diagnostics}"
                        ),
                    }
                )
            raise RuntimeError(
                f"Target is unreachable: {target_url}. "
                f"{diagnostics}"
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

    def scan_sync(
        self,
        target_url: str,
        auth_context: dict[str, object] | None = None,
        scan_options: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return asyncio.run(self.scan(target_url, auth_context=auth_context, scan_options=scan_options))

    @staticmethod
    def _apply_profile_to_auth_context(
        auth_context: dict[str, object] | None,
        scan_options: dict[str, object],
    ) -> dict[str, object]:
        context = dict(auth_context or {})
        if context.get("rate_limit_per_second") in {None, ""}:
            context["rate_limit_per_second"] = scan_options.get("rate_limit_per_second", settings.default_rate_limit_per_second)
        return context

    @staticmethod
    def _timeline(timeline: list[dict[str, object]], phase: str, message: str, progress: int) -> None:
        timeline.append(
            {
                "phase": phase,
                "message": message,
                "progress": progress,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    @staticmethod
    def _enrich_findings(findings: list[Finding]) -> list[Finding]:
        severity_base = {"high": 8.6, "medium": 6.1, "low": 3.8}
        confidence_mod = {"high": 0.5, "medium": 0.0, "low": -0.7}
        for finding in findings:
            confidence_score = finding.confidence_score if finding.confidence_score is not None else {"high": 0.85, "medium": 0.55, "low": 0.3}.get(finding.confidence or "medium", 0.5)
            score = severity_base.get(finding.severity, 5.0) + confidence_mod.get(finding.confidence or "medium", 0.0) + (confidence_score - 0.5)
            finding.cvss_score = round(min(10.0, max(0.1, score)), 1)
            finding.remediation_priority = "P1" if finding.cvss_score >= 8.5 else "P2" if finding.cvss_score >= 6.0 else "P3"
            if not finding.validation_state:
                finding.validation_state = "validated" if finding.confidence == "high" else "requires-review"
            cwe = map_cwe(finding.detector, finding.category)
            finding.cwe_id = cwe["cwe_id"]
            finding.cwe_title = cwe["title"]
            finding.poc = (
                f"{finding.method.upper()} {finding.url} with parameter {finding.parameter or '-'} "
                f"using payload {finding.payload or '-'}"
            )
            remediation = get_remediation(finding.detector)
            finding.owasp_category = remediation["owasp_category"]
            if not finding.recommendation or finding.recommendation == "Sanitize input.":
                finding.recommendation = remediation["fix"]
            finding.code_snippet = remediation["code_snippet"]
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
    def _build_auth_summary(request_handler: RequestHandler, site_map: dict[str, object]) -> dict[str, object]:
        session_context = request_handler.session_context
        login_performed = bool(session_context and getattr(session_context, "login_performed", False))
        cookie_count = len(getattr(session_context, "cookies", {}) or {}) if session_context else 0
        header_count = len(getattr(session_context, "headers", {}) or {}) if session_context else 0
        return {
            "login_performed": login_performed,
            "cookie_count": cookie_count,
            "header_count": header_count,
            "authenticated_forms": sum(1 for form in site_map.get("forms", []) if "login" in str(form.get("action", "")).lower()),
        }

    @staticmethod
    def _build_attack_chain_summary(site_map: dict[str, object], findings: list[Finding], auth_summary: dict[str, object]) -> dict[str, object]:
        privileged_endpoints = [
            endpoint for endpoint in site_map.get("endpoints", [])
            if isinstance(endpoint, dict) and any(token in str(endpoint.get("url", "")).lower() for token in ("/admin", "/account", "/profile", "/settings"))
        ]
        chain_candidates: list[str] = []
        if auth_summary.get("login_performed"):
            chain_candidates.append("authenticated-session-established")
        if privileged_endpoints:
            chain_candidates.append("privileged-surface-discovered")
        if any(finding.detector == "auth_bypass" for finding in findings):
            chain_candidates.append("authorization-gap-identified")
        if any(finding.detector == "sqli" for finding in findings):
            chain_candidates.append("data-access-pivot-possible")
        return {
            "candidate_count": len(chain_candidates),
            "candidates": chain_candidates,
            "privileged_endpoint_count": len(privileged_endpoints),
        }

    @staticmethod
    def _build_role_summary(auth_context: dict[str, object] | None, target_url: str) -> dict[str, object]:
        auth_context = auth_context or {}
        role_name = str(auth_context.get("role_name") or "default")
        historical = [item for item in list_scans() if item.get("target_url") == target_url]
        return {
            "role_name": role_name,
            "historical_scan_count_for_target": len(historical),
            "uses_authenticated_context": bool(
                auth_context.get("headers")
                or auth_context.get("cookies")
                or auth_context.get("jwt_token")
                or auth_context.get("login_url")
            ),
        }

    @staticmethod
    def _diagnose_target_url(target_url: str) -> str:
        host = urlparse(target_url).hostname or ""
        if host in {"127.0.0.1", "localhost"}:
            return "Ensure the local target app is running on the requested port and retry."
        return "Verify DNS, network reachability, and that the target is accepting HTTP requests."

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
