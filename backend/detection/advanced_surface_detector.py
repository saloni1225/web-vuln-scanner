from __future__ import annotations

from backend.core.request_handler import RequestHandler
from backend.detection.base_detector import BaseDetector, Finding


class AdvancedSurfaceDetector(BaseDetector):
    name = "advanced_surface"

    async def detect(
        self,
        target_url: str,
        site_map: dict[str, object],
        request_handler: RequestHandler,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = [item for item in site_map.get("endpoints", []) if isinstance(item, dict)]
        forms = [item for item in site_map.get("forms", []) if isinstance(item, dict)]
        urls = [str(item.get("url", "")) for item in endpoints]

        for url in urls:
            lower = url.lower()
            if "graphql" in lower:
                findings.append(self._review_finding(url, "GraphQL endpoint requires schema and authorization review", "api", "medium"))
            if "swagger" in lower or "openapi" in lower:
                findings.append(self._review_finding(url, "Public API schema endpoint exposes attack surface metadata", "api", "medium"))
            if any(token in lower for token in ("/admin", "/console", "/manage")):
                findings.append(self._review_finding(url, "Administrative route discovered during crawl", "authorization", "medium"))
            if "upload" in lower:
                findings.append(self._review_finding(url, "File upload surface requires MIME, extension, and storage validation", "server-side", "medium"))
            if lower.startswith("ws:") or lower.startswith("wss:") or "websocket" in lower:
                findings.append(self._review_finding(url, "WebSocket surface requires origin, auth, and message validation review", "advanced", "medium"))

        for form in forms:
            action = str(form.get("action", target_url))
            fields = " ".join(str(field) for field in form.get("fields", [])).lower()
            if any(token in fields for token in ("redirect", "return", "next", "url")):
                findings.append(self._review_finding(action, "Redirect-like form input may support OAuth or open redirect abuse paths", "auth", "low"))
            if "password" in fields and not any(str(item.get("name", "")).lower() in {"csrf", "csrf_token", "_token"} for item in form.get("inputs", []) if isinstance(item, dict)):
                findings.append(self._review_finding(action, "Authentication form should be reviewed for CSRF, MFA, rate limit, and session fixation controls", "auth", "medium"))

        return self._dedupe(findings)

    @staticmethod
    def _review_finding(url: str, evidence: str, category: str, severity: str) -> Finding:
        return Finding(
            detector="advanced_surface",
            severity=severity,
            url=url,
            evidence=evidence,
            recommendation="Validate authorization, input handling, rate limits, and monitoring for this exposed surface.",
            confidence="medium",
            category=category,
            validation_state="requires-review",
            reason="Passive attack surface heuristic",
        )

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.url, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique
