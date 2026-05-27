from __future__ import annotations

from backend.core.request_handler import RequestHandler
from backend.detection.base_detector import BaseDetector, Finding


class AdvancedClientDetector(BaseDetector):
    name = "advanced_client"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in site_map.get("endpoints", []):
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            lower = url.lower()
            params = " ".join(str(item).lower() for item in endpoint.get("query_params", []) or endpoint.get("schema_fields", []))
            if "#" in url or any(token in params for token in ("redirect", "callback", "html", "template", "returnurl", "next")):
                findings.append(_client_finding(url, "DOM XSS sink candidate requires browser taint validation", "dom-xss", "medium"))
            if any(token in params for token in ("__proto__", "constructor", "prototype", "merge", "options")):
                findings.append(_client_finding(url, "Prototype pollution candidate requires object merge validation", "prototype-pollution", "high"))
            if any(token in params for token in ("id", "name", "form", "window")):
                findings.append(_client_finding(url, "DOM clobbering candidate requires ID/name collision review", "dom-clobbering", "low"))
            if any(token in lower for token in ("comment", "review", "message", "profile")):
                findings.append(_client_finding(url, "Stored or blind XSS candidate workflow requires persistence validation", "stored-blind-xss", "medium"))
        return _dedupe(findings)


def _client_finding(url: str, evidence: str, category: str, severity: str) -> Finding:
    return Finding(
        detector="advanced_client",
        severity=severity,
        url=url,
        evidence=evidence,
        recommendation="Instrument DOM sinks, encode untrusted data by context, enforce CSP, and add browser regression tests.",
        confidence="medium",
        category=category,
        validation_state="requires-review",
        reason="SPA/client-side heuristic",
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    output = []
    for finding in findings:
        key = (finding.url, finding.category)
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output

