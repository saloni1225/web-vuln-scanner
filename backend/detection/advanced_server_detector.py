from __future__ import annotations

from backend.core.request_handler import RequestHandler
from backend.detection.base_detector import BaseDetector, Finding


class AdvancedServerDetector(BaseDetector):
    name = "advanced_server"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in site_map.get("endpoints", []):
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            lower = url.lower()
            params = {str(item).lower() for item in endpoint.get("query_params", []) or endpoint.get("schema_fields", [])}
            if any(token in params for token in ("url", "uri", "target", "callback", "webhook", "image", "fetch")):
                findings.append(_server_finding(url, "SSRF/blind SSRF candidate parameter requires egress-safe callback validation", "ssrf", "high"))
            if any(token in lower for token in ("upload", "file", "avatar", "import")):
                findings.append(_server_finding(url, "File upload bypass candidate requires MIME, extension, content, and storage validation", "file-upload", "high"))
            if any(token in params for token in ("path", "file", "filename", "template", "download")):
                findings.append(_server_finding(url, "Path traversal candidate parameter requires canonicalization validation", "path-traversal", "high"))
            if any(token in lower for token in ("cache", "cdn", "proxy")):
                findings.append(_server_finding(url, "Cache poisoning candidate requires header and key normalization validation", "cache-poisoning", "medium"))
            if any(token in lower for token in ("host", "redirect", "callback")):
                findings.append(_server_finding(url, "Host header attack candidate requires trusted host validation", "host-header", "medium"))
            if str(endpoint.get("type")) == "graphql" or lower.startswith("ws") or "websocket" in lower:
                findings.append(_server_finding(url, "WebSocket/GraphQL transport requires auth, origin, and message validation", "websocket-graphql", "medium"))
            if any(token in lower for token in ("transfer-encoding", "http2", "h2", "proxy")):
                findings.append(_server_finding(url, "HTTP desync/request smuggling candidate requires proxy chain validation", "request-smuggling", "high"))
            if any(token in lower for token in ("checkout", "payment", "coupon", "redeem", "order")):
                findings.append(_server_finding(url, "Race condition candidate requires concurrent replay and idempotency validation", "race-condition", "medium"))
        return _dedupe(findings)


def _server_finding(url: str, evidence: str, category: str, severity: str) -> Finding:
    return Finding(
        detector="advanced_server",
        severity=severity,
        url=url,
        evidence=evidence,
        recommendation="Validate this server-side surface with scoped safe replay, strict allowlists, canonicalization, and monitoring.",
        confidence="medium",
        category=category,
        validation_state="requires-review",
        reason="Server-side attack surface heuristic",
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
