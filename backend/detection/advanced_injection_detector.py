from __future__ import annotations

from backend.core.request_handler import RequestHandler
from backend.detection.base_detector import BaseDetector, Finding


class AdvancedInjectionDetector(BaseDetector):
    name = "advanced_injection"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        findings: list[Finding] = []
        for surface in _parameter_surfaces(site_map):
            joined = " ".join(surface["params"]).lower()
            url = surface["url"]
            if any(token in joined for token in ("filter", "where", "mongo", "json", "query")):
                findings.append(_finding(url, "NoSQL injection candidate parameter requires operator injection validation", "nosql-injection", "high"))
            if any(token in joined for token in ("cmd", "command", "exec", "ping", "host", "domain")):
                findings.append(_finding(url, "Command injection candidate parameter requires shell metacharacter validation", "command-injection", "high"))
            if any(token in joined for token in ("ldap", "dn", "uid", "cn")):
                findings.append(_finding(url, "LDAP injection candidate parameter requires filter escaping validation", "ldap-injection", "medium"))
            if any(token in joined for token in ("xpath", "xml", "node", "path")):
                findings.append(_finding(url, "XPath injection candidate parameter requires expression escaping validation", "xpath-injection", "medium"))
            if any(token in joined for token in ("template", "view", "render", "name", "message")):
                findings.append(_finding(url, "SSTI candidate input requires template expression validation", "ssti", "high"))
            if any(token in joined for token in ("xml", "soap", "saml", "metadata")):
                findings.append(_finding(url, "XXE candidate parser surface requires external entity hardening validation", "xxe", "high"))
            if any(token in url.lower() for token in ("deserialize", "pickle", "object", "java", "session")):
                findings.append(_finding(url, "Insecure deserialization candidate endpoint requires signed object validation", "deserialization", "high"))
        return _dedupe(findings)


def _parameter_surfaces(site_map: dict[str, object]) -> list[dict[str, object]]:
    surfaces = []
    for endpoint in site_map.get("endpoints", []):
        if isinstance(endpoint, dict):
            params = [str(item) for item in endpoint.get("query_params", []) or endpoint.get("schema_fields", []) or []]
            surfaces.append({"url": str(endpoint.get("url", "")), "params": params})
    for form in site_map.get("forms", []):
        if isinstance(form, dict):
            surfaces.append({"url": str(form.get("action", "")), "params": [str(item) for item in form.get("inputs", [])]})
    return surfaces


def _finding(url: str, evidence: str, category: str, severity: str) -> Finding:
    return Finding(
        detector="advanced_injection",
        severity=severity,
        url=url,
        evidence=evidence,
        recommendation="Use strict input allowlists, parameterized APIs, parser hardening, and targeted regression tests for this sink.",
        confidence="medium",
        category=category,
        validation_state="requires-review",
        reason="Parameter and endpoint naming heuristic",
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    deduped = []
    for finding in findings:
        key = (finding.url, finding.category)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped

