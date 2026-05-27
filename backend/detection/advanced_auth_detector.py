from __future__ import annotations

from backend.core.request_handler import RequestHandler
from backend.detection.base_detector import BaseDetector, Finding


class AdvancedAuthDetector(BaseDetector):
    name = "advanced_auth"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        findings: list[Finding] = []
        for form in site_map.get("forms", []):
            if not isinstance(form, dict):
                continue
            action = str(form.get("action", ""))
            fields = {str(item).lower() for item in form.get("inputs", [])}
            if "password" in fields:
                findings.append(_auth_finding(action, "Login flow requires MFA, brute-force, session fixation, and CSRF validation", "mfa-session", "medium"))
            if any(token in fields for token in ("redirect", "return", "next", "callback")):
                findings.append(_auth_finding(action, "OAuth/OIDC redirect candidate requires allowlist and state validation", "oauth", "high"))
        for endpoint in site_map.get("endpoints", []):
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            lower = url.lower()
            params = {str(item).lower() for item in endpoint.get("query_params", []) or endpoint.get("schema_fields", [])}
            if any(token in lower for token in ("/user/", "/account", "/profile", "/tenant", "/workspace")) or {"id", "user_id", "account_id"} & params:
                findings.append(_auth_finding(url, "IDOR/BOLA candidate requires role-differential authorization validation", "idor", "high"))
            if any(token in lower for token in ("/admin", "/role", "/permission", "/rbac")):
                findings.append(_auth_finding(url, "RBAC bypass candidate requires privilege differential testing", "rbac-bypass", "high"))
            if "jwt" in lower or "token" in params:
                findings.append(_auth_finding(url, "JWT handling requires alg, expiry, audience, issuer, and key rotation validation", "jwt", "medium"))
        return _dedupe(findings)


def _auth_finding(url: str, evidence: str, category: str, severity: str) -> Finding:
    return Finding(
        detector="advanced_auth",
        severity=severity,
        url=url,
        evidence=evidence,
        recommendation="Enforce server-side authorization, strong session lifecycle controls, MFA policy, and role-based regression tests.",
        confidence="medium",
        category=category,
        validation_state="requires-review",
        reason="Authenticated workflow heuristic",
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

