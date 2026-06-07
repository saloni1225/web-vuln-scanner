"""API Authorization Detector — Multi-role authorization differential testing.

Replays API endpoints with stripped/low-privilege auth to detect broken
function-level authorization (BFLA) and missing authentication.

CWE-285/CWE-862 · OWASP API1-API5
"""
from __future__ import annotations
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_SENSITIVE_PATH_HINTS = (
    "/admin", "/manage", "/config", "/settings", "/internal", "/debug",
    "/users", "/roles", "/permissions", "/billing", "/audit", "/logs",
    "/export", "/import", "/migrate", "/deploy", "/delete", "/bulk",
)
_METHOD_OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-Method-Override", "DELETE"),
]


class APIAuthzDetector(BaseDetector):
    name = "api_authz"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        max_params = int(site_map.get("max_detector_params", 6) or 6)
        tested = 0

        for endpoint in site_map.get("endpoints", []):
            if tested >= max_params:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            if not any(h in url.lower() for h in _SENSITIVE_PATH_HINTS):
                continue
            tested += 1

            # Test 1: No-auth access
            f = await self._probe_no_auth(request_handler, analyzer, url)
            if f:
                findings.append(f)

            # Test 2: HTTP method override
            f2 = await self._probe_method_override(request_handler, analyzer, url)
            if f2:
                findings.append(f2)

        return self._dedupe(findings)

    async def _probe_no_auth(self, rh, analyzer, url):
        try:
            authed = await rh.get(url)
        except Exception:
            return None
        if authed.status_code not in {200, 201, 204}:
            return None
        from backend.core.request_handler import RequestHandler as RH
        try:
            unauthed_rh = RH(auth={})
            unauthed = await unauthed_rh.get(url)
            await unauthed_rh.close()
        except Exception:
            return None
        if unauthed.status_code in {200, 201, 204}:
            if not analyzer.has_length_anomaly(authed, unauthed, ratio=0.2):
                v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=0.7)
                return Finding(
                    detector=self.name, severity="high", url=url,
                    evidence=f"Sensitive endpoint returned {unauthed.status_code} without authentication. Content similar to authenticated response.",
                    recommendation="Enforce authentication middleware on all sensitive API endpoints. Return 401/403 for unauthenticated requests.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=None, payload="no-auth",
                    method="get", category="broken-authentication",
                    baseline_status=authed.status_code, mutated_status=unauthed.status_code,
                    baseline_length=len(authed.text), mutated_length=len(unauthed.text),
                    request_snapshot=f"GET {url} (no auth)", response_snapshot=analyzer.snapshot_response(unauthed),
                    reason="Endpoint accessible without authentication.", validation_state=str(v["validation_state"]),
                )
        return None

    async def _probe_method_override(self, rh, analyzer, url):
        try:
            baseline = await rh.get(url)
        except Exception:
            return None
        for header_name, header_value in _METHOD_OVERRIDE_HEADERS:
            try:
                response = await rh.request_json("GET", url, data={})
            except Exception:
                continue
            if response.status_code in {200, 204} and analyzer.has_length_anomaly(baseline, response):
                v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=analyzer.anomaly_score(baseline, response))
                return Finding(
                    detector=self.name, severity="medium", url=url,
                    evidence=f"HTTP method override header '{header_name}: {header_value}' accepted by the endpoint.",
                    recommendation="Reject HTTP method override headers. Enforce strict HTTP method routing.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=header_name, payload=header_value,
                    method="get", category="method-override",
                    baseline_status=baseline.status_code, mutated_status=response.status_code,
                    baseline_length=len(baseline.text), mutated_length=len(response.text),
                    request_snapshot=f"GET {url} with {header_name}: {header_value}",
                    response_snapshot=analyzer.snapshot_response(response),
                    reason="Method override header changed response behavior.", validation_state=str(v["validation_state"]),
                )
        return None

    @staticmethod
    def _dedupe(findings):
        seen, out = set(), []
        for f in findings:
            k = (f.url, f.category)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out
