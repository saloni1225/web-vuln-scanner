"""Web Cache Poisoning Detector — Unkeyed header injection + cache key analysis.

CWE-349 · Emerging OWASP category.
"""
from __future__ import annotations
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_CANARY = "awvs-cache-canary-7x3q"

_UNKEYED_HEADERS = [
    ("X-Forwarded-Host", f"{_CANARY}.example.com"),
    ("X-Original-URL", f"/{_CANARY}"),
    ("X-Rewrite-URL", f"/{_CANARY}"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Host", f"{_CANARY}.example.com"),
]


class CachePoisonDetector(BaseDetector):
    name = "cache_poison"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []

        # Test on cacheable pages (homepage + discovered pages)
        pages = [target_url] + [str(p) for p in site_map.get("pages", [])[:3]]
        tested = 0
        max_params = int(site_map.get("max_detector_params", 6) or 6)

        for page_url in pages:
            if tested >= max_params:
                break
            tested += 1

            for header_name, header_value in _UNKEYED_HEADERS[:2]:
                f = await self._probe_cache(request_handler, analyzer, page_url, header_name, header_value)
                if f:
                    findings.append(f)
                    break

        return self._dedupe(findings)

    async def _probe_cache(self, rh, analyzer, url, header_name, header_value):
        # Step 1: Normal request (baseline)
        try:
            baseline = await rh.get(url)
        except Exception:
            return None

        # Check if response indicates caching
        cache_headers = {k.lower(): v for k, v in baseline.headers.items()}
        has_cache = any(k in cache_headers for k in ("x-cache", "cf-cache-status", "age", "x-varnish", "x-cdn"))
        has_vary = "vary" in cache_headers

        # Step 2: Request with unkeyed header (poison attempt)
        try:
            poisoned = await rh.request_json("GET", url, data={})
        except Exception:
            return None

        # Step 3: Check if canary appears in poisoned response
        canary_reflected = _CANARY in poisoned.text

        # Step 4: Re-request normally to check if cache was poisoned
        if canary_reflected:
            try:
                recheck = await rh.get(url)
            except Exception:
                return None

            if _CANARY in recheck.text:
                # Cache was actually poisoned
                v = analyzer.classify_confidence(dangerous_reflection=True, stable_reflection=True, anomaly_score=0.85)
                return Finding(
                    detector=self.name, severity="high", url=url,
                    evidence=f"Cache poisoning confirmed: header '{header_name}' with value '{header_value}' was cached and served to subsequent requests.",
                    recommendation="Ensure CDN/cache keys include all headers that influence response. Add Vary headers. Sanitize forwarded headers.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=header_name, payload=header_value,
                    method="get", category="cache-poisoning-confirmed", baseline_status=baseline.status_code,
                    mutated_status=recheck.status_code, baseline_length=len(baseline.text),
                    mutated_length=len(recheck.text),
                    request_snapshot=f"GET {url} with {header_name}: {header_value}",
                    response_snapshot=analyzer.snapshot_response(recheck),
                    reason="Injected header value persisted in cache.", validation_state=str(v["validation_state"]),
                )
            else:
                v = analyzer.classify_confidence(dangerous_reflection=True, anomaly_score=0.5)
                return Finding(
                    detector=self.name, severity="medium", url=url,
                    evidence=f"Unkeyed header reflection: '{header_name}' reflected in response but not cached. Potential cache poisoning vector.",
                    recommendation="Add the reflected header to cache key or strip it at the edge. Review Vary header configuration.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=header_name, payload=header_value,
                    method="get", category="cache-poisoning-candidate", baseline_status=baseline.status_code,
                    mutated_status=poisoned.status_code, baseline_length=len(baseline.text),
                    mutated_length=len(poisoned.text),
                    request_snapshot=f"GET {url} with {header_name}: {header_value}",
                    response_snapshot=analyzer.snapshot_response(poisoned),
                    reason="Unkeyed header reflected in response.", validation_state=str(v["validation_state"]),
                )

        # Check missing Vary headers on cacheable responses
        if has_cache and not has_vary:
            v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=0.3)
            return Finding(
                detector=self.name, severity="low", url=url,
                evidence="Cached response missing Vary header. Cache key may not account for request headers that influence response.",
                recommendation="Add appropriate Vary headers (Host, Accept-Encoding, etc.) to cached responses.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter="Vary", payload="missing",
                method="get", category="cache-missing-vary", baseline_status=baseline.status_code,
                mutated_status=baseline.status_code, baseline_length=len(baseline.text),
                mutated_length=len(baseline.text),
                request_snapshot=f"GET {url}",
                response_snapshot=analyzer.snapshot_response(baseline),
                reason="No Vary header on cached response.", validation_state=str(v["validation_state"]),
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
