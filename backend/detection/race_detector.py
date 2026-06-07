"""Race Condition Detector — Concurrent replay for TOCTOU / limit-check bypass.

CWE-362 · OWASP A04:2021 — Only runs when allow_state_changing_fuzz is enabled.
"""
from __future__ import annotations
import asyncio
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_RACE_PATH_HINTS = (
    "/checkout", "/payment", "/pay", "/transfer", "/send", "/withdraw",
    "/coupon", "/redeem", "/voucher", "/discount", "/apply",
    "/vote", "/like", "/follow", "/subscribe", "/confirm", "/order",
)
_CONCURRENT_COPIES = 5


class RaceDetector(BaseDetector):
    name = "race"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        # Safety gate: only test when state-changing fuzz is explicitly allowed
        if not site_map.get("allow_state_changing_fuzz"):
            return []

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
            method = str(endpoint.get("method", "get")).lower()
            if not any(h in url.lower() for h in _RACE_PATH_HINTS):
                continue
            tested += 1

            # Test with concurrent GET/POST replay
            f = await self._probe_race(request_handler, analyzer, url, method)
            if f:
                findings.append(f)

        return self._dedupe(findings)

    async def _probe_race(self, rh, analyzer, url, method):
        # Get baseline (single request)
        try:
            baseline = await rh.get(url)
        except Exception:
            return None

        # Send concurrent copies
        async def _single_request():
            try:
                return await rh.get(url)
            except Exception:
                return None

        tasks = [_single_request() for _ in range(_CONCURRENT_COPIES)]
        responses = await asyncio.gather(*tasks)
        valid = [r for r in responses if r is not None]

        if len(valid) < 3:
            return None

        # Analyze: count how many got 200 (success)
        success_count = sum(1 for r in valid if r.status_code in {200, 201, 204})
        error_count = sum(1 for r in valid if r.status_code in {409, 429, 400, 403})

        # If all concurrent requests succeeded when at most one should → race condition
        if success_count >= _CONCURRENT_COPIES - 1 and error_count == 0:
            # Check if responses are identical (suggests no race) or different (suggests race)
            lengths = [len(r.text) for r in valid]
            unique_lengths = len(set(lengths))

            if unique_lengths <= 1:
                # All identical — might just be idempotent
                return None

            v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=0.65)
            return Finding(
                detector=self.name, severity="medium", url=url,
                evidence=f"Race condition candidate: {success_count}/{len(valid)} concurrent requests succeeded with {unique_lengths} distinct response sizes.",
                recommendation="Implement idempotency keys, database-level locks, or atomic check-and-update operations for business-critical endpoints.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter=None, payload=f"concurrent-{_CONCURRENT_COPIES}",
                method="get", category="race-condition", baseline_status=baseline.status_code,
                mutated_status=valid[0].status_code, baseline_length=len(baseline.text),
                mutated_length=len(valid[0].text),
                request_snapshot=f"GET {url} x{_CONCURRENT_COPIES} concurrent",
                response_snapshot=analyzer.snapshot_response(valid[0]),
                reason=f"Concurrent replay produced divergent responses without conflict errors.",
                validation_state=str(v["validation_state"]),
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
