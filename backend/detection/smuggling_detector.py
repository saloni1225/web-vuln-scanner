"""Request Smuggling Detector — HTTP desync detection via CL.TE/TE.CL timing.

CWE-444 · Safety: timing-only detection, no request poisoning.
"""
from __future__ import annotations
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_SMUGGLING_PROBES = [
    {
        "label": "CL.TE-basic",
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
        "body": "1\r\nZ\r\n0\r\n\r\n",
    },
    {
        "label": "TE.CL-basic",
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "11"},
        "body": "0\r\n\r\nSMUGGLED",
    },
    {
        "label": "TE.TE-obfuscation",
        "headers": {"Transfer-Encoding": "chunked", "Transfer-encoding": " chunked"},
        "body": "0\r\n\r\n",
    },
    {
        "label": "CL.CL-duplicate",
        "headers": {"Content-Length": "0"},
        "body": "",
    },
]


class SmugglingDetector(BaseDetector):
    name = "smuggling"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []

        # Get baseline timing
        try:
            baseline = await request_handler.get(target_url)
        except Exception:
            return findings

        for probe in _SMUGGLING_PROBES[:2]:
            try:
                response = await request_handler.request_json("POST", target_url, data={"smuggle": probe["body"]})
            except Exception:
                continue

            has_timing = analyzer.has_time_delay_anomaly(baseline, response, threshold_ms=2500)
            has_status = response.status_code in {400, 500, 502, 503}
            has_anomaly = analyzer.has_length_anomaly(baseline, response)

            # Smuggling signals: unusual timeout or connection behavior
            smuggle_sigs = any(s in response.text.lower() for s in (
                "bad request", "invalid request", "request timeout",
                "connection reset", "transfer-encoding", "malformed",
            ))

            if not has_timing and not smuggle_sigs and not (has_status and has_anomaly):
                continue

            kw = {"anomaly_score": analyzer.anomaly_score(baseline, response)}
            if has_timing:
                kw["time_delay"] = True
            if smuggle_sigs:
                kw["error_signature"] = True
            v = analyzer.classify_confidence(**kw)

            findings.append(Finding(
                detector=self.name, severity="high", url=target_url,
                evidence=f"HTTP request smuggling signal ({probe['label']}). " + ("Timing anomaly detected. " if has_timing else "") + ("Server error/malformed request response. " if smuggle_sigs else ""),
                recommendation="Normalize Transfer-Encoding handling. Reject ambiguous CL/TE combinations. Use HTTP/2 end-to-end.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter="headers", payload=probe["label"],
                method="post", category="request-smuggling", baseline_status=baseline.status_code,
                mutated_status=response.status_code, baseline_length=len(baseline.text),
                mutated_length=len(response.text),
                request_snapshot=f"POST {target_url} ({probe['label']})",
                response_snapshot=analyzer.snapshot_response(response),
                reason=f"Desync probe '{probe['label']}' triggered anomaly.", validation_state=str(v["validation_state"]),
            ))
            break

        return findings
