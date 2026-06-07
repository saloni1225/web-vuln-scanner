"""SSRF Detector — Active Server-Side Request Forgery detection.

CWE-918 · OWASP A10:2021-Server-Side Request Forgery
"""
from __future__ import annotations
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_URL_PARAM_NAMES = {
    "url", "uri", "target", "callback", "webhook", "redirect", "next",
    "return", "returnurl", "dest", "destination", "image", "img",
    "fetch", "load", "page", "feed", "host", "site", "path", "src", "source",
}

_SSRF_PROBES = [
    {"payload": "http://127.0.0.1/", "signature": "", "label": "localhost"},
    {"payload": "http://169.254.169.254/latest/meta-data/", "signature": "ami-id", "label": "aws-meta"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/", "signature": "attributes", "label": "gcp-meta"},
    {"payload": "http://[::1]/", "signature": "", "label": "ipv6-loopback"},
    {"payload": "file:///etc/passwd", "signature": "root:", "label": "file-unix"},
    {"payload": "http://0177.0.0.1/", "signature": "", "label": "octal-loopback"},
]

_INTERNAL_SIGS = [
    "ami-id", "instance-id", "local-hostname", "iam/security-credentials",
    "root:x:", "root:*:", "SSH-2", "OpenSSH", "attributes/", "169.254.169.254",
]


class SSRFDetector(BaseDetector):
    name = "ssrf"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        max_params = int(site_map.get("max_detector_params", 6) or 6)
        max_payloads = int(site_map.get("max_payloads_per_param", 2) or 2)
        tested = 0

        for endpoint in site_map.get("endpoints", []):
            if tested >= max_params:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            params = [str(p).lower() for p in endpoint.get("query_params", []) or endpoint.get("schema_fields", [])]
            url_params = [p for p in params if p in _URL_PARAM_NAMES]
            if not url_params:
                continue
            for param in url_params[:1]:
                if tested >= max_params:
                    break
                tested += 1
                pf = await self._probe_get(request_handler, analyzer, url, param, max_payloads)
                findings.extend(pf)

        for form in site_map.get("forms", []):
            if tested >= max_params:
                break
            if not isinstance(form, dict) or not self.allow_active_post_probe(form, site_map):
                continue
            action = str(form.get("action", ""))
            inputs = [str(i) for i in form.get("inputs", []) if i]
            ct = str(form.get("content_type", "form")).lower()
            url_inputs = [i for i in inputs if i.lower() in _URL_PARAM_NAMES]
            if not url_inputs or not action:
                continue
            for param in url_inputs[:1]:
                if tested >= max_params:
                    break
                tested += 1
                pf = await self._probe_post(request_handler, analyzer, action, param, inputs, ct, max_payloads)
                findings.extend(pf)

        return self._dedupe(findings)

    async def _probe_get(self, rh, analyzer, url, param, max_payloads):
        findings = []
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        baseline_url = urlunparse(parsed._replace(query=urlencode({**qs, param: "https://example.com"})))
        try:
            baseline = await rh.get(baseline_url)
        except Exception:
            return findings
        for probe in _SSRF_PROBES[:max_payloads]:
            probe_url = urlunparse(parsed._replace(query=urlencode({**qs, param: probe["payload"]})))
            try:
                response = await rh.get(probe_url)
            except Exception:
                continue
            f = self._analyze(analyzer, baseline, response, url, param, probe, "get", f"GET {probe_url}")
            if f:
                findings.append(f)
                break
        return findings

    async def _probe_post(self, rh, analyzer, action, param, inputs, ct, max_payloads):
        findings = []
        safe = {n: "baseline" for n in inputs}
        safe[param] = "https://example.com"
        try:
            baseline = await (rh.post_json(action, safe) if ct == "json" else rh.post(action, safe))
        except Exception:
            return findings
        for probe in _SSRF_PROBES[:max_payloads]:
            body = {n: "baseline" for n in inputs}
            body[param] = probe["payload"]
            try:
                response = await (rh.post_json(action, body) if ct == "json" else rh.post(action, body))
            except Exception:
                continue
            f = self._analyze(analyzer, baseline, response, action, param, probe, "post", f"POST {action} body[{param}]={probe['payload']}")
            if f:
                findings.append(f)
                break
        return findings

    def _analyze(self, analyzer, baseline, response, url, param, probe, method, snap):
        body_lower = response.text.lower()
        has_sig = False
        matched = ""
        if probe["signature"] and probe["signature"].lower() in body_lower:
            has_sig, matched = True, probe["signature"]
        else:
            for sig in _INTERNAL_SIGS:
                if sig.lower() in body_lower:
                    has_sig, matched = True, sig
                    break
        has_timing = analyzer.has_time_delay_anomaly(baseline, response, threshold_ms=2000)
        has_len = analyzer.has_length_anomaly(baseline, response)
        has_stat = analyzer.has_status_anomaly(baseline, response)
        if not has_sig and not has_timing and not (has_len and has_stat):
            return None
        kw = {"anomaly_score": analyzer.anomaly_score(baseline, response)}
        if has_sig:
            kw["error_signature"] = True
        if has_timing:
            kw["time_delay"] = True
        if has_len:
            kw["boolean_delta"] = True
        v = analyzer.classify_confidence(**kw)
        ssrf_type = "full-read" if has_sig else "blind" if has_timing else "anomaly"
        return Finding(
            detector=self.name, severity="high", url=url,
            evidence=f"SSRF ({ssrf_type}) via '{param}' with '{probe['label']}'. " + (f"Signature '{matched}' found. " if has_sig else "") + (f"Timing delta {round(response.elapsed_ms - baseline.elapsed_ms)}ms. " if has_timing else ""),
            recommendation="Implement URL allowlist for outbound requests. Block internal IP ranges and disable file:// protocol.",
            confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
            validation_signals=list(v["signals"]), parameter=param, payload=probe["payload"],
            method=method, category=f"ssrf-{ssrf_type}",
            baseline_status=baseline.status_code, mutated_status=response.status_code,
            baseline_length=len(baseline.text), mutated_length=len(response.text),
            request_snapshot=snap, response_snapshot=analyzer.snapshot_response(response),
            reason=f"Probe '{probe['label']}' triggered {ssrf_type} SSRF signal.",
            validation_state=str(v["validation_state"]),
        )

    @staticmethod
    def _dedupe(findings):
        seen, out = set(), []
        for f in findings:
            k = (f.url, f.category)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out
