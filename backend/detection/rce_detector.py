"""Safe RCE Detector — Command injection via timing and canary probes.

CWE-78 · OWASP A03:2021 — No destructive commands, only timing + read-only canaries.
"""
from __future__ import annotations
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_RCE_PARAM_HINTS = {"cmd", "command", "exec", "ping", "host", "domain", "ip", "target", "run", "shell", "process", "system", "query", "path", "file", "dir"}

# Safe canary payloads — no destructive operations.
_RCE_CANARY_PROBES = [
    ("; echo AWVS_RCE_49", "AWVS_RCE_49", "unix-echo"),
    ("| echo AWVS_RCE_49", "AWVS_RCE_49", "pipe-echo"),
    ("`echo AWVS_RCE_49`", "AWVS_RCE_49", "backtick-echo"),
    ("$(echo AWVS_RCE_49)", "AWVS_RCE_49", "subshell-echo"),
    ("& echo AWVS_RCE_49", "AWVS_RCE_49", "ampersand-echo"),
]

_RCE_TIMING_PROBES = [
    ("; sleep 5", "unix-sleep"),
    ("| timeout /t 5 /nobreak", "win-timeout"),
    ("`sleep 5`", "backtick-sleep"),
    ("$(sleep 5)", "subshell-sleep"),
    ("& ping -c 5 127.0.0.1", "ping-delay"),
]

_RCE_ENV_PROBES = [
    ("$(expr 41 + 1)", "42", "expr-math"),
    ("${PATH}", "/usr", "env-path-unix"),
]


class RCEDetector(BaseDetector):
    name = "rce"

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
            params = [str(p) for p in endpoint.get("query_params", []) or endpoint.get("schema_fields", [])]
            targets = [p for p in params if p.lower() in _RCE_PARAM_HINTS]
            if not targets:
                continue
            for param in targets[:1]:
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
            targets = [i for i in inputs if i.lower() in _RCE_PARAM_HINTS]
            if not targets or not action:
                continue
            for param in targets[:1]:
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
        try:
            baseline = await rh.get(url)
        except Exception:
            return findings

        # Canary probes
        for payload, canary, label in _RCE_CANARY_PROBES[:max_payloads]:
            test_url = urlunparse(parsed._replace(query=urlencode({**qs, param: payload})))
            try:
                resp = await rh.get(test_url)
            except Exception:
                continue
            if canary in resp.text and canary not in baseline.text:
                v = analyzer.classify_confidence(dangerous_reflection=True, anomaly_score=0.9)
                findings.append(self._build_finding(url, param, payload, label, "canary-reflected", resp, baseline, v, "get", test_url))
                return findings

        # Timing probes
        for payload, label in _RCE_TIMING_PROBES[:max_payloads]:
            test_url = urlunparse(parsed._replace(query=urlencode({**qs, param: payload})))
            try:
                resp = await rh.get(test_url)
            except Exception:
                continue
            if analyzer.has_time_delay_anomaly(baseline, resp, threshold_ms=3500):
                v = analyzer.classify_confidence(time_delay=True, anomaly_score=0.8)
                findings.append(self._build_finding(url, param, payload, label, "timing-based", resp, baseline, v, "get", test_url))
                return findings

        # Env/math probes
        for payload, expected, label in _RCE_ENV_PROBES[:max_payloads]:
            test_url = urlunparse(parsed._replace(query=urlencode({**qs, param: payload})))
            try:
                resp = await rh.get(test_url)
            except Exception:
                continue
            if expected in resp.text and expected not in baseline.text:
                v = analyzer.classify_confidence(dangerous_reflection=True, anomaly_score=0.75)
                findings.append(self._build_finding(url, param, payload, label, "env-leak", resp, baseline, v, "get", test_url))
                return findings

        return findings

    async def _probe_post(self, rh, analyzer, action, param, inputs, ct, max_payloads):
        findings = []
        safe = {n: "baseline" for n in inputs}
        try:
            baseline = await (rh.post_json(action, safe) if ct == "json" else rh.post(action, safe))
        except Exception:
            return findings

        for payload, canary, label in _RCE_CANARY_PROBES[:max_payloads]:
            body = {n: "baseline" for n in inputs}
            body[param] = payload
            try:
                resp = await (rh.post_json(action, body) if ct == "json" else rh.post(action, body))
            except Exception:
                continue
            if canary in resp.text and canary not in baseline.text:
                v = analyzer.classify_confidence(dangerous_reflection=True, anomaly_score=0.9)
                findings.append(self._build_finding(action, param, payload, label, "canary-reflected", resp, baseline, v, "post", f"POST {action} body[{param}]={payload}"))
                return findings

        return findings

    def _build_finding(self, url, param, payload, label, rce_type, response, baseline, v, method, snap):
        return Finding(
            detector=self.name, severity="high", url=url,
            evidence=f"RCE ({rce_type}) detected via '{param}' with '{label}' payload.",
            recommendation="Never pass user input to system commands. Use safe APIs, allowlists, and sandboxed execution.",
            confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
            validation_signals=list(v["signals"]), parameter=param, payload=payload,
            method=method, category=f"rce-{rce_type}", baseline_status=baseline.status_code,
            mutated_status=response.status_code, baseline_length=len(baseline.text),
            mutated_length=len(response.text), request_snapshot=snap,
            response_snapshot=ResponseAnalyzer().snapshot_response(response),
            reason=f"RCE probe '{label}' triggered {rce_type} signal.", validation_state=str(v["validation_state"]),
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
