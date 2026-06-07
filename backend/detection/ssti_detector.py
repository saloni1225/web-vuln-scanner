"""SSTI Detector — Server-Side Template Injection via safe math expressions.

CWE-1336 · OWASP A03:2021-Injection
"""
from __future__ import annotations
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

# Math-expression probes and their expected reflection.
_SSTI_PROBES = [
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "freemarker/velocity"),
    ("<%= 7*7 %>", "49", "erb/ejs"),
    ("#{7*7}", "49", "ruby/java-el"),
    ("{7*7}", "49", "smarty/generic"),
    ("{{7*'7'}}", "7777777", "jinja2-string-mul"),
    ("${7*7}", "49", "java-el"),
]

# Engine fingerprinting probes (safe, no RCE).
_ENGINE_PROBES = [
    ("{{config}}", "config", "jinja2"),
    ("{{settings}}", "settings", "django"),
    ("${.now}", "20", "freemarker"),
    ("{{_self.env}}", "twig", "twig"),
    ("<%= self.class %>", "class", "erb"),
]

_SSTI_PARAM_HINTS = {"template", "view", "render", "name", "message", "content", "text", "title", "body", "subject", "greeting", "email", "comment", "desc", "description", "q", "search", "query"}


class SSTIDetector(BaseDetector):
    name = "ssti"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        max_params = int(site_map.get("max_detector_params", 6) or 6)
        max_payloads = int(site_map.get("max_payloads_per_param", 2) or 2)
        tested = 0

        # GET endpoints
        for endpoint in site_map.get("endpoints", []):
            if tested >= max_params:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            params = [str(p) for p in endpoint.get("query_params", []) or endpoint.get("schema_fields", [])]
            targets = [p for p in params if p.lower() in _SSTI_PARAM_HINTS]
            if not targets:
                continue
            for param in targets[:1]:
                if tested >= max_params:
                    break
                tested += 1
                pf = await self._probe_get(request_handler, analyzer, url, param, max_payloads)
                findings.extend(pf)

        # POST forms
        for form in site_map.get("forms", []):
            if tested >= max_params:
                break
            if not isinstance(form, dict) or not self.allow_active_post_probe(form, site_map):
                continue
            action = str(form.get("action", ""))
            inputs = [str(i) for i in form.get("inputs", []) if i]
            ct = str(form.get("content_type", "form")).lower()
            targets = [i for i in inputs if i.lower() in _SSTI_PARAM_HINTS]
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

        for payload, expected, engine in _SSTI_PROBES[:max_payloads]:
            test_url = urlunparse(parsed._replace(query=urlencode({**qs, param: payload})))
            try:
                response = await rh.get(test_url)
            except Exception:
                continue
            if expected in response.text and expected not in baseline.text:
                # Confirmed SSTI — try engine fingerprinting
                detected_engine = await self._fingerprint_engine(rh, parsed, qs, param, max_payloads)
                v = analyzer.classify_confidence(dangerous_reflection=True, anomaly_score=0.8)
                findings.append(Finding(
                    detector=self.name, severity="high", url=url,
                    evidence=f"SSTI confirmed: '{payload}' evaluated to '{expected}' in response. Engine: {detected_engine or engine}.",
                    recommendation="Never pass user input directly to template engines. Use sandboxed rendering with strict variable allowlists.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=param, payload=payload,
                    method="get", category="ssti", baseline_status=baseline.status_code,
                    mutated_status=response.status_code, baseline_length=len(baseline.text),
                    mutated_length=len(response.text), request_snapshot=f"GET {test_url}",
                    response_snapshot=analyzer.snapshot_response(response),
                    reason=f"Template expression '{payload}' was evaluated server-side.", validation_state=str(v["validation_state"]),
                ))
                break
        return findings

    async def _probe_post(self, rh, analyzer, action, param, inputs, ct, max_payloads):
        findings = []
        safe = {n: "baseline" for n in inputs}
        try:
            baseline = await (rh.post_json(action, safe) if ct == "json" else rh.post(action, safe))
        except Exception:
            return findings

        for payload, expected, engine in _SSTI_PROBES[:max_payloads]:
            body = {n: "baseline" for n in inputs}
            body[param] = payload
            try:
                response = await (rh.post_json(action, body) if ct == "json" else rh.post(action, body))
            except Exception:
                continue
            if expected in response.text and expected not in baseline.text:
                v = analyzer.classify_confidence(dangerous_reflection=True, anomaly_score=0.8)
                findings.append(Finding(
                    detector=self.name, severity="high", url=action,
                    evidence=f"SSTI confirmed: '{payload}' evaluated to '{expected}'. Engine hint: {engine}.",
                    recommendation="Never pass user input to template engines. Use sandboxed rendering.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=param, payload=payload,
                    method="post", category="ssti", baseline_status=baseline.status_code,
                    mutated_status=response.status_code, baseline_length=len(baseline.text),
                    mutated_length=len(response.text), request_snapshot=f"POST {action} body[{param}]={payload}",
                    response_snapshot=analyzer.snapshot_response(response),
                    reason=f"Template expression evaluated server-side.", validation_state=str(v["validation_state"]),
                ))
                break
        return findings

    async def _fingerprint_engine(self, rh, parsed, qs, param, max_payloads):
        for probe, sig, engine in _ENGINE_PROBES[:max_payloads]:
            test_url = urlunparse(parsed._replace(query=urlencode({**qs, param: probe})))
            try:
                resp = await rh.get(test_url)
                if sig.lower() in resp.text.lower():
                    return engine
            except Exception:
                continue
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
