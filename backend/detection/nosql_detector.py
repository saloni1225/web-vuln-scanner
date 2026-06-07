"""NoSQL Injection Detector — Active operator and JS injection testing.

CWE-943 · OWASP A03:2021-Injection
"""
from __future__ import annotations
import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_NOSQL_PAYLOADS_GET = [
    ("[$gt]=", "operator-gt"),
    ("[$ne]=null", "operator-ne"),
    ("[$regex]=.*", "operator-regex"),
    ("'; return true; var x='", "js-injection-true"),
    ("'; return false; var x='", "js-injection-false"),
    ('{"$gt":""}', "json-operator-gt"),
    ("true, $where: '1'=='1'", "where-tautology"),
]

_NOSQL_PAYLOADS_JSON = [
    ({"$gt": ""}, {"$lt": ""}, "operator-gt-lt"),
    ({"$ne": None}, {"$eq": None}, "operator-ne-eq"),
    ({"$regex": ".*"}, {"$regex": "^$"}, "regex-wildcard"),
]

_NOSQL_PARAM_HINTS = {"filter", "where", "query", "search", "find", "mongo", "json", "q", "id", "username", "email", "password", "user", "name"}


class NoSQLDetector(BaseDetector):
    name = "nosql"

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
            targets = [p for p in params if p.lower() in _NOSQL_PARAM_HINTS]
            if not targets:
                continue
            for param in targets[:1]:
                if tested >= max_params:
                    break
                tested += 1
                pf = await self._probe_get(request_handler, analyzer, url, param, max_payloads)
                findings.extend(pf)

        # POST forms (JSON bodies)
        for form in site_map.get("forms", []):
            if tested >= max_params:
                break
            if not isinstance(form, dict) or not self.allow_active_post_probe(form, site_map):
                continue
            action = str(form.get("action", ""))
            inputs = [str(i) for i in form.get("inputs", []) if i]
            ct = str(form.get("content_type", "form")).lower()
            targets = [i for i in inputs if i.lower() in _NOSQL_PARAM_HINTS]
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
        baseline_url = urlunparse(parsed._replace(query=urlencode({**qs, param: "baseline"})))
        try:
            baseline = await rh.get(baseline_url)
        except Exception:
            return findings

        for payload_str, label in _NOSQL_PAYLOADS_GET[:max_payloads]:
            test_qs = urlencode({**qs, param: payload_str})
            test_url = urlunparse(parsed._replace(query=test_qs))
            try:
                response = await rh.get(test_url)
            except Exception:
                continue
            f = self._check(analyzer, baseline, response, url, param, payload_str, label, "get", f"GET {test_url}")
            if f:
                findings.append(f)
                break
        return findings

    async def _probe_post(self, rh, analyzer, action, param, inputs, ct, max_payloads):
        findings = []
        safe = {n: "baseline" for n in inputs}
        try:
            baseline = await (rh.post_json(action, safe) if ct == "json" else rh.post(action, safe))
        except Exception:
            return findings

        if ct == "json":
            for truthy, falsy, label in _NOSQL_PAYLOADS_JSON[:max_payloads]:
                body_t = {n: "baseline" for n in inputs}
                body_f = {n: "baseline" for n in inputs}
                body_t[param] = truthy
                body_f[param] = falsy
                try:
                    resp_t = await rh.post_json(action, body_t)
                    resp_f = await rh.post_json(action, body_f)
                except Exception:
                    continue
                if analyzer.has_boolean_response_delta(baseline, resp_t, resp_f):
                    v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=analyzer.anomaly_score(baseline, resp_t))
                    findings.append(Finding(
                        detector=self.name, severity="high", url=action,
                        evidence=f"NoSQL boolean injection on '{param}' via {label}. Truthy/falsy operator payloads produced divergent responses.",
                        recommendation="Use parameterized queries, sanitize operator keys, reject $ prefixed fields in user input.",
                        confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                        validation_signals=list(v["signals"]), parameter=param, payload=json.dumps(truthy),
                        method="post", category="nosql-boolean", baseline_status=baseline.status_code,
                        mutated_status=resp_t.status_code, baseline_length=len(baseline.text),
                        mutated_length=len(resp_t.text), request_snapshot=f"POST {action} body[{param}]={json.dumps(truthy)}",
                        response_snapshot=analyzer.snapshot_response(resp_t),
                        reason="Operator injection caused boolean response divergence.", validation_state=str(v["validation_state"]),
                    ))
                    break
        else:
            for payload_str, label in _NOSQL_PAYLOADS_GET[:max_payloads]:
                body = {n: "baseline" for n in inputs}
                body[param] = payload_str
                try:
                    response = await rh.post(action, body)
                except Exception:
                    continue
                f = self._check(analyzer, baseline, response, action, param, payload_str, label, "post", f"POST {action} body[{param}]={payload_str}")
                if f:
                    findings.append(f)
                    break
        return findings

    def _check(self, analyzer, baseline, response, url, param, payload, label, method, snap):
        has_err = analyzer.has_error_signature(response)
        has_stat = analyzer.has_status_anomaly(baseline, response)
        has_len = analyzer.has_length_anomaly(baseline, response)
        nosql_sigs = any(s in response.text.lower() for s in ("mongoerror", "bson", "objectid", "casteerror", "validationerror", "e11000", "writeerror"))
        if not has_err and not nosql_sigs and not (has_stat and has_len):
            return None
        kw = {"anomaly_score": analyzer.anomaly_score(baseline, response)}
        if has_err or nosql_sigs:
            kw["error_signature"] = True
        if has_len:
            kw["boolean_delta"] = True
        v = analyzer.classify_confidence(**kw)
        return Finding(
            detector=self.name, severity="high", url=url,
            evidence=f"NoSQL injection signal on '{param}' via {label}." + (" MongoDB error signature detected." if nosql_sigs else ""),
            recommendation="Use parameterized queries, sanitize operator keys, reject $ prefixed fields.",
            confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
            validation_signals=list(v["signals"]), parameter=param, payload=payload,
            method=method, category="nosql-injection", baseline_status=baseline.status_code,
            mutated_status=response.status_code, baseline_length=len(baseline.text),
            mutated_length=len(response.text), request_snapshot=snap,
            response_snapshot=analyzer.snapshot_response(response),
            reason=f"NoSQL payload '{label}' triggered error/anomaly.", validation_state=str(v["validation_state"]),
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
