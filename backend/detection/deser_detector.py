"""Deserialization Detector — Unsafe deserialization detection via error signatures.

CWE-502 · OWASP A08:2021
"""
from __future__ import annotations
import base64
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

# Serialization magic bytes and headers
_DESER_PROBES = [
    {"label": "java-rO0", "payload": "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtj+5Q==", "sigs": ["classnotfoundexception", "java.io.invalidclassexception", "java.io.objectinputstream", "java.lang.classcastexception", "deseriali"]},
    {"label": "python-pickle", "payload": base64.b64encode(b"\x80\x04\x95\x0f\x00\x00\x00\x00\x00\x00\x00\x8c\x04test\x94.").decode(), "sigs": ["unpicklingerror", "pickle", "_pickle", "insecure string pickle", "could not deseriali"]},
    {"label": "php-object", "payload": 'O:8:"stdClass":0:{}', "sigs": ["unserialize()", "__wakeup", "__destruct", "allowed classes", "could not convert"]},
    {"label": "dotnet-viewstate", "payload": "/wEPDwULLTE2MTY2MzMzMzk=", "sigs": ["viewstate", "system.web", "invalid viewstate", "mac validation failed"]},
    {"label": "yaml-unsafe", "payload": "!!python/object/apply:os.system ['echo test']", "sigs": ["yaml.constructor", "could not determine", "yaml.scanner", "found character"]},
]

_DESER_PATH_HINTS = ("/api", "/rest", "/data", "/import", "/upload", "/process", "/decode", "/parse")
_DESER_PARAM_HINTS = {"data", "payload", "object", "session", "token", "state", "viewstate", "serialized", "encoded", "input", "body"}


class DeserDetector(BaseDetector):
    name = "deser"

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
            targets = [p for p in params if p.lower() in _DESER_PARAM_HINTS]
            is_api = any(h in url.lower() for h in _DESER_PATH_HINTS)
            if not targets and not is_api:
                continue
            tested += 1
            pf = await self._probe_endpoint(request_handler, analyzer, url, targets[:1] or ["data"], max_payloads)
            findings.extend(pf)

        for form in site_map.get("forms", []):
            if tested >= max_params:
                break
            if not isinstance(form, dict) or not self.allow_active_post_probe(form, site_map):
                continue
            action = str(form.get("action", ""))
            inputs = [str(i) for i in form.get("inputs", []) if i]
            targets = [i for i in inputs if i.lower() in _DESER_PARAM_HINTS]
            if not targets or not action:
                continue
            tested += 1
            pf = await self._probe_post(request_handler, analyzer, action, targets[0], inputs, max_payloads)
            findings.extend(pf)

        return self._dedupe(findings)

    async def _probe_endpoint(self, rh, analyzer, url, params, max_payloads):
        findings = []
        try:
            baseline = await rh.get(url)
        except Exception:
            return findings

        param = params[0] if params else "data"
        for probe in _DESER_PROBES[:max_payloads]:
            try:
                resp = await rh.request_json("POST", url, data={param: probe["payload"]})
            except Exception:
                continue
            body_lower = resp.text.lower()
            matched_sigs = [s for s in probe["sigs"] if s.lower() in body_lower]
            if matched_sigs:
                v = analyzer.classify_confidence(error_signature=True, anomaly_score=0.7)
                findings.append(Finding(
                    detector=self.name, severity="high", url=url,
                    evidence=f"Insecure deserialization ({probe['label']}): error signatures [{', '.join(matched_sigs[:3])}] detected.",
                    recommendation="Never deserialize untrusted data. Use safe formats (JSON). Implement integrity checks (HMAC) on serialized objects.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=param, payload=probe["label"],
                    method="post", category=f"deser-{probe['label']}", baseline_status=baseline.status_code,
                    mutated_status=resp.status_code, baseline_length=len(baseline.text),
                    mutated_length=len(resp.text), request_snapshot=f"POST {url} ({probe['label']})",
                    response_snapshot=analyzer.snapshot_response(resp),
                    reason=f"Deserialization probe '{probe['label']}' exposed error signature.", validation_state=str(v["validation_state"]),
                ))
                break
        return findings

    async def _probe_post(self, rh, analyzer, action, param, inputs, max_payloads):
        findings = []
        safe = {n: "baseline" for n in inputs}
        try:
            baseline = await rh.post(action, safe)
        except Exception:
            return findings

        for probe in _DESER_PROBES[:max_payloads]:
            body = {n: "baseline" for n in inputs}
            body[param] = probe["payload"]
            try:
                resp = await rh.post(action, body)
            except Exception:
                continue
            body_lower = resp.text.lower()
            matched = [s for s in probe["sigs"] if s.lower() in body_lower]
            if matched:
                v = analyzer.classify_confidence(error_signature=True, anomaly_score=0.7)
                findings.append(Finding(
                    detector=self.name, severity="high", url=action,
                    evidence=f"Insecure deserialization ({probe['label']}) on form field '{param}': [{', '.join(matched[:3])}].",
                    recommendation="Never deserialize untrusted data. Use JSON and implement HMAC integrity checks.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter=param, payload=probe["label"],
                    method="post", category=f"deser-{probe['label']}", baseline_status=baseline.status_code,
                    mutated_status=resp.status_code, baseline_length=len(baseline.text),
                    mutated_length=len(resp.text), request_snapshot=f"POST {action} body[{param}]={probe['label']}",
                    response_snapshot=analyzer.snapshot_response(resp),
                    reason=f"Deser probe exposed error signature.", validation_state=str(v["validation_state"]),
                ))
                break
        return findings

    @staticmethod
    def _dedupe(findings):
        seen, out = set(), []
        for f in findings:
            k = (f.url, f.category)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out
