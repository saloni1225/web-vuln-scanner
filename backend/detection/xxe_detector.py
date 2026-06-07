"""XXE Detector — XML External Entity injection on XML-accepting endpoints.

CWE-611 · OWASP A05:2021-Security Misconfiguration
"""
from __future__ import annotations
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_XXE_CANARY = "AWVS_XXE_CANARY_9f3a"

# Safe XXE payloads — no external network calls, only internal entity expansion.
_XXE_PAYLOADS = [
    {
        "label": "internal-entity",
        "body": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "{_XXE_CANARY}">]><root><data>&xxe;</data></root>',
        "canary": _XXE_CANARY,
    },
    {
        "label": "parameter-entity",
        "body": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe "{_XXE_CANARY}"><!ENTITY canary "%xxe;">]><root><data>&canary;</data></root>',
        "canary": _XXE_CANARY,
    },
    {
        "label": "entity-expansion",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "AAAA"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><root><data>&c;</data></root>',
        "canary": "AAAA" * 16,
    },
    {
        "label": "cdata-probe",
        "body": f'<?xml version="1.0"?><root><![CDATA[{_XXE_CANARY}]]></root>',
        "canary": _XXE_CANARY,
    },
]

_SAFE_XML_BODY = '<?xml version="1.0"?><root><data>baseline</data></root>'

_XML_CONTENT_TYPES = {"application/xml", "text/xml", "application/soap+xml", "application/xhtml+xml"}
_XML_PARAM_HINTS = {"xml", "soap", "saml", "metadata", "config", "data", "payload", "body", "request"}


class XXEDetector(BaseDetector):
    name = "xxe"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        max_params = int(site_map.get("max_detector_params", 6) or 6)
        max_payloads = int(site_map.get("max_payloads_per_param", 2) or 2)
        tested = 0

        # Find endpoints that accept XML
        for endpoint in site_map.get("endpoints", []):
            if tested >= max_params:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            ct = str(endpoint.get("content_type", "")).lower()
            params = " ".join(str(p).lower() for p in endpoint.get("query_params", []) or endpoint.get("schema_fields", []))
            is_xml = ct in _XML_CONTENT_TYPES or any(h in url.lower() for h in ("xml", "soap", "saml", "wsdl")) or any(h in params for h in _XML_PARAM_HINTS)
            if not is_xml:
                continue
            tested += 1
            pf = await self._probe_xml_endpoint(request_handler, analyzer, url, max_payloads)
            findings.extend(pf)

        # Also check forms with XML-like content types
        for form in site_map.get("forms", []):
            if tested >= max_params:
                break
            if not isinstance(form, dict) or not self.allow_active_post_probe(form, site_map):
                continue
            action = str(form.get("action", ""))
            ct = str(form.get("content_type", "")).lower()
            inputs_str = " ".join(str(i).lower() for i in form.get("inputs", []))
            is_xml = ct in _XML_CONTENT_TYPES or any(h in action.lower() for h in ("xml", "soap")) or any(h in inputs_str for h in _XML_PARAM_HINTS)
            if not is_xml or not action:
                continue
            tested += 1
            pf = await self._probe_xml_endpoint(request_handler, analyzer, action, max_payloads)
            findings.extend(pf)

        return self._dedupe(findings)

    async def _probe_xml_endpoint(self, rh, analyzer, url, max_payloads):
        findings = []
        # Get baseline with safe XML
        try:
            baseline = await rh.request_json("POST", url, data={"xml": _SAFE_XML_BODY})
        except Exception:
            return findings

        for probe in _XXE_PAYLOADS[:max_payloads]:
            try:
                response = await rh.request_json("POST", url, data={"xml": probe["body"]})
            except Exception:
                continue

            # Check for canary reflection
            has_canary = probe["canary"] in response.text
            # Check for error signatures indicating XML parsing
            xml_errors = any(s in response.text.lower() for s in (
                "xml parsing error", "saxparseexception", "xmlsyntaxerror",
                "lxml.etree", "expat", "org.xml.sax", "javax.xml",
                "simplexml_load", "domdocument", "entity", "dtd",
            ))
            has_timing = analyzer.has_time_delay_anomaly(baseline, response, threshold_ms=2000)

            if not has_canary and not xml_errors and not has_timing:
                continue

            kw = {"anomaly_score": analyzer.anomaly_score(baseline, response)}
            if has_canary:
                kw["dangerous_reflection"] = True
            if xml_errors:
                kw["error_signature"] = True
            if has_timing:
                kw["time_delay"] = True
            v = analyzer.classify_confidence(**kw)

            xxe_type = "entity-reflected" if has_canary else "parser-error" if xml_errors else "timing-based"
            findings.append(Finding(
                detector=self.name, severity="high", url=url,
                evidence=f"XXE ({xxe_type}) detected via '{probe['label']}' payload." + (f" Canary '{probe['canary'][:20]}...' reflected." if has_canary else "") + (" XML parser error exposed." if xml_errors else ""),
                recommendation="Disable external entity processing in XML parsers. Use defusedxml (Python), set FEATURE_SECURE_PROCESSING (Java), or libxml_disable_entity_loader (PHP).",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter="xml-body", payload=probe["label"],
                method="post", category=f"xxe-{xxe_type}", baseline_status=baseline.status_code,
                mutated_status=response.status_code, baseline_length=len(baseline.text),
                mutated_length=len(response.text), request_snapshot=f"POST {url} (XXE payload: {probe['label']})",
                response_snapshot=analyzer.snapshot_response(response),
                reason=f"XXE probe '{probe['label']}' triggered {xxe_type} signal.", validation_state=str(v["validation_state"]),
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
