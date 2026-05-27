import asyncio

from backend.detection.advanced_auth_detector import AdvancedAuthDetector
from backend.detection.advanced_client_detector import AdvancedClientDetector
from backend.detection.advanced_injection_detector import AdvancedInjectionDetector
from backend.detection.advanced_server_detector import AdvancedServerDetector
from backend.detection.registry import describe_loaded_detectors


def test_advanced_detector_registry_families_are_enabled():
    names = {item["name"] for item in describe_loaded_detectors()}
    assert {"advanced_injection", "advanced_client", "advanced_auth", "advanced_server"}.issubset(names)


def test_advanced_detector_families_emit_reviewable_findings():
    site_map = {
        "endpoints": [
            {"url": "https://example.com/api/search", "query_params": ["filter", "cmd", "url", "id", "template", "xml"], "schema_fields": []},
            {"url": "https://example.com/admin/roles", "query_params": ["user_id", "token"], "schema_fields": []},
            {"url": "https://example.com/upload", "query_params": ["filename"], "schema_fields": []},
            {"url": "https://example.com/#/callback", "query_params": ["redirect", "__proto__"], "schema_fields": []},
            {"url": "https://example.com/cache/proxy/http2", "query_params": ["target"], "schema_fields": []},
            {"url": "https://example.com/checkout/redeem", "query_params": ["coupon"], "schema_fields": []},
            {"url": "https://example.com/api/deserialize/session", "query_params": ["object"], "schema_fields": []},
        ],
        "forms": [{"action": "https://example.com/login", "inputs": ["email", "password", "next"]}],
    }
    detectors = [AdvancedInjectionDetector(), AdvancedClientDetector(), AdvancedAuthDetector(), AdvancedServerDetector()]
    findings = []
    for detector in detectors:
        findings.extend(asyncio.run(detector.detect("https://example.com", site_map, request_handler=None)))
    categories = {finding.category for finding in findings}
    assert {
        "nosql-injection",
        "command-injection",
        "ssti",
        "xxe",
        "deserialization",
        "prototype-pollution",
        "dom-clobbering",
        "oauth",
        "jwt",
        "idor",
        "rbac-bypass",
        "ssrf",
        "file-upload",
        "path-traversal",
        "cache-poisoning",
        "request-smuggling",
        "race-condition",
    }.issubset(categories)
    assert all(finding.validation_state == "requires-review" for finding in findings)
