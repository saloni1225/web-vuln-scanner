from __future__ import annotations


PAYLOAD_CATEGORIES = {
    "injection": ["sqli", "blind-sqli", "nosql", "ldap", "xpath", "ssti", "command", "xxe"],
    "client_side": ["reflected-xss", "stored-xss", "dom-xss", "prototype-pollution", "dom-clobbering"],
    "auth": ["jwt", "oauth", "session-fixation", "weak-cookies", "mfa"],
    "server_side": ["ssrf", "request-smuggling", "cache-poisoning", "path-traversal", "file-upload"],
    "api": ["bola", "mass-assignment", "rate-limit", "graphql-introspection"],
}


def payload_catalog() -> dict[str, object]:
    return {
        "categories": PAYLOAD_CATEGORIES,
        "safety": "Payloads are executed through bounded detectors, scan profiles, and explicit authorization controls.",
        "coverage_count": sum(len(items) for items in PAYLOAD_CATEGORIES.values()),
    }

