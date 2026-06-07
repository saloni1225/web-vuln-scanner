from urllib.parse import urlparse


CWE_BY_DETECTOR = {
    "sqli": {"cwe_id": "CWE-89", "title": "Improper Neutralization of Special Elements used in an SQL Command"},
    "xss": {"cwe_id": "CWE-79", "title": "Improper Neutralization of Input During Web Page Generation"},
    "csrf": {"cwe_id": "CWE-352", "title": "Cross-Site Request Forgery"},
    "auth_bypass": {"cwe_id": "CWE-284", "title": "Improper Access Control"},
    "idor": {"cwe_id": "CWE-639", "title": "Authorization Bypass Through User-Controlled Key"},
    "ssrf": {"cwe_id": "CWE-918", "title": "Server-Side Request Forgery"},
    "api_authz": {"cwe_id": "CWE-862", "title": "Missing Authorization"},
    "graphql_authz": {"cwe_id": "CWE-285", "title": "Improper Authorization"},
    "nosql": {"cwe_id": "CWE-943", "title": "Improper Neutralization of Special Elements in Data Query Logic"},
    "ssti": {"cwe_id": "CWE-1336", "title": "Improper Neutralization of Special Elements Used in a Template Engine"},
    "xxe": {"cwe_id": "CWE-611", "title": "Improper Restriction of XML External Entity Reference"},
    "smuggling": {"cwe_id": "CWE-444", "title": "Inconsistent Interpretation of HTTP Requests"},
    "race": {"cwe_id": "CWE-362", "title": "Concurrent Execution Using Shared Resource with Improper Synchronization"},
    "cache_poison": {"cwe_id": "CWE-349", "title": "Acceptance of Extraneous Untrusted Data With Trusted Data"},
    "oauth": {"cwe_id": "CWE-601", "title": "URL Redirection to Untrusted Site"},
    "rce": {"cwe_id": "CWE-78", "title": "Improper Neutralization of Special Elements used in an OS Command"},
    "deser": {"cwe_id": "CWE-502", "title": "Deserialization of Untrusted Data"},
    "cloud_exposure": {"cwe_id": "CWE-200", "title": "Exposure of Sensitive Information to an Unauthorized Actor"},
    "openvas": {"cwe_id": "CWE-693", "title": "Protection Mechanism Failure"},
}


def normalize_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.geturl().rstrip("/")


def is_private_host(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in {"127.0.0.1", "localhost"} or host.startswith("192.168.") or host.startswith("10.") or host.startswith("172.16.")


def build_target_advisory(url: str) -> dict[str, object]:
    is_local = is_private_host(url)
    if is_local:
        return {
            "safe_for_demo": True,
            "kind": "local-or-private",
            "message": "Private targets are supported for internal validation and staging assessments.",
            "recommended_targets": ["https://staging.example.com", "https://app.example.com"],
        }
    return {
        "safe_for_demo": False,
        "kind": "external",
        "message": "Hosted targets are supported when you own them or have explicit authorization. Use the allowlist and conservative rate limits for production systems.",
        "recommended_targets": ["https://staging.example.com", "https://app.example.com"],
    }


def map_cwe(detector: str, category: str | None = None) -> dict[str, str]:
    detector_key = detector.lower()
    if detector_key in CWE_BY_DETECTOR:
        return CWE_BY_DETECTOR[detector_key]
    if category and "access" in category:
        return {"cwe_id": "CWE-284", "title": "Improper Access Control"}
    return {"cwe_id": "CWE-693", "title": "Protection Mechanism Failure"}


def map_cvss_vector(detector: str, severity: str) -> str:
    """Build CVSS v3.1 vector based on detector and classification details."""
    det = detector.lower()
    sev = severity.lower()
    
    # Defaults based on severity
    pr = "N" if sev in {"high", "critical"} else "L"
    ui = "N"
    c = "H" if sev in {"high", "critical"} else "L"
    i = "H" if sev in {"high", "critical"} else "L"
    a = "N"
    
    # Specific vulnerability categories
    if "sqli" in det or "nosql" in det or "rce" in det:
        a = "H" if sev in {"high", "critical"} else "L"
    elif "xss" in det:
        ui = "R"
        i = "L"
        c = "L"
    elif "csrf" in det:
        ui = "R"
        pr = "N"
        c = "N"
        i = "H"
        a = "N"
    elif "ssrf" in det:
        c = "H"
        i = "L"
        a = "L"
    elif "xxe" in det:
        c = "H"
        i = "N"
        a = "L"
        
    return f"CVSS:3.1/AV:N/AC:L/PR:{pr}/UI:{ui}/S:U/C:{c}/I:{i}/A:{a}"
