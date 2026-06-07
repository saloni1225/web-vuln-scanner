import ipaddress
import socket


# Cloud metadata endpoints that must always be blocked
_BLOCKED_METADATA_HOSTS = frozenset({
    "169.254.169.254",          # AWS/GCP/Azure IMDS
    "metadata.google.internal", # GCP metadata
    "metadata.internal",        # internal metadata alias
    "169.254.170.2",            # ECS task metadata
})

# RFC1918 + special-use ranges (SSRF blocklist)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # This network
    ipaddress.ip_network("10.0.0.0/8"),          # RFC1918 Class A
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918 Class B (172.16-31.x)
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918 Class C
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # Documentation TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # Documentation TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
    ipaddress.ip_network("::/128"),              # IPv6 unspecified
]


def _ip_is_private(ip_str: str) -> bool:
    """Return True if the resolved IP falls within any blocked network range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return True  # Fail-safe: block if unparseable


def is_private_host(url: str, resolve_dns: bool = True) -> bool:
    """
    SSRF safety check. Returns True if the URL resolves to a private/internal address.

    Checks:
    - Blocked hostname literals (metadata endpoints)
    - Known private hostname patterns (localhost, 127.0.0.1, etc.)
    - RFC1918 and special-use IP ranges via ip_network matching
    - DNS resolution to catch rebinding attacks (e.g., attacker.com -> 10.0.0.1)

    Args:
        url: Target URL to check.
        resolve_dns: If True (default), resolve hostname via DNS to check final IP.
                     Set to False only in unit tests.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower().strip()

    if not host:
        return True  # Fail-safe: block empty hosts

    # Block explicit metadata endpoints
    if host in _BLOCKED_METADATA_HOSTS:
        return True

    # Block localhost aliases
    if host in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
        return True

    # Try to parse as IP directly (handles 127.0.0.1, ::1, hex IPs, etc.)
    try:
        parsed_ip = ipaddress.ip_address(host)
        if _ip_is_private(str(parsed_ip)):
            return True
    except ValueError:
        pass  # Not a raw IP — proceed to DNS resolution

    # DNS resolution: prevent rebinding attacks (attacker.com -> 10.0.0.1)
    if resolve_dns:
        try:
            resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, _, _, _, sockaddr in resolved:
                ip = sockaddr[0]
                if _ip_is_private(ip):
                    return True
        except (socket.gaierror, OSError):
            # DNS failure: fail-safe, treat as private to prevent scanning internal services
            return True

    return False


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


def build_target_advisory(url: str) -> dict[str, object]:
    # NOTE: resolve_dns=False here — this function returns a UI advisory only.
    # Real SSRF safety enforcement (with DNS resolution) happens at scan launch time.
    is_local = is_private_host(url, resolve_dns=False)
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
