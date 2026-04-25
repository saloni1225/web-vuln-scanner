from urllib.parse import urlparse


CWE_BY_DETECTOR = {
    "sqli": {"cwe_id": "CWE-89", "title": "Improper Neutralization of Special Elements used in an SQL Command"},
    "xss": {"cwe_id": "CWE-79", "title": "Improper Neutralization of Input During Web Page Generation"},
    "csrf": {"cwe_id": "CWE-352", "title": "Cross-Site Request Forgery"},
    "auth_bypass": {"cwe_id": "CWE-284", "title": "Improper Access Control"},
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
            "message": "Local or private targets are the safest way to validate the scanner during development.",
            "recommended_targets": ["http://127.0.0.1:3000", "http://localhost:3000"],
        }
    return {
        "safe_for_demo": False,
        "kind": "external",
        "message": "Use explicit authorization before scanning external production systems. Prefer a local lab such as OWASP Juice Shop.",
        "recommended_targets": ["http://127.0.0.1:3000", "http://localhost:3000"],
    }


def map_cwe(detector: str, category: str | None = None) -> dict[str, str]:
    detector_key = detector.lower()
    if detector_key in CWE_BY_DETECTOR:
        return CWE_BY_DETECTOR[detector_key]
    if category and "access" in category:
        return {"cwe_id": "CWE-284", "title": "Improper Access Control"}
    return {"cwe_id": "CWE-693", "title": "Protection Mechanism Failure"}
