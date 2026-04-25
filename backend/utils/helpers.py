from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.geturl().rstrip("/")


def build_target_advisory(url: str) -> dict[str, object]:
    host = urlparse(url).hostname or ""
    is_local = host in {"127.0.0.1", "localhost"} or host.startswith("192.168.") or host.startswith("10.")
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
