from urllib.parse import urlparse


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
