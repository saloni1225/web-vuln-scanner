import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.scanner_engine import ScannerEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a web vulnerability scan.")
    parser.add_argument("target_url")
    parser.add_argument("--auth-header", action="append", default=[], help="Custom auth header in KEY=VALUE format.")
    parser.add_argument("--auth-cookie", action="append", default=[], help="Session cookie in KEY=VALUE format.")
    parser.add_argument("--jwt-token", default="", help="JWT bearer token to reuse for the scan.")
    parser.add_argument("--login-url", default="", help="Optional login URL for session bootstrap.")
    parser.add_argument("--username", default="", help="Login username.")
    parser.add_argument("--password", default="", help="Login password.")
    parser.add_argument("--rate-limit", type=float, default=None, help="Requests per second.")
    parser.add_argument("--retry-attempts", type=int, default=None, help="Retry count for transient request failures.")
    args = parser.parse_args()
    auth_headers = _parse_kv_pairs(args.auth_header)
    auth_cookies = _parse_kv_pairs(args.auth_cookie)
    result = ScannerEngine().scan_sync(
        args.target_url,
        auth_context={
            "headers": auth_headers,
            "cookies": auth_cookies,
            "jwt_token": args.jwt_token,
            "login_url": args.login_url,
            "username": args.username,
            "password": args.password,
            "rate_limit_per_second": args.rate_limit,
            "retry_attempts": args.retry_attempts,
        },
    )
    print(json.dumps(result, indent=2))


def _parse_kv_pairs(items: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            parsed[key] = value
    return parsed


if __name__ == "__main__":
    main()

