import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.scanner_engine import ScannerEngine
from backend.core.risk_gate import evaluate_risk_gate
from backend.reports.report_generator import generate_html_report


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
    parser.add_argument("--profile", default="deep", choices=["quick", "deep", "passive", "api", "stealth", "authenticated"], help="Scan profile.")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with code 2 when high severity findings exceed the allowed count.")
    parser.add_argument("--max-high", type=int, default=0, help="Allowed high severity findings when --fail-on-high is enabled.")
    parser.add_argument("--max-medium", type=int, default=None, help="Optional allowed medium severity findings.")
    parser.add_argument("--max-total", type=int, default=None, help="Optional allowed total findings.")
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
        scan_options={"scan_profile": args.profile},
    )
    result["risk_gate"] = evaluate_risk_gate(
        result.get("summary", {}),
        fail_on_high=args.fail_on_high,
        max_high=args.max_high,
        max_medium=args.max_medium,
        max_total=args.max_total,
    )
    html_path = generate_html_report(result)
    result["report_path"] = str(html_path)
    print(json.dumps(result, indent=2))
    if args.fail_on_high and not result["risk_gate"]["passed"]:
        sys.exit(2)


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

