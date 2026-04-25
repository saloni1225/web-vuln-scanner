import argparse
import json

from backend.core.scanner_engine import ScannerEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a web vulnerability scan.")
    parser.add_argument("target_url")
    parser.add_argument("--auth-header", action="append", default=[], help="Custom auth header in KEY=VALUE format.")
    parser.add_argument("--auth-cookie", action="append", default=[], help="Session cookie in KEY=VALUE format.")
    args = parser.parse_args()
    auth_headers = _parse_kv_pairs(args.auth_header)
    auth_cookies = _parse_kv_pairs(args.auth_cookie)
    result = ScannerEngine().scan_sync(args.target_url, auth_context={"headers": auth_headers, "cookies": auth_cookies})
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

