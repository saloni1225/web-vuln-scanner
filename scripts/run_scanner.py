import argparse
import json

from backend.core.scanner_engine import ScannerEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a web vulnerability scan.")
    parser.add_argument("target_url")
    args = parser.parse_args()
    result = ScannerEngine().scan_sync(args.target_url)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

