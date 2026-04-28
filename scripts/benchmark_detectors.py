import argparse
import asyncio
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.scanner_engine import ScannerEngine


BENCHMARK_TARGETS = {
    "juice-shop": {
        "url": "http://127.0.0.1:3000",
        "profile": "deep",
        "expected_surface": {"pages": 1, "endpoints": 3},
    },
    "local-api": {
        "url": "http://127.0.0.1:8000",
        "profile": "api",
        "expected_surface": {"pages": 1, "endpoints": 2},
    },
}


async def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark detector coverage against authorized vulnerable targets.")
    parser.add_argument("--target", choices=sorted(BENCHMARK_TARGETS), default="juice-shop")
    parser.add_argument("--url", default="", help="Override benchmark URL.")
    parser.add_argument("--output", default="benchmark-results.json")
    args = parser.parse_args()

    config = dict(BENCHMARK_TARGETS[args.target])
    if args.url:
        config["url"] = args.url

    engine = ScannerEngine()
    result = await engine.scan(
        str(config["url"]),
        auth_context={"authorization_confirmed": True, "domain_allowlist": []},
        scan_options={"scan_profile": config["profile"]},
    )
    summary = result.get("summary", {})
    expected = config.get("expected_surface", {})
    benchmark = {
        "target": args.target,
        "url": config["url"],
        "profile": config["profile"],
        "summary": summary,
        "detector_timings": result.get("detector_timings", []),
        "passed_surface_baseline": (
            int(summary.get("page_count", 0)) >= int(expected.get("pages", 0))
            and int(summary.get("endpoint_count", 0)) >= int(expected.get("endpoints", 0))
        ),
    }
    Path(args.output).write_text(json.dumps(benchmark, indent=2), encoding="utf-8")
    print(json.dumps(benchmark, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
