from __future__ import annotations


def build_scan_telemetry(scan: dict[str, object]) -> dict[str, object]:
    summary = scan.get("summary", {}) if isinstance(scan.get("summary"), dict) else {}
    timeline = [item for item in scan.get("timeline", []) if isinstance(item, dict)]
    detector_timings = [item for item in scan.get("detector_timings", []) if isinstance(item, dict)]
    return {
        "status": "completed" if scan.get("finished_at") else "running",
        "duration_ms": summary.get("duration_ms", 0),
        "events": timeline,
        "detector_timings": detector_timings,
        "throughput": {
            "pages": summary.get("page_count", 0),
            "endpoints": summary.get("endpoint_count", 0),
            "schema_probes": summary.get("schema_fuzz_probe_count", 0),
        },
        "live_channels": ["/api/ws/scans", f"/api/ws/scans/{scan.get('scan_id')}"],
    }

