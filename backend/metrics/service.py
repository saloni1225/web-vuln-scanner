from __future__ import annotations


def platform_metrics(scans: list[dict[str, object]]) -> dict[str, object]:
    return {
        "scan_count": len(scans),
        "finding_count": sum(int(scan.get("findings_count", 0) or 0) for scan in scans),
        "high_count": sum(int(scan.get("high_severity_count", 0) or 0) for scan in scans),
        "endpoint_count": sum(int(scan.get("endpoint_count", 0) or 0) for scan in scans),
        "risk_gate_failures": sum(1 for scan in scans if scan.get("risk_gate_status") == "failed"),
    }

