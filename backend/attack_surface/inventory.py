from __future__ import annotations

from urllib.parse import urlparse


def build_attack_surface_inventory(scan: dict[str, object]) -> dict[str, object]:
    target = str(scan.get("target_url", ""))
    host = urlparse(target).hostname or target
    endpoints = [item for item in scan.get("endpoints", []) if isinstance(item, dict)]
    findings = [item for item in scan.get("findings", []) if isinstance(item, dict)]
    assets = [
        {"asset_id": f"web:{host}", "type": "web-app", "name": host, "criticality": "high", "exposure": "internet-facing"}
    ]
    for endpoint in endpoints[:100]:
        assets.append(
            {
                "asset_id": f"endpoint:{endpoint.get('url')}",
                "type": str(endpoint.get("type") or "endpoint"),
                "name": str(endpoint.get("url") or ""),
                "criticality": _endpoint_criticality(str(endpoint.get("url", ""))),
                "exposure": "public-http",
            }
        )
    return {
        "asset_count": len(assets),
        "internet_facing_count": len(assets),
        "high_risk_asset_count": sum(1 for asset in assets if asset["criticality"] == "high"),
        "assets": assets,
        "exposure_timeline": [
            {
                "scan_id": scan.get("scan_id"),
                "finished_at": scan.get("finished_at"),
                "asset_count": len(assets),
                "finding_count": len(findings),
            }
        ],
        "drift": {
            "status": "baseline-created",
            "new_assets": len(assets),
            "removed_assets": 0,
        },
    }


def compare_endpoint_history(current_scan: dict[str, object], previous_scans: list[dict[str, object]]) -> dict[str, object]:
    target = current_scan.get("target_url")
    current = {
        str(item.get("url", ""))
        for item in current_scan.get("endpoints", [])
        if isinstance(item, dict) and item.get("url")
    }
    previous = set()
    for scan in previous_scans:
        if scan.get("target_url") != target:
            continue
        for endpoint in scan.get("endpoints", []) if isinstance(scan.get("endpoints"), list) else []:
            if isinstance(endpoint, dict) and endpoint.get("url"):
                previous.add(str(endpoint["url"]))
    return {
        "target_url": target,
        "current_endpoint_count": len(current),
        "previous_endpoint_count": len(previous),
        "new_endpoints": sorted(current - previous)[:100],
        "removed_endpoints": sorted(previous - current)[:100],
        "drift_detected": bool((current - previous) or (previous - current)),
    }


def _endpoint_criticality(url: str) -> str:
    lower = url.lower()
    if any(token in lower for token in ("/admin", "/graphql", "/swagger", "/openapi", "/upload")):
        return "high"
    if any(token in lower for token in ("/api", "/account", "/profile")):
        return "medium"
    return "low"
