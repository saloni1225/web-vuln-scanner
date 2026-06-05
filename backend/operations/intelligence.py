from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from backend.attack_surface.graph import build_attack_surface_graph, build_drift_timeline, correlate_attack_paths
from backend.ai.offensive_intelligence import build_offensive_ai_intelligence
from backend.exposure.intelligence import aggregate_exposure
from backend.metrics.service import platform_metrics


def build_operations_intelligence(scans: list[dict[str, object]]) -> dict[str, object]:
    """Shape scan evidence into product-level offensive operations workstreams."""
    metrics = platform_metrics(scans)
    exposure = aggregate_exposure(scans)
    drift = build_drift_timeline(scans)
    graph = _latest_graph(scans)
    attack_paths = _attack_paths(scans)
    assets = _asset_rows(scans)
    technologies = _technology_rows(scans)
    exposure_feed = _exposure_feed(scans)
    research_feed = _research_feed(scans, drift)
    threat_feed = _threat_feed(scans, technologies)
    api_operations = _api_operations(scans)
    offensive_ai = build_offensive_ai_intelligence(scans)

    high_count = int(metrics.get("high_count", 0) or 0)
    finding_count = int(metrics.get("finding_count", 0) or 0)
    endpoint_count = int(metrics.get("endpoint_count", 0) or 0)
    risk_failures = int(metrics.get("risk_gate_failures", 0) or 0)
    score = int(exposure.get("score", 0) or max(0, 100 - min(85, high_count * 5 + risk_failures * 10)))

    return {
        "executive": {
            "organization_exposure_score": score,
            "posture": _posture(score),
            "internet_facing_risk": high_count + risk_failures,
            "operational_insights": _operational_insights(metrics, exposure, drift, attack_paths),
            "trend": drift.get("timeline", [])[-8:],
        },
        "attack_surface": {
            "asset_count": len(assets),
            "endpoint_count": endpoint_count,
            "graph": graph,
            "assets": assets,
            "service_topology": _service_topology(scans),
            "cloud_exposure": _cloud_exposure(scans),
        },
        "exposure_operations": {
            "feed": exposure_feed,
            "ranking": sorted(exposure_feed, key=lambda item: int(item["priority_score"]), reverse=True)[:25],
            "heatmap": exposure.get("highest_risk", {}).get("heatmap", []) if isinstance(exposure.get("highest_risk"), dict) else [],
            "auth_exposure": _auth_exposure(scans),
        },
        "offensive_research": {
            "feed": research_feed,
            "newly_exposed_assets": [item for item in research_feed if item["type"] == "new-asset"][:10],
            "attack_path_changes": [item for item in research_feed if item["type"] == "attack-path"][:10],
            "suspicious_drift": [item for item in research_feed if item["type"] == "drift"][:10],
        },
        "threat_intelligence": {
            "feed": threat_feed,
            "technology_exposure": technologies,
            "exploit_correlation": _exploit_correlation(scans),
            "ai_exploitability": offensive_ai.get("exploitability_predictions", [])[:25],
        },
        "api_security_operations": api_operations,
        "ai_offensive_intelligence": offensive_ai,
        "attack_path_analysis": {
            "paths": attack_paths[:50],
            "confidence": offensive_ai.get("attack_path_confidence", []),
            "privilege_escalation_candidates": _privilege_escalation_candidates(attack_paths),
            "risk_propagation": _risk_propagation(graph, attack_paths),
        },
        "drift_intelligence": {
            "timeline": drift.get("timeline", []),
            "drift_event_count": drift.get("drift_event_count", 0),
            "exposure_spikes": _exposure_spikes(drift),
            "api_drift": _api_drift(scans),
            "auth_drift": _auth_drift(scans),
        },
        "continuous_monitoring": {
            "drift": drift,
            "telemetry_stream": _telemetry_stream(scans, metrics),
            "coverage": {
                "recurring_monitoring_ready": True,
                "scans_observed": metrics.get("scan_count", 0),
                "assets_under_monitoring": len(assets),
            },
        },
        "findings_validation": {
            "validated_findings": finding_count,
            "exploitability_queue": attack_paths[:15],
            "attack_chain_correlation": len(attack_paths),
        },
        "operational_telemetry": {
            "stream": _telemetry_stream(scans, metrics),
            "worker_events": _worker_events(scans),
            "alerts": _operational_alerts(metrics, drift, attack_paths),
            "notifications": _notifications(metrics, drift, attack_paths),
        },
    }


def _latest_graph(scans: list[dict[str, object]]) -> dict[str, object]:
    if not scans:
        return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0, "attack_paths": []}
    latest = scans[0]
    graph = latest.get("attack_surface_graph")
    built = graph if isinstance(graph, dict) else build_attack_surface_graph(latest)
    if isinstance(built, dict):
        return built
    return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0, "attack_paths": []}


def _attack_paths(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    paths: list[dict[str, object]] = []
    for scan in scans[:25]:
        graph = scan.get("attack_surface_graph") if isinstance(scan.get("attack_surface_graph"), dict) else build_attack_surface_graph(scan)
        if not isinstance(graph, dict):
            continue
        for path in correlate_attack_paths(scan, graph):
            paths.append({**path, "target_url": scan.get("target_url"), "scan_id": scan.get("scan_id")})
    return sorted(paths, key=lambda item: int(item.get("risk_score", 0) or 0), reverse=True)


def _asset_rows(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    by_host: dict[str, dict[str, object]] = {}
    for scan in scans:
        host = urlparse(str(scan.get("target_url", ""))).hostname or str(scan.get("target_url", "unknown"))
        row = by_host.setdefault(host, {"asset": host, "scan_count": 0, "finding_count": 0, "high_count": 0, "endpoint_count": 0, "last_seen": ""})
        row["scan_count"] = int(row["scan_count"]) + 1
        row["finding_count"] = int(row["finding_count"]) + int(scan.get("findings_count", 0) or 0)
        row["high_count"] = int(row["high_count"]) + int(scan.get("high_severity_count", 0) or 0)
        row["endpoint_count"] = int(row["endpoint_count"]) + int(scan.get("endpoint_count", 0) or 0)
        row["last_seen"] = str(scan.get("finished_at") or scan.get("started_at") or row["last_seen"])
    for row in by_host.values():
        row["exposure"] = "Internet-facing"
        row["priority_score"] = min(100, int(row["high_count"]) * 20 + int(row["finding_count"]) * 3 + int(row["endpoint_count"]))
    return sorted(by_host.values(), key=lambda item: int(item["priority_score"]), reverse=True)


def _service_topology(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    topology = Counter()
    for scan in scans:
        for service in scan.get("open_services", []) or scan.get("services", []) or []:
            if isinstance(service, dict):
                topology[str(service.get("service") or service.get("name") or service.get("port") or "unknown")] += 1
            else:
                topology[str(service)] += 1
    if not topology:
        topology.update({"HTTP": len(scans), "API Gateway": sum(int(scan.get("api_endpoint_count", 0) or 0) for scan in scans)})
    return [{"service": key, "asset_count": value} for key, value in topology.most_common(10)]


def _cloud_exposure(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    candidates = []
    for scan in scans:
        for item in scan.get("cloud_assets", []) or scan.get("cloud_exposure", []) or []:
            if isinstance(item, dict):
                candidates.append(item)
    if candidates:
        return candidates[:25]
    return [
        {"provider": "cloud", "surface": "public storage and CDN candidates", "status": "monitoring-ready"},
        {"provider": "identity", "surface": "federated auth boundaries", "status": "correlation-ready"},
    ]


def _exposure_feed(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    feed = []
    for scan in scans[:50]:
        target = str(scan.get("target_url", "unknown"))
        score = min(100, int(scan.get("high_severity_count", 0) or 0) * 25 + int(scan.get("medium_severity_count", 0) or 0) * 8 + int(scan.get("high_risk_endpoint_count", 0) or 0) * 5)
        feed.append({
            "target": target,
            "type": "internet-exposure",
            "priority_score": score,
            "reason": "Validated findings and risky externally reachable endpoints",
            "status": scan.get("risk_gate_status") or "monitored",
        })
    return feed


def _auth_exposure(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for scan in scans:
        auth_count = int(scan.get("auth_finding_count", 0) or 0)
        idor_count = sum(1 for finding in scan.get("findings", []) if isinstance(finding, dict) and str(finding.get("category", "")).lower() in {"idor", "bola", "rbac-bypass", "oauth", "jwt"})
        if auth_count or idor_count:
            rows.append({"target": scan.get("target_url"), "auth_signals": auth_count + idor_count, "focus": "identity boundary validation"})
    return rows[:25]


def _research_feed(scans: list[dict[str, object]], drift: dict[str, object]) -> list[dict[str, object]]:
    feed = []
    for event in drift.get("timeline", []) or []:
        if event.get("drift_detected"):
            feed.append({"type": "drift", "title": "Suspicious surface drift", "target": event.get("target_url"), "signal": f"{event.get('new_endpoint_count', 0)} new endpoints"})
        if int(event.get("new_endpoint_count", 0) or 0) > 0:
            feed.append({"type": "new-asset", "title": "Newly exposed surface", "target": event.get("target_url"), "signal": "endpoint expansion"})
    for path in _attack_paths(scans)[:10]:
        feed.append({"type": "attack-path", "title": str(path.get("name", "Attack path changed")), "target": path.get("target_url"), "signal": f"risk {path.get('risk_score', 0)}"})
    return feed[:50]


def _technology_rows(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    counts = Counter()
    for scan in scans:
        for tech in scan.get("technologies", []) or scan.get("technology_fingerprints", []) or []:
            if isinstance(tech, dict):
                counts[str(tech.get("name") or tech.get("technology") or "unknown")] += 1
            else:
                counts[str(tech)] += 1
    return [{"technology": key, "asset_count": value, "exposure": "internet-facing"} for key, value in counts.most_common(15)]


def _threat_feed(scans: list[dict[str, object]], technologies: list[dict[str, object]]) -> list[dict[str, object]]:
    feed = []
    for tech in technologies[:10]:
        feed.append({"type": "technology", "title": f"{tech['technology']} exposure", "severity": "medium", "asset_count": tech["asset_count"]})
    for scan in scans[:10]:
        if int(scan.get("high_severity_count", 0) or 0) > 0:
            feed.append({"type": "exploitability", "title": "High-severity exposure requires exploit validation", "severity": "high", "target": scan.get("target_url")})
    return feed


def _exploit_correlation(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for scan in scans[:25]:
        high = int(scan.get("high_severity_count", 0) or 0)
        if high:
            rows.append({"target": scan.get("target_url"), "exploitability": "elevated", "signals": high, "recommended_action": "validate exploit chain and owner"})
    return rows


def _api_operations(scans: list[dict[str, object]]) -> dict[str, object]:
    rows = []
    for scan in scans:
        rows.append({
            "target": scan.get("target_url"),
            "rest_endpoints": int(scan.get("api_endpoint_count", 0) or 0),
            "graphql_endpoints": int(scan.get("graphql_endpoint_count", 0) or 0),
            "schema_probes": int(scan.get("schema_fuzz_probe_count", 0) or 0),
            "sensitive_endpoints": int(scan.get("high_risk_endpoint_count", 0) or 0),
        })
    return {
        "inventory": rows,
        "sensitive_endpoint_count": sum(item["sensitive_endpoints"] for item in rows),
        "graphql_surface_count": sum(item["graphql_endpoints"] for item in rows),
        "undocumented_api_candidates": sum(1 for item in rows if item["rest_endpoints"] and not item["schema_probes"]),
        "api_drift_candidates": _api_drift(scans),
    }


def _telemetry_stream(scans: list[dict[str, object]], metrics: dict[str, object]) -> list[dict[str, object]]:
    stream = [
        {"event": "surface-indexed", "value": metrics.get("endpoint_count", 0), "status": "live"},
        {"event": "findings-correlated", "value": metrics.get("finding_count", 0), "status": "ready"},
        {"event": "risk-gates-evaluated", "value": metrics.get("risk_gate_failures", 0), "status": "enforced"},
    ]
    for scan in scans[:5]:
        stream.append({"event": "scan-finished", "value": scan.get("target_url"), "status": scan.get("risk_gate_status") or "complete"})
    return stream


def _privilege_escalation_candidates(paths: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "name": path.get("name"),
            "risk_score": path.get("risk_score", 0),
            "reason": "Path crosses API, auth, admin, or data-access boundaries.",
        }
        for path in paths
        if any(token in " ".join(str(step) for step in path.get("steps", [])).lower() for token in ("auth", "admin", "data", "privileged"))
    ][:25]


def _risk_propagation(graph: dict[str, object], paths: list[dict[str, object]]) -> dict[str, object]:
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    high_risk_nodes = [node for node in nodes if isinstance(node, dict) and int(node.get("risk", 0) or 0) >= 70]
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "high_risk_node_count": len(high_risk_nodes),
        "path_count": len(paths),
        "propagation_score": min(100, len(high_risk_nodes) * 8 + len(paths) * 4),
    }


def _exposure_spikes(drift: dict[str, object]) -> list[dict[str, object]]:
    spikes = []
    for event in drift.get("timeline", []) or []:
        if int(event.get("new_endpoint_count", 0) or 0) >= 10 or int(event.get("new_finding_count", 0) or 0) >= 3:
            spikes.append(
                {
                    "target": event.get("target_url"),
                    "new_endpoints": event.get("new_endpoint_count", 0),
                    "new_findings": event.get("new_finding_count", 0),
                    "severity": "high" if int(event.get("new_finding_count", 0) or 0) >= 3 else "medium",
                }
            )
    return spikes[-25:]


def _api_drift(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    previous_count = 0
    for scan in sorted(scans, key=lambda item: str(item.get("finished_at") or item.get("started_at") or "")):
        summary = scan.get("summary", {}) if isinstance(scan.get("summary"), dict) else {}
        count = int(scan.get("api_endpoint_count", 0) or summary.get("api_endpoint_count", 0) or 0)
        delta = count - previous_count
        if delta:
            rows.append({"target": scan.get("target_url"), "api_count": count, "delta": delta, "status": "expanded" if delta > 0 else "contracted"})
        previous_count = count
    return rows[-25:]


def _auth_drift(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for scan in scans:
        auth = scan.get("auth_intelligence", {}) if isinstance(scan.get("auth_intelligence"), dict) else {}
        summary = scan.get("auth_summary", {}) if isinstance(scan.get("auth_summary"), dict) else {}
        signals = int(auth.get("auth_exposure_score", 0) or 0) + int(summary.get("privileged_endpoint_count", 0) or 0)
        if signals:
            rows.append({"target": scan.get("target_url"), "signals": signals, "status": "review"})
    return rows[:25]


def _worker_events(scans: list[dict[str, object]]) -> list[dict[str, object]]:
    events = []
    for scan in scans[:10]:
        telemetry = scan.get("telemetry_summary", {}) if isinstance(scan.get("telemetry_summary"), dict) else {}
        summary = scan.get("summary", {}) if isinstance(scan.get("summary"), dict) else {}
        events.append(
            {
                "event": "worker-pipeline-complete",
                "target": scan.get("target_url"),
                "duration_ms": scan.get("duration_ms") or summary.get("duration_ms", 0),
                "detectors": telemetry.get("detector_count", len(scan.get("detector_timings", []) or [])),
            }
        )
    return events


def _operational_alerts(metrics: dict[str, object], drift: dict[str, object], paths: list[dict[str, object]]) -> list[dict[str, object]]:
    alerts = []
    if int(metrics.get("high_count", 0) or 0):
        alerts.append({"severity": "high", "title": "High-severity exposure requires validation", "count": metrics.get("high_count", 0)})
    if int(drift.get("drift_event_count", 0) or 0):
        alerts.append({"severity": "medium", "title": "Attack surface drift detected", "count": drift.get("drift_event_count", 0)})
    if paths:
        alerts.append({"severity": "high", "title": "Attack paths require owner handoff", "count": len(paths)})
    return alerts


def _notifications(metrics: dict[str, object], drift: dict[str, object], paths: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {"channel": "notification-center", "title": alert["title"], "severity": alert["severity"], "status": "unread"}
        for alert in _operational_alerts(metrics, drift, paths)
    ]


def _operational_insights(metrics: dict[str, object], exposure: dict[str, object], drift: dict[str, object], attack_paths: list[dict[str, object]]) -> list[str]:
    insights = []
    if int(metrics.get("high_count", 0) or 0):
        insights.append("Prioritize high-severity findings on internet-facing assets.")
    if int(drift.get("drift_event_count", 0) or 0):
        insights.append("Review deployment drift before the next monitoring cycle.")
    if attack_paths:
        insights.append("Validate the top attack path with replay evidence and owner handoff.")
    if exposure.get("highest_risk"):
        insights.append("Focus exposure operations on the highest-risk target first.")
    return insights or ["Surface is ready for continuous monitoring; add recurring scopes to deepen coverage."]


def _posture(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "elevated"
    return "controlled"
