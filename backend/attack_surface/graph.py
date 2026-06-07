"""
Asset-Level Graph Engine for AdaptiveScan.

This module handles asset-level graphs (representing network topology, hosts, endpoints,
and services).

DISTINCTION:
- Asset Graph (this file): Models the physical and logical architecture/topology of the attack surface.
- Attack Graph (backend/core/correlation.py): Models exploit chains and vulnerability dependency paths.
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlparse


def build_attack_surface_graph(scan: dict[str, object]) -> dict[str, object]:
    target_url = str(scan.get("target_url", ""))
    host = urlparse(target_url).hostname or target_url
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []

    def add_node(node_id: str, label: str, node_type: str, risk: int = 10, metadata: dict[str, object] | None = None) -> None:
        if any(node["id"] == node_id for node in nodes):
            return
        nodes.append({"id": node_id, "label": label, "type": node_type, "risk": min(100, max(0, risk)), "metadata": metadata or {}})

    def add_edge(source: str, target: str, relationship: str, weight: int = 1) -> None:
        edges.append({"source": source, "target": target, "relationship": relationship, "weight": weight})

    org_id = f"org:{host.split('.')[-2] if '.' in host else host}"
    host_id = f"host:{host}"
    add_node(org_id, host.split(".")[-2] if "." in host else host, "organization", 20)
    add_node(host_id, host, "internet-facing-host", _host_risk(scan))
    add_edge(org_id, host_id, "owns")

    recon = scan.get("recon_summary", {}) if isinstance(scan.get("recon_summary"), dict) else {}
    for subdomain in recon.get("subdomain_summary", {}).get("resolved", []) if isinstance(recon.get("subdomain_summary"), dict) else []:
        if not isinstance(subdomain, dict):
            continue
        sub_host = str(subdomain.get("host", ""))
        sub_id = f"host:{sub_host}"
        add_node(sub_id, sub_host, "subdomain", 35, {"addresses": subdomain.get("addresses", [])})
        add_edge(org_id, sub_id, "discovered-subdomain")

    for port in recon.get("port_summary", {}).get("open_ports", []) if isinstance(recon.get("port_summary"), dict) else []:
        if not isinstance(port, dict):
            continue
        port_id = f"service:{host}:{port.get('port')}"
        add_node(port_id, f"{host}:{port.get('port')}", "service", 45, {"service_hint": port.get("service_hint"), "banner": port.get("banner")})
        add_edge(host_id, port_id, "exposes")

    for endpoint in scan.get("endpoints", []) if isinstance(scan.get("endpoints"), list) else []:
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get("url", ""))
        endpoint_id = f"endpoint:{_stable_id(url)}"
        risk = _endpoint_risk(url, str(endpoint.get("type", "endpoint")))
        add_node(endpoint_id, url, str(endpoint.get("type") or "endpoint"), risk, {"method": endpoint.get("method", "GET"), "source": endpoint.get("source", "")})
        add_edge(host_id, endpoint_id, "serves")

    for finding in scan.get("findings", []) if isinstance(scan.get("findings"), list) else []:
        if not isinstance(finding, dict):
            continue
        url = str(finding.get("url", ""))
        finding_id = f"finding:{_stable_id(str(finding.get('detector', '')) + url + str(finding.get('parameter', '')))}"
        add_node(
            finding_id,
            str(finding.get("detector", "finding")),
            "finding",
            _finding_risk(finding),
            {
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "validation_state": finding.get("validation_state"),
                "cwe_id": finding.get("cwe_id"),
            },
        )
        endpoint_id = f"endpoint:{_stable_id(url)}"
        if any(node["id"] == endpoint_id for node in nodes):
            add_edge(endpoint_id, finding_id, "has-finding", _finding_risk(finding))
        else:
            add_edge(host_id, finding_id, "has-finding", _finding_risk(finding))

    paths = correlate_attack_paths(scan, {"nodes": nodes, "edges": edges})
    return {
        "nodes": nodes[:500],
        "edges": edges[:1000],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "attack_paths": paths,
        "highest_risk_path": paths[0] if paths else None,
        # Cross-reference finding-level exploit chains from core/correlation.py
        "finding_level_chains": scan.get("attack_chain_summary", {}).get("chains", []),
    }


def correlate_attack_paths(scan: dict[str, object], graph: dict[str, object] | None = None) -> list[dict[str, object]]:
    graph = graph or {}
    findings = [item for item in scan.get("findings", []) if isinstance(item, dict)]
    endpoints = [item for item in scan.get("endpoints", []) if isinstance(item, dict)]
    recon = scan.get("recon_summary", {}) if isinstance(scan.get("recon_summary"), dict) else {}
    paths: list[dict[str, object]] = []

    api_endpoints = [item for item in endpoints if "api" in str(item.get("url", "")).lower() or str(item.get("type")) in {"api", "graphql"}]
    auth_findings = [item for item in findings if str(item.get("detector", "")).lower() in {"auth_bypass", "csrf", "idor"} or "auth" in str(item.get("category", "")).lower()]
    injection_findings = [item for item in findings if any(token in str(item.get("detector", "")).lower() for token in ("sqli", "nosql", "ssti", "command"))]
    admin_endpoints = [item for item in endpoints if any(token in str(item.get("url", "")).lower() for token in ("admin", "console", "dashboard", "manage"))]

    if api_endpoints and auth_findings:
        paths.append(
            _path(
                "exposed-api-auth-boundary",
                ["internet-facing API", "auth weakness", "data/object access risk"],
                86,
                api_endpoints[:5],
                auth_findings[:5],
            )
        )
    if admin_endpoints and findings:
        paths.append(
            _path(
                "admin-surface-with-exploitable-signal",
                ["admin route discovered", "validated or high-confidence finding", "privileged surface"],
                82,
                admin_endpoints[:5],
                findings[:5],
            )
        )
    if injection_findings and recon.get("port_summary", {}).get("open_ports"):
        paths.append(
            _path(
                "service-to-data-access",
                ["open internet service", "injection class finding", "data access pivot"],
                78,
                recon.get("port_summary", {}).get("open_ports", [])[:5],
                injection_findings[:5],
            )
        )
    if recon.get("cloud_asset_summary", {}).get("exposed"):
        paths.append(
            _path(
                "cloud-storage-exposure",
                ["cloud bucket candidate", "public response", "evidence collection"],
                74,
                recon.get("cloud_asset_summary", {}).get("exposed", [])[:5],
                [],
            )
        )
    if not paths and (findings or endpoints):
        paths.append(_path("public-surface-triage", ["internet-facing host", "mapped endpoints", "prioritized validation"], 48, endpoints[:5], findings[:5]))
    return sorted(paths, key=lambda item: int(item["risk_score"]), reverse=True)


def build_drift_timeline(scans: list[dict[str, object]]) -> dict[str, object]:
    ordered = sorted(scans, key=lambda item: str(item.get("finished_at") or item.get("started_at") or ""))
    timeline = []
    previous_endpoints: set[str] = set()
    previous_findings: set[str] = set()
    for scan in ordered:
        scan_endpoints = {
            str(item.get("url", ""))
            for item in scan.get("endpoints", [])
            if isinstance(item, dict) and item.get("url")
        }
        scan_findings = {
            f"{item.get('detector')}:{item.get('url')}:{item.get('parameter')}"
            for item in scan.get("findings", [])
            if isinstance(item, dict)
        }
        new_endpoints = sorted(scan_endpoints - previous_endpoints)
        removed_endpoints = sorted(previous_endpoints - scan_endpoints)
        new_findings = sorted(scan_findings - previous_findings)
        timeline.append(
            {
                "scan_id": scan.get("scan_id"),
                "target_url": scan.get("target_url"),
                "finished_at": scan.get("finished_at"),
                "endpoint_count": len(scan_endpoints),
                "finding_count": len(scan_findings),
                "new_endpoint_count": len(new_endpoints),
                "removed_endpoint_count": len(removed_endpoints),
                "new_finding_count": len(new_findings),
                "drift_detected": bool(new_endpoints or removed_endpoints or new_findings),
                "new_endpoints": new_endpoints[:25],
                "removed_endpoints": removed_endpoints[:25],
            }
        )
        previous_endpoints = scan_endpoints
        previous_findings = scan_findings
    return {
        "event_count": len(timeline),
        "drift_event_count": sum(1 for item in timeline if item["drift_detected"]),
        "timeline": timeline[-50:],
    }


def _path(name: str, steps: list[str], risk_score: int, assets: list[dict[str, object]], findings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "name": name,
        "risk_score": risk_score,
        "severity": "critical" if risk_score >= 85 else "high" if risk_score >= 70 else "medium",
        "steps": steps,
        "asset_samples": assets,
        "finding_samples": findings,
        "recommendation": "Validate the chain with replay evidence, assign an owner, and monitor for drift until remediated.",
    }


def _stable_id(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:14]


def _host_risk(scan: dict[str, object]) -> int:
    summary = scan.get("summary", {}) if isinstance(scan.get("summary"), dict) else {}
    return min(100, 20 + int(summary.get("high_severity_count", 0) or 0) * 12 + int(summary.get("high_risk_endpoint_count", 0) or 0) * 4)


def _endpoint_risk(url: str, endpoint_type: str) -> int:
    lower = url.lower()
    score = 20
    if endpoint_type == "graphql" or "graphql" in lower:
        score += 28
    if "/api" in lower:
        score += 18
    if any(token in lower for token in ("admin", "dashboard", "console", "debug")):
        score += 35
    if "?" in url:
        score += 10
    return min(100, score)


def _finding_risk(finding: dict[str, object]) -> int:
    severity = {"critical": 95, "high": 82, "medium": 58, "low": 32}.get(str(finding.get("severity", "low")).lower(), 40)
    if finding.get("validation_state") == "validated":
        severity += 8
    return min(100, severity)

