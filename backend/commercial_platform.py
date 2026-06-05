from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse


def public_api_catalog() -> dict[str, object]:
    return {
        "version": "v1",
        "base_path": "/api",
        "authentication": ["Bearer JWT", "workspace API key"],
        "resources": [
            {"name": "Assets API", "path": "/api/public/assets", "methods": ["GET"], "use_case": "List monitored domains, APIs, services, and ownership metadata."},
            {"name": "Findings API", "path": "/api/public/findings", "methods": ["GET"], "use_case": "Export validated findings with severity, owner, status, and evidence."},
            {"name": "Reports API", "path": "/api/public/reports", "methods": ["GET"], "use_case": "List executive and technical report artifacts."},
            {"name": "Monitoring API", "path": "/api/public/monitoring", "methods": ["GET"], "use_case": "Read monitoring workflows, drift state, and alert policy status."},
            {"name": "Notifications API", "path": "/api/public/notifications", "methods": ["GET"], "use_case": "Read notification channels and routing rules."},
        ],
        "developer_portal": {
            "sections": ["Authentication", "Organizations", "Assets", "Findings", "Reports", "Monitoring", "Notifications", "Webhooks"],
            "sdk_plan": ["Python SDK", "Node SDK", "Terraform provider"],
        },
    }


def marketplace_architecture() -> dict[str, object]:
    return {
        "marketplace": "AdaptiveScan Marketplace",
        "categories": ["Detectors", "Alert destinations", "Ticketing", "SIEM", "Cloud inventory", "Identity providers"],
        "integration_model": {
            "manifest": "plugin.json",
            "execution": "sandboxed worker or webhook connector",
            "approval": "organization admin approval with scoped permissions",
            "audit": "install, update, disable, and dispatch events are written to audit logs",
        },
        "connectors": [
            "Slack",
            "Microsoft Teams",
            "Discord",
            "Jira",
            "GitHub",
            "GitLab",
            "ServiceNow",
            "Splunk",
            "Elastic",
            "Microsoft Sentinel",
        ],
    }


def founder_analytics(scans: list[dict[str, object]], tenancy: dict[str, object]) -> dict[str, object]:
    organizations = tenancy.get("organizations", []) if isinstance(tenancy.get("organizations"), list) else []
    workspaces = tenancy.get("workspaces", []) if isinstance(tenancy.get("workspaces"), list) else []
    plan_counter = Counter(str(org.get("plan", "starter")).lower() for org in organizations if isinstance(org, dict))
    monitored_assets = _asset_count(scans)
    scan_volume = len(scans)
    active_orgs = len(organizations) or 1
    trials = max(1, plan_counter.get("starter", 0))
    paid_orgs = max(0, active_orgs - trials)
    mrr = paid_orgs * 399
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "revenue": {
            "mrr": mrr,
            "arr": mrr * 12,
            "average_revenue_per_account": round(mrr / paid_orgs, 2) if paid_orgs else 0,
        },
        "growth": {
            "trials": trials,
            "conversions": paid_orgs,
            "trial_to_paid_rate": round((paid_orgs / max(active_orgs, 1)) * 100, 2),
            "retention": "modeled: 92%",
        },
        "platform_usage": {
            "active_organizations": active_orgs,
            "workspaces": len(workspaces),
            "monitored_assets": monitored_assets,
            "scan_volume": scan_volume,
            "reports_generated": scan_volume,
        },
        "founder_view": [
            "Increase activation by shortening time from registration to first monitored asset.",
            "Move customers from scans to recurring monitoring plans.",
            "Prioritize integrations that improve remediation workflow stickiness.",
        ],
    }


def public_assets(scans: list[dict[str, object]]) -> dict[str, object]:
    assets = {}
    for scan in scans:
        target = str(scan.get("target_url", ""))
        host = urlparse(target).hostname or target.replace("https://", "").replace("http://", "").split("/")[0]
        if not host:
            continue
        current = assets.setdefault(host, {
            "asset": host,
            "type": "domain",
            "owner": "Security",
            "tags": ["production", "internet-facing"],
            "services": set(),
            "apis": 0,
            "findings": 0,
            "last_seen": scan.get("created_at") or scan.get("completed_at") or "recent",
        })
        current["apis"] = int(current["apis"]) + int(scan.get("api_endpoint_count", 0) or 0)
        current["findings"] = int(current["findings"]) + int(scan.get("findings_count", 0) or scan.get("summary", {}).get("finding_count", 0) or 0)
        for service in scan.get("services", []) if isinstance(scan.get("services"), list) else []:
            current["services"].add(str(service))
    normalized = [{**asset, "services": sorted(asset["services"])} for asset in assets.values()]
    return {"assets": normalized, "count": len(normalized), "relationships": ["domain -> APIs", "domain -> services", "domain -> certificates", "domain -> findings"]}


def public_findings(scans: list[dict[str, object]]) -> dict[str, object]:
    findings = []
    for scan in scans:
        for index, finding in enumerate(scan.get("findings", []) if isinstance(scan.get("findings"), list) else []):
            if not isinstance(finding, dict):
                continue
            findings.append({
                "id": f"{scan.get('scan_id', 'scan')}-{index}",
                "asset": scan.get("target_url"),
                "title": finding.get("title") or finding.get("type") or "Security finding",
                "severity": finding.get("severity", "medium"),
                "status": finding.get("status", "open"),
                "owner": finding.get("owner", "Unassigned"),
                "evidence_available": bool(finding.get("evidence") or finding.get("replay_plan")),
            })
    return {"findings": findings, "count": len(findings)}


def public_reports(scans: list[dict[str, object]]) -> dict[str, object]:
    reports = [{
        "scan_id": scan.get("scan_id"),
        "target": scan.get("target_url"),
        "executive_report": scan.get("report_url") or scan.get("report_urls", {}).get("html"),
        "technical_report": scan.get("pdf_report_url") or scan.get("report_urls", {}).get("pdf"),
        "findings": scan.get("findings_count", 0) or scan.get("summary", {}).get("finding_count", 0),
    } for scan in scans]
    return {"reports": reports, "count": len(reports)}


def implementation_report() -> dict[str, object]:
    return {
        "product_positioning": "Commercial ASM, exposure intelligence, continuous monitoring, and vulnerability assessment SaaS.",
        "completed_capabilities": [
            "Public marketing website",
            "Registration, login, OTP, MFA, JWT-ready auth",
            "Organization and workspace foundation",
            "RBAC and audit log foundation",
            "Asset inventory and exposure dashboards",
            "Monitoring workflows and notification center",
            "Billing catalog and subscription architecture",
            "Trust center and compliance posture",
            "Public API catalog and marketplace architecture",
            "Founder analytics model",
        ],
        "operating_model": ["Organization", "Assets", "Monitoring", "Exposure", "Findings", "Reports"],
        "next_investments": [
            "Persist all SaaS resources in PostgreSQL with Alembic migrations.",
            "Back public APIs with tenant-scoped authorization and pagination.",
            "Promote connector manifests into installable marketplace entries.",
            "Add production payment provider and identity provider adapters.",
        ],
    }


def _asset_count(scans: list[dict[str, object]]) -> int:
    hosts = set()
    for scan in scans:
        target = str(scan.get("target_url", ""))
        host = urlparse(target).hostname or target
        if host:
            hosts.add(host)
    return len(hosts)
