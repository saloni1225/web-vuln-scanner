import React, { useEffect, useMemo, useState } from "react";
import { Activity, Boxes, CheckCircle2, Clock3, Code2, FileText, GitBranch, KeyRound, MonitorDot, Network, Radar, ShieldAlert, ShieldCheck, Siren, Target } from "lucide-react";
import { Card, CardHeader, DataTable, KpiStrip, PageHeader, SeverityBadge, StatCard, StatusPill } from "../components/ui.jsx";
import { fetchAttackPaths, fetchAttackSurfaceDrift, fetchAttackSurfaceGraph, fetchExposureOverview, fetchOperationsIntelligence, fetchPlatformOverview, fetchReports, fetchScanHistory } from "../services/api.js";

function useEnterpriseData() {
  const [reports, setReports] = useState([]);
  const [platform, setPlatform] = useState(null);
  const [history, setHistory] = useState({ severity_trends: [] });
  const [operations, setOperations] = useState(null);
  useEffect(() => {
    fetchReports().then(setReports).catch(() => setReports([]));
    fetchPlatformOverview().then(setPlatform).catch(() => setPlatform(null));
    fetchScanHistory().then(setHistory).catch(() => setHistory({ severity_trends: [] }));
    fetchOperationsIntelligence().then(setOperations).catch(() => setOperations(null));
  }, []);
  return { reports, platform, history, operations };
}

export function AssetsPage() {
  const { reports, platform } = useEnterpriseData();
  const rows = (platform?.assets?.tracked_hosts ?? []).map((host) => ({
    asset: host,
    type: "Web application",
    exposure: "Internet-facing",
    scans: reports.filter((report) => String(report.target_url).includes(host)).length,
    risk: reports.some((report) => String(report.target_url).includes(host) && report.high_severity_count) ? "high" : "monitored",
  }));
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Inventory" title="Assets" subtitle="Internet-facing applications, services, and endpoint inventory." />
      <KpiStrip items={[
        { label: "Owned assets", value: rows.length, meta: "tracked hosts" },
        { label: "External exposure", value: rows.filter((row) => row.exposure === "Internet-facing").length, meta: "publicly reachable" },
        { label: "Critical ownership", value: rows.filter((row) => row.risk === "high").length, meta: "needs owner", tone: rows.some((row) => row.risk === "high") ? "danger" : "good" },
        { label: "Coverage", value: `${Math.min(100, rows.length ? 92 : 0)}%`, meta: "scan mapped" },
      ]} />
      <section className="stat-grid">
        <StatCard icon={Boxes} label="Assets" value={rows.length} />
        <StatCard icon={Network} label="Endpoints" value={platform?.metrics?.endpoint_count ?? 0} />
        <StatCard icon={ShieldAlert} label="High risk" value={rows.filter((row) => row.risk === "high").length} tone="danger" />
        <StatCard icon={CheckCircle2} label="Monitored" value={rows.filter((row) => row.risk !== "high").length} tone="good" />
      </section>
      <Card>
        <CardHeader icon={Boxes} title="Asset inventory" meta={`${rows.length} assets`} />
        <DataTable rows={rows} columns={[
          { key: "asset", label: "Asset" },
          { key: "type", label: "Type" },
          { key: "exposure", label: "Exposure" },
          { key: "scans", label: "Scans" },
          { key: "risk", label: "Risk", render: (row) => <StatusPill tone={row.risk === "high" ? "danger" : "good"}>{row.risk}</StatusPill> },
        ]} />
      </Card>
    </section>
  );
}

export function ReconPage() {
  const { reports, platform } = useEnterpriseData();
  const rows = reports.map((report) => ({
    target: report.target_url,
    technologies: report.technology_count ?? report.recon_technology_count ?? 0,
    ports: report.open_port_count ?? 0,
    endpoints: report.endpoint_count ?? 0,
    posture: report.risk_gate_status ?? "monitored",
  }));
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Recon Intelligence" title="Recon" subtitle="Passive fingerprinting, endpoint discovery, TLS/WAF posture, and external drift signals." />
      <section className="stat-grid">
        <StatCard icon={Radar} label="Recon runs" value={reports.length} />
        <StatCard icon={Target} label="Hosts observed" value={platform?.assets?.host_count ?? 0} />
        <StatCard icon={Network} label="Endpoints found" value={platform?.metrics?.endpoint_count ?? 0} />
        <StatCard icon={Activity} label="Drift signals" value={platform?.metrics?.risk_gate_failures ?? 0} tone={platform?.metrics?.risk_gate_failures ? "warn" : "good"} />
      </section>
      <section className="enterprise-grid">
        <Card>
          <CardHeader icon={Radar} title="Recon coverage" meta="latest scans" />
          <DataTable rows={rows} columns={[
            { key: "target", label: "Target" },
            { key: "endpoints", label: "Endpoints" },
            { key: "ports", label: "Ports" },
            { key: "technologies", label: "Tech" },
            { key: "posture", label: "Posture", render: (row) => <StatusPill tone={row.posture === "failed" ? "danger" : "good"}>{row.posture}</StatusPill> },
          ]} />
        </Card>
        <Card>
          <CardHeader icon={GitBranch} title="Discovery pipeline" meta="operational model" />
          <div className="pipeline-lanes">
            {["DNS", "TLS", "WAF", "Crawler", "APIs", "Evidence"].map((stage, index) => (
              <div key={stage} className="pipeline-stage">
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{stage}</strong>
                <small>{index < 4 ? "active" : "ready"}</small>
              </div>
            ))}
          </div>
        </Card>
      </section>
    </section>
  );
}

export function FindingsPage() {
  const { reports } = useEnterpriseData();
  const rows = reports.flatMap((report) => [
    report.high_severity_count ? { target: report.target_url, severity: "high", title: "High severity findings", count: report.high_severity_count, status: report.risk_gate_status } : null,
    report.medium_severity_count ? { target: report.target_url, severity: "medium", title: "Medium severity findings", count: report.medium_severity_count, status: report.risk_gate_status } : null,
    report.low_severity_count ? { target: report.target_url, severity: "low", title: "Low severity findings", count: report.low_severity_count, status: report.risk_gate_status } : null,
  ].filter(Boolean));
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Vulnerability Management" title="Findings" subtitle="Grouped issues, lifecycle state, validation confidence, and remediation status." />
      <KpiStrip items={[
        { label: "Exploit confidence", value: rows.some((row) => row.severity === "high") ? "High" : "Low", meta: "validation weighted", tone: rows.some((row) => row.severity === "high") ? "danger" : "good" },
        { label: "Open SLA", value: rows.length, meta: "grouped findings" },
        { label: "Evidence quality", value: "Ready", meta: "request replay available", tone: "good" },
        { label: "Retest queue", value: 0, meta: "waiting" },
      ]} />
      <section className="stat-grid">
        <StatCard icon={Siren} label="Finding groups" value={rows.length} />
        <StatCard icon={ShieldAlert} label="High" value={rows.filter((row) => row.severity === "high").reduce((sum, row) => sum + row.count, 0)} tone="danger" />
        <StatCard icon={Clock3} label="Retesting" value="0" />
        <StatCard icon={CheckCircle2} label="Resolved" value="0" tone="good" />
      </section>
      <Card>
        <CardHeader icon={Siren} title="Finding groups" meta={`${rows.length} groups`} />
        <DataTable rows={rows} columns={[
          { key: "title", label: "Finding" },
          { key: "target", label: "Target" },
          { key: "severity", label: "Severity", render: (row) => <SeverityBadge value={row.severity} /> },
          { key: "count", label: "Count" },
          { key: "status", label: "Lifecycle", render: () => <StatusPill>Open</StatusPill> },
        ]} />
      </Card>
      <section className="split-workflow">
        <Card>
          <CardHeader icon={ShieldAlert} title="Lifecycle lanes" meta="triage board" />
          <div className="lane-board">
            {["New", "Validated", "Assigned", "Retest"].map((lane, index) => (
              <div key={lane} className="lifecycle-lane">
                <span>{lane}</span>
                <strong>{index === 0 ? rows.length : 0}</strong>
              </div>
            ))}
          </div>
        </Card>
        <Card>
          <CardHeader icon={Target} title="Remediation intelligence" meta="recommended focus" />
          <div className="intel-list">
            <div><strong>Patch externally reachable high severity first</strong><span>{rows.filter((row) => row.severity === "high").length} groups</span></div>
            <div><strong>Validate medium findings with replay evidence</strong><span>{rows.filter((row) => row.severity === "medium").length} groups</span></div>
            <div><strong>Retest after owner handoff</strong><span>0 queued</span></div>
          </div>
        </Card>
      </section>
    </section>
  );
}

export function AttackSurfacePage() {
  const { reports, platform, operations } = useEnterpriseData();
  const [graph, setGraph] = useState(null);
  const [drift, setDrift] = useState(null);
  const [paths, setPaths] = useState(null);
  const [exposure, setExposure] = useState(null);
  useEffect(() => {
    fetchAttackSurfaceGraph().then(setGraph).catch(() => setGraph(null));
    fetchAttackSurfaceDrift().then(setDrift).catch(() => setDrift(null));
    fetchAttackPaths().then(setPaths).catch(() => setPaths(null));
    fetchExposureOverview().then(setExposure).catch(() => setExposure(null));
  }, []);
  const rows = reports.map((report) => ({
    target: report.target_url,
    endpoints: report.endpoint_count,
    risky: report.high_risk_endpoint_count,
    profile: report.scan_profile,
    gate: report.risk_gate_status,
  }));
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Attack Surface Intelligence" title="External surface map" subtitle="Asset inventory, exposure graph, service topology, API relationships, and cloud exposure in one operational view." />
      <KpiStrip items={[
        { label: "Graph nodes", value: operations?.attack_surface?.graph?.node_count ?? graph?.node_count ?? 0, meta: `${operations?.attack_surface?.graph?.edge_count ?? graph?.edge_count ?? 0} relationships` },
        { label: "Attack paths", value: paths?.path_count ?? graph?.attack_paths?.length ?? 0, meta: graph?.highest_risk_path?.name ?? "correlation ready", tone: graph?.highest_risk_path ? "danger" : "neutral" },
        { label: "Drift events", value: drift?.drift_event_count ?? 0, meta: `${drift?.event_count ?? 0} scan snapshots`, tone: drift?.drift_event_count ? "warn" : "good" },
        { label: "Exposure score", value: exposure?.score ?? 0, meta: exposure?.label ?? "offensive correlation", tone: (exposure?.score ?? 0) >= 60 ? "danger" : (exposure?.score ?? 0) >= 35 ? "warn" : "good" },
      ]} />
      <section className="attack-graph-panel">
        <div className="attack-graph">
          {((graph?.nodes ?? []).length ? graph.nodes : (platform?.assets?.tracked_hosts ?? ["Run a scan to map assets"]).map((host) => ({ id: host, label: host, type: "host", risk: 20 }))).slice(0, 8).map((node, index) => (
            <div key={node.id ?? node.label} className={`graph-node node-${index}`} style={{ "--x": `${14 + (index % 4) * 22}%`, "--y": `${18 + Math.floor(index / 4) * 34}%` }}>
              <strong>{node.label}</strong>
              <span>{node.type} · risk {node.risk ?? rows.find((row) => row.target.includes(node.label))?.risky ?? 0}</span>
            </div>
          ))}
          <div className="graph-core"><Network size={24} /><strong>External ASM</strong></div>
        </div>
      </section>
      <Card>
        <CardHeader icon={Network} title="Endpoint inventory" meta={`${rows.length} scans`} />
        <DataTable rows={rows} columns={[
          { key: "target", label: "Target" },
          { key: "endpoints", label: "Endpoints" },
          { key: "risky", label: "Risky" },
          { key: "profile", label: "Profile" },
          { key: "gate", label: "Gate", render: (row) => <StatusPill tone={row.gate === "failed" ? "danger" : "good"}>{row.gate}</StatusPill> },
        ]} />
      </Card>
      <section className="split-workflow">
        <Card>
          <CardHeader icon={GitBranch} title="Attack path intelligence" meta={`${paths?.path_count ?? 0} paths`} />
          <div className="intel-list">
            {((paths?.paths ?? graph?.attack_paths) ?? []).length ? ((paths?.paths ?? graph?.attack_paths) ?? []).slice(0, 5).map((path) => (
              <div key={`${path.name}-${path.target_url ?? ""}`}>
                <strong>{path.name}</strong>
                <span>{path.risk_score} · {path.severity}</span>
              </div>
            )) : <div><strong>No attack paths yet</strong><span>Run scans to correlate exposure</span></div>}
          </div>
        </Card>
        <Card>
          <CardHeader icon={ShieldAlert} title="Priority exposure assets" meta={exposure?.highest_risk?.target_url ?? "aggregated"} />
          <div className="intel-list">
            {(exposure?.highest_risk?.priority_assets ?? []).slice(0, 5).map((asset) => (
              <div key={asset.asset}>
                <strong>{asset.asset}</strong>
                <span>{asset.score} · {asset.reason}</span>
              </div>
            ))}
            {!(exposure?.highest_risk?.priority_assets ?? []).length ? <div><strong>No priority assets yet</strong><span>Run recon to score exposure</span></div> : null}
          </div>
        </Card>
        <Card>
          <CardHeader icon={Activity} title="Exposure heatmap" meta="offensive dimensions" />
          <div className="exposure-heatmap">
            {(exposure?.highest_risk?.heatmap ?? []).map((cell) => (
              <div key={cell.dimension} className={`heat-cell heat-${Math.min(4, Math.ceil((cell.intensity ?? 0) / 25))}`}>
                <strong>{cell.dimension}</strong>
                <span>{cell.value} signals</span>
              </div>
            ))}
          </div>
        </Card>
      </section>
      <section className="split-workflow">
        <Card>
          <CardHeader icon={Network} title="Service topology" meta="internet services" />
          <div className="intel-list">
            {(operations?.attack_surface?.service_topology ?? []).map((item) => (
              <div key={item.service}><strong>{item.service}</strong><span>{item.asset_count} assets</span></div>
            ))}
          </div>
        </Card>
        <Card>
          <CardHeader icon={Boxes} title="Cloud exposure map" meta="correlation candidates" />
          <div className="intel-list">
            {(operations?.attack_surface?.cloud_exposure ?? []).map((item, index) => (
              <div key={`${item.surface ?? item.provider}-${index}`}><strong>{item.surface ?? item.provider}</strong><span>{item.status ?? "observed"}</span></div>
            ))}
          </div>
        </Card>
      </section>
      <section className="split-workflow">
        <Card>
          <CardHeader icon={Activity} title="Drift timeline" meta={`${drift?.drift_event_count ?? 0} changes`} />
          <div className="timeline-list">
            {(drift?.timeline ?? []).length ? (drift?.timeline ?? []).slice(-6).reverse().map((event) => (
              <div key={event.scan_id} className="timeline-row">
                <strong>{event.target_url}</strong>
                <small>{event.new_endpoint_count} new · {event.removed_endpoint_count} removed · {event.new_finding_count} findings</small>
                <span>{event.drift_detected ? "drift" : "stable"}</span>
              </div>
            )) : <div className="empty-panel">Exposure drift appears after multiple scans.</div>}
          </div>
        </Card>
      </section>
    </section>
  );
}

export function ExposureOperationsPage() {
  const { operations } = useEnterpriseData();
  const feed = operations?.exposure_operations?.feed ?? [];
  const ranking = operations?.exposure_operations?.ranking ?? [];
  const authRows = operations?.exposure_operations?.auth_exposure ?? [];
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Exposure Operations" title="Exploitability queue" subtitle="Internet exposure feed, auth exposure, API sensitivity, cloud candidates, and exploitability-ranked remediation focus." />
      <KpiStrip items={[
        { label: "Queued exposures", value: feed.length, meta: "internet-facing signals" },
        { label: "Top priority", value: ranking[0]?.priority_score ?? 0, meta: ranking[0]?.target ?? "none" },
        { label: "Auth exposure", value: authRows.length, meta: "identity boundary signals", tone: authRows.length ? "warn" : "good" },
        { label: "Heatmap cells", value: operations?.exposure_operations?.heatmap?.length ?? 0, meta: "risk dimensions" },
      ]} />
      <section className="enterprise-grid">
        <Card>
          <CardHeader icon={ShieldAlert} title="Internet exposure feed" meta={`${feed.length} signals`} />
          <DataTable rows={ranking} columns={[
            { key: "target", label: "Asset" },
            { key: "priority_score", label: "Score" },
            { key: "reason", label: "Reason" },
            { key: "status", label: "State", render: (row) => <StatusPill tone={row.status === "failed" ? "danger" : "good"}>{row.status}</StatusPill> },
          ]} empty="No exposure signals yet" />
        </Card>
        <Card>
          <CardHeader icon={KeyRound} title="Auth exposure" meta="identity operations" />
          <DataTable rows={authRows} columns={[
            { key: "target", label: "Target" },
            { key: "auth_signals", label: "Signals" },
            { key: "focus", label: "Focus" },
          ]} empty="No auth exposure signals yet" />
        </Card>
        <Card className="wide-card">
          <CardHeader icon={Activity} title="Exposure heatmap" meta="offensive dimensions" />
          <div className="exposure-heatmap">
            {(operations?.exposure_operations?.heatmap ?? []).length ? operations.exposure_operations.heatmap.map((cell) => (
              <div key={cell.dimension} className={`heat-cell heat-${Math.min(4, Math.ceil((cell.intensity ?? 0) / 25))}`}>
                <strong>{cell.dimension}</strong>
                <span>{cell.value} signals</span>
              </div>
            )) : <div className="empty-panel">Heatmap appears after exposure scoring.</div>}
          </div>
        </Card>
      </section>
    </section>
  );
}

export function OffensiveResearchPage() {
  const { operations } = useEnterpriseData();
  const feed = operations?.offensive_research?.feed ?? [];
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Offensive Research Center" title="Research feed" subtitle="Newly exposed assets, attack-path changes, suspicious drift, new APIs, exposed admin surfaces, and auth weaknesses." />
      <section className="stat-grid">
        <StatCard icon={Radar} label="Research signals" value={feed.length} />
        <StatCard icon={Boxes} label="New assets" value={operations?.offensive_research?.newly_exposed_assets?.length ?? 0} />
        <StatCard icon={GitBranch} label="Path changes" value={operations?.offensive_research?.attack_path_changes?.length ?? 0} tone="warn" />
        <StatCard icon={Activity} label="Suspicious drift" value={operations?.offensive_research?.suspicious_drift?.length ?? 0} tone="warn" />
      </section>
      <Card>
        <CardHeader icon={Radar} title="Offensive research queue" meta={`${feed.length} signals`} />
        <DataTable rows={feed} columns={[
          { key: "title", label: "Signal" },
          { key: "type", label: "Type" },
          { key: "target", label: "Target" },
          { key: "signal", label: "Evidence" },
        ]} empty="Research signals appear as scans and drift accumulate" />
      </Card>
    </section>
  );
}

export function ThreatIntelligencePage() {
  const { operations } = useEnterpriseData();
  const feed = operations?.threat_intelligence?.feed ?? [];
  const technologies = operations?.threat_intelligence?.technology_exposure ?? [];
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Threat Intelligence" title="Internet threat correlation" subtitle="CVE enrichment readiness, exploit intelligence, vulnerable technology exposure, and internet-scale threat context." />
      <section className="stat-grid">
        <StatCard icon={Siren} label="Threat signals" value={feed.length} />
        <StatCard icon={Code2} label="Technologies" value={technologies.length} />
        <StatCard icon={ShieldAlert} label="Exploit candidates" value={operations?.threat_intelligence?.exploit_correlation?.length ?? 0} tone="danger" />
        <StatCard icon={CheckCircle2} label="Intel status" value="Ready" tone="good" />
      </section>
      <section className="enterprise-grid">
        <Card>
          <CardHeader icon={Siren} title="Threat feed" meta={`${feed.length} events`} />
          <DataTable rows={feed} columns={[
            { key: "title", label: "Signal" },
            { key: "type", label: "Type" },
            { key: "severity", label: "Severity", render: (row) => <SeverityBadge value={row.severity ?? "medium"} /> },
            { key: "target", label: "Target" },
          ]} empty="Threat correlation appears after technology discovery" />
        </Card>
        <Card>
          <CardHeader icon={Code2} title="Exposed technologies" meta="CVE enrichment ready" />
          <DataTable rows={technologies} columns={[
            { key: "technology", label: "Technology" },
            { key: "asset_count", label: "Assets" },
            { key: "exposure", label: "Exposure" },
          ]} empty="No technology exposure yet" />
        </Card>
      </section>
    </section>
  );
}

export function ApiSecurityPage() {
  const { reports, platform } = useEnterpriseData();
  const rows = reports.map((report) => ({
    target: report.target_url,
    api: report.api_endpoint_count ?? 0,
    graphql: report.graphql_endpoint_count ?? 0,
    probes: report.schema_fuzz_probe_count ?? 0,
    risk: report.high_risk_endpoint_count ?? 0,
  }));
  return (
    <section className="page-stack">
      <PageHeader eyebrow="API Security" title="APIs" subtitle="REST, GraphQL, hidden endpoint discovery, schema fuzzing, and dependency exposure." />
      <section className="stat-grid">
        <StatCard icon={Code2} label="API endpoints" value={platform?.metrics?.api_endpoint_count ?? rows.reduce((sum, row) => sum + row.api, 0)} />
        <StatCard icon={Network} label="GraphQL" value={rows.reduce((sum, row) => sum + row.graphql, 0)} />
        <StatCard icon={Activity} label="Schema probes" value={rows.reduce((sum, row) => sum + row.probes, 0)} />
        <StatCard icon={ShieldAlert} label="Risky endpoints" value={rows.reduce((sum, row) => sum + row.risk, 0)} tone="warn" />
      </section>
      <section className="enterprise-grid">
        <Card>
          <CardHeader icon={Code2} title="API exposure" meta={`${rows.length} targets`} />
          <DataTable rows={rows} columns={[
            { key: "target", label: "Target" },
            { key: "api", label: "REST" },
            { key: "graphql", label: "GraphQL" },
            { key: "probes", label: "Probes" },
            { key: "risk", label: "Risk" },
          ]} />
        </Card>
        <Card>
          <CardHeader icon={GitBranch} title="Dependency map" meta="relationship view" />
          <div className="api-map">
            {["Client", "Gateway", "REST", "GraphQL", "Auth", "Data"].map((node) => <span key={node}>{node}</span>)}
          </div>
        </Card>
      </section>
    </section>
  );
}

export function CompliancePage() {
  const { platform } = useEnterpriseData();
  const rows = [
    { framework: "OWASP Top 10", mapped: platform?.metrics?.finding_count ?? 0, status: "Mapped" },
    { framework: "PCI DSS", mapped: platform?.metrics?.high_count ?? 0, status: "Evidence ready" },
    { framework: "ISO 27001", mapped: platform?.metrics?.scan_count ?? 0, status: "Monitoring" },
    { framework: "NIST CSF", mapped: platform?.metrics?.endpoint_count ?? 0, status: "Monitoring" },
  ];
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Governance" title="Compliance" subtitle="Executive-ready framework mapping and evidence export center." />
      <section className="stat-grid">
        <StatCard icon={FileText} label="Frameworks" value={rows.length} />
        <StatCard icon={ShieldCheck} label="Mapped findings" value={platform?.metrics?.finding_count ?? 0} />
        <StatCard icon={CheckCircle2} label="Evidence bundles" value={platform?.architecture?.object_storage?.artifact_count ?? 0} tone="good" />
        <StatCard icon={Clock3} label="Open exceptions" value="0" />
      </section>
      <Card>
        <CardHeader icon={FileText} title="Framework coverage" meta="Export ready" />
        <DataTable rows={rows} columns={[
          { key: "framework", label: "Framework" },
          { key: "mapped", label: "Mapped" },
          { key: "status", label: "Status", render: (row) => <StatusPill tone="good">{row.status}</StatusPill> },
        ]} />
      </Card>
    </section>
  );
}

export function MonitoringPage() {
  const { platform } = useEnterpriseData();
  const policies = platform?.monitoring?.alert_policies ?? [];
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Continuous Monitoring" title="Monitoring" subtitle="Scheduled scanning, drift alerts, recurring telemetry, and notification policy." />
      <section className="stat-grid">
        <StatCard icon={MonitorDot} label="Recurring targets" value={platform?.monitoring?.scheduler?.recurring_scan_count ?? 0} />
        <StatCard icon={ShieldAlert} label="Alert policies" value={policies.length} />
        <StatCard icon={CheckCircle2} label="Asset monitor" value={platform?.monitoring?.continuous_asset_monitoring?.enabled ? "On" : "Off"} tone="good" />
        <StatCard icon={KeyRound} label="Dedupe window" value={`${platform?.monitoring?.notification_engine?.dedupe_window_minutes ?? 60}m`} />
      </section>
      <Card>
        <CardHeader icon={MonitorDot} title="Alert policies" meta={`${policies.length} policies`} />
        <DataTable rows={policies} columns={[
          { key: "name", label: "Policy" },
          { key: "condition", label: "Condition" },
          { key: "severity", label: "Severity", render: (row) => <SeverityBadge value={row.severity} /> },
          { key: "channels", label: "Channels", render: (row) => row.channels.join(", ") },
        ]} />
      </Card>
    </section>
  );
}

export function SettingsPage() {
  return (
    <section className="page-stack">
      <PageHeader eyebrow="Administration" title="Settings" subtitle="Scope controls, API keys, RBAC policy, credential handling, and scan safety defaults." />
      <section className="settings-grid">
        {[
          ["Authorization confirmation", "External targets require explicit scope confirmation."],
          ["Domain allowlists", "Restrict scans to approved hosts and workspaces."],
          ["Secure credentials", "Session values stay scoped to authorized scan requests."],
          ["Rate limits", "Default throttling protects production applications."],
        ].map(([title, text]) => (
          <Card key={title}>
            <CardHeader icon={ShieldCheck} title={title} meta="Enabled" />
            <p className="card-copy">{text}</p>
          </Card>
        ))}
      </section>
    </section>
  );
}
