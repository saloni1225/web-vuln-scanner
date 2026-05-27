import React, { useEffect, useMemo, useState } from "react";
import { Activity, ArrowRight, Boxes, FileText, Gauge, GitBranch, MonitorDot, Network, Radar, ShieldAlert, ShieldCheck, TrendingUp } from "lucide-react";
import { Card, CardHeader, DataTable, KpiStrip, PageHeader, SeverityBadge, StatCard, StatusPill } from "../components/ui.jsx";
import { fetchActiveScans, fetchExposureOverview, fetchOperationsIntelligence, fetchPlatformOverview, fetchReports, fetchScanHistory } from "../services/api.js";

export function Home({ onStart }) {
  const [reports, setReports] = useState([]);
  const [history, setHistory] = useState({ severity_trends: [] });
  const [activeScans, setActiveScans] = useState([]);
  const [platform, setPlatform] = useState(null);
  const [exposure, setExposure] = useState(null);
  const [operations, setOperations] = useState(null);

  useEffect(() => {
    fetchReports().then(setReports).catch(() => setReports([]));
    fetchScanHistory().then(setHistory).catch(() => setHistory({ severity_trends: [] }));
    fetchActiveScans().then(setActiveScans).catch(() => setActiveScans([]));
    fetchPlatformOverview().then(setPlatform).catch(() => setPlatform(null));
    fetchExposureOverview().then(setExposure).catch(() => setExposure(null));
    fetchOperationsIntelligence().then(setOperations).catch(() => setOperations(null));
  }, []);

  const latest = reports[0] ?? {};
  const metrics = platform?.metrics ?? {};
  const executive = operations?.executive ?? {};
  const exposureScore = executive.organization_exposure_score ?? exposure?.score ?? Math.max(0, 100 - Math.min(80, (metrics.high_count ?? 0) * 4 + (metrics.risk_gate_failures ?? 0) * 8));
  const exposureLabel = executive.posture ?? exposure?.label ?? (exposureScore > 80 ? "controlled" : exposureScore > 55 ? "elevated" : "critical");
  const internetExposure = (metrics.endpoint_count ?? 0) + (metrics.open_port_count ?? 0) + (metrics.api_endpoint_count ?? 0);
  const trendRows = history.severity_trends ?? [];
  const maxTotal = Math.max(1, ...trendRows.map((item) => item.total ?? 0));
  const latestFindings = reports.slice(0, 6).map((report) => ({
    target: report.target_url,
    severity: report.high_severity_count ? "high" : report.medium_severity_count ? "medium" : "low",
    findings: report.findings_count,
    status: report.risk_gate_status,
    finished: report.finished_at,
  }));
  const assetRows = useMemo(() => (platform?.assets?.tracked_hosts ?? []).map((host) => ({
    host,
    exposure: "Internet-facing",
    scans: reports.filter((report) => String(report.target_url).includes(host)).length,
  })), [platform, reports]);

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="AI-Driven Attack Surface Intelligence Platform"
        title="Executive Overview"
        subtitle="Offensive exposure intelligence, attack-path correlation, and continuous internet-facing risk operations for authorized assets."
        actions={<><button className="ghost-button" type="button"><Activity size={16} /> Live operations</button><button className="primary-action" type="button" onClick={onStart}><Radar size={16} /> Open ASM map</button></>}
      />

      <KpiStrip items={[
        { label: "Exposure posture", value: exposureLabel, meta: `${exposureScore}/100 offensive score`, tone: exposureScore >= 60 ? "danger" : exposureScore >= 35 ? "warn" : "good" },
        { label: "Surface signals", value: internetExposure, meta: "endpoints, APIs, ports" },
        { label: "Attack paths", value: operations?.findings_validation?.attack_chain_correlation ?? 0, meta: "correlated chains", tone: operations?.findings_validation?.attack_chain_correlation ? "warn" : "good" },
        { label: "Scan coverage", value: metrics.scan_count ?? reports.length, meta: `${activeScans.length} active now` },
      ]} />

      <section className="stat-grid">
        <StatCard icon={Gauge} label="Exposure score" value={exposureScore} delta={exposure?.highest_risk?.target_url ?? "Aggregated posture"} tone={exposureScore >= 60 ? "danger" : exposureScore >= 35 ? "warn" : "good"} />
        <StatCard icon={Boxes} label="Tracked assets" value={platform?.assets?.host_count ?? 0} delta={`${metrics.endpoint_count ?? 0} endpoints`} />
        <StatCard icon={ShieldAlert} label="Open findings" value={metrics.finding_count ?? 0} delta={`${metrics.high_count ?? 0} high`} tone={metrics.high_count ? "danger" : "good"} />
        <StatCard icon={MonitorDot} label="Live operations" value={activeScans.length} delta={latest.target_url ?? "No recent assessment"} />
      </section>

      <section className="overview-grid">
        <Card className="posture-card command-card">
          <CardHeader icon={ShieldCheck} title="Organization exposure score" meta={latest.risk_gate_status ?? "not evaluated"} />
          <div className="score-ring" style={{ "--score": exposureScore }}>
            <strong>{exposureScore}</strong>
            <span>exposure</span>
          </div>
          <div className="posture-list">
            <div><span>High severity</span><strong>{metrics.high_count ?? 0}</strong></div>
            <div><span>Risk gate failures</span><strong>{metrics.risk_gate_failures ?? 0}</strong></div>
            <div><span>Total scans</span><strong>{metrics.scan_count ?? reports.length}</strong></div>
          </div>
        </Card>

        <Card>
          <CardHeader icon={ShieldAlert} title="Operational insights" meta={exposureLabel} />
          <div className="surface-breakdown">
            {(executive.operational_insights ?? []).map((item) => (
              <div key={item}><span>Insight</span><strong>{item}</strong></div>
            ))}
            {!(executive.operational_insights ?? []).length ? Object.entries(exposure?.dimension_averages ?? exposure?.highest_risk?.dimensions ?? {}).map(([key, value]) => (
              <div key={key}><span>{key.replaceAll("_", " ")}</span><strong>{value}</strong></div>
            )) : null}
            {!exposure ? <div><span>Status</span><strong>Loading</strong></div> : null}
          </div>
        </Card>

        <Card className="wide-card trend-card">
          <CardHeader icon={TrendingUp} title="Severity trend analytics" meta={`${trendRows.length} scans`} />
          <div className="mini-trend">
            {trendRows.length ? trendRows.map((point) => (
              <div key={point.scan_id} title={`${point.target_url}: ${point.total} findings`}>
                <span className="trend-high" style={{ height: `${Math.max(4, ((point.high ?? 0) / maxTotal) * 100)}%` }} />
                <span className="trend-medium" style={{ height: `${Math.max(4, ((point.medium ?? 0) / maxTotal) * 100)}%` }} />
                <span className="trend-low" style={{ height: `${Math.max(4, ((point.low ?? 0) / maxTotal) * 100)}%` }} />
              </div>
            )) : <div className="empty-panel">No trend data yet</div>}
          </div>
        </Card>

        <Card className="wide-card">
          <CardHeader icon={FileText} title="Findings & validation spotlight" meta={`${latestFindings.length} recent`} />
          <DataTable
            rows={latestFindings}
            columns={[
              { key: "target", label: "Target" },
              { key: "severity", label: "Severity", render: (row) => <SeverityBadge value={row.severity} /> },
              { key: "findings", label: "Findings" },
              { key: "status", label: "Gate", render: (row) => <StatusPill tone={row.status === "failed" ? "danger" : "good"}>{row.status ?? "unknown"}</StatusPill> },
            ]}
            empty="No findings yet"
          />
        </Card>

        <Card>
          <CardHeader icon={Boxes} title="Internet-facing assets" meta={`${assetRows.length} hosts`} />
          <DataTable
            rows={assetRows}
            columns={[
              { key: "host", label: "Host" },
              { key: "exposure", label: "Exposure" },
              { key: "scans", label: "Scans" },
            ]}
            empty="Run scans to populate assets"
          />
        </Card>

        <Card className="wide-card">
          <CardHeader icon={Network} title="Exposure heatmap" meta="Internet facing" />
          <div className="exposure-heatmap">
            {(assetRows.length ? assetRows : [{ host: "No assets yet", scans: 0 }]).slice(0, 18).map((asset, index) => (
              <div key={`${asset.host}-${index}`} className={`heat-cell heat-${Math.min(4, asset.scans ?? 0)}`}>
                <strong>{asset.host}</strong>
                <span>{asset.scans ?? 0} scans</span>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader icon={GitBranch} title="Attack-path model" meta="Risk propagation" />
          <div className="attack-chain">
            {["Internet", "Asset", "Endpoint", "Finding", "Owner"].map((step, index) => (
              <div key={step} className={index < 3 ? "active" : ""}>
                <span>{index + 1}</span>
                <strong>{step}</strong>
              </div>
            ))}
          </div>
        </Card>
      </section>
    </section>
  );
}
