import React, { useEffect, useState } from "react";
import { Activity, Bot, Boxes, Database, HardDrive, KeyRound, Network, RadioTower, ShieldCheck, Users } from "lucide-react";
import { fetchPlatformDatabase, fetchPlatformObservability, fetchPlatformOverview, fetchPlatformQueue } from "../services/api.js";

function Metric({ icon: Icon, label, value }) {
  return (
    <article className="metric-card">
      <Icon size={18} />
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

export function PlatformPage() {
  const [platform, setPlatform] = useState(null);
  const [queue, setQueue] = useState(null);
  const [database, setDatabase] = useState(null);
  const [observability, setObservability] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      fetchPlatformOverview(),
      fetchPlatformQueue(),
      fetchPlatformDatabase(),
      fetchPlatformObservability(),
    ])
      .then(([overview, queueState, databaseState, observabilityState]) => {
        setPlatform(overview);
        setQueue(queueState);
        setDatabase(databaseState);
        setObservability(observabilityState);
      })
      .catch((err) => setError(String(err.message || "Could not load platform overview")));
  }, []);

  const metrics = platform?.metrics ?? {};
  const architecture = platform?.architecture ?? {};
  const queues = queue?.queues ?? architecture.queue?.queues ?? [];
  const workers = architecture.workers?.worker_pools ?? [];
  const monitoring = platform?.monitoring ?? {};
  const databaseState = database ?? architecture.database ?? {};
  const observabilityState = observability ?? architecture.observability ?? {};

  return (
    <section className="workspace platform-workspace hacker-surface">
      <section className="scan-hero">
        <div>
          <h1>Security Operations Platform</h1>
          <p>AdaptiveScan control plane for continuous attack surface intelligence, queued scanning, enterprise reporting, and AI-assisted risk operations.</p>
        </div>
        <div className="hero-status-cluster">
          <div><span>Tracked hosts</span><strong>{platform?.assets?.host_count ?? 0}</strong></div>
          <div><span>Risk gate failures</span><strong>{metrics.risk_gate_failures ?? 0}</strong></div>
        </div>
      </section>

      {error ? <article className="panel error-panel"><strong>{error}</strong></article> : null}

      <section className="metrics-grid report-metrics">
        <Metric icon={Activity} label="Scans" value={metrics.scan_count ?? 0} />
        <Metric icon={ShieldCheck} label="Findings" value={metrics.finding_count ?? 0} />
        <Metric icon={Network} label="Endpoints" value={metrics.endpoint_count ?? 0} />
        <Metric icon={RadioTower} label="High risk" value={metrics.high_count ?? 0} />
      </section>

      <section className="platform-grid">
        <article className="panel platform-card">
          <header className="panel-header">
            <div><Boxes size={18} /><strong>Reference Architecture</strong></div>
            <span>{platform?.product ?? "AdaptiveScan"}</span>
          </header>
          <div className="architecture-ladder">
            {["frontend", "api_gateway", "telemetry", "ai_risk_engine"].map((key) => (
              <div key={key}>
                <strong>{key.replaceAll("_", " ")}</strong>
                <small>{architecture[key]}</small>
              </div>
            ))}
            <div>
              <strong>database</strong>
              <small>{databaseState.engine ?? "sqlite"} · {databaseState.mode ?? "local-dev"} · {databaseState.migration_tool ?? "alembic"}</small>
            </div>
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><Database size={18} /><strong>Redis Queue Topology</strong></div>
            <span>{queue?.broker ?? architecture.queue?.broker ?? "redis"}</span>
          </header>
          <div className="queue-grid">
            {queues.map((queue) => (
              <div key={queue.name}>
                <strong>{queue.name}</strong>
                <small>{queue.purpose} · {queue.routing_key ?? "scan.*"}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><Bot size={18} /><strong>Worker Pools</strong></div>
            <span>{architecture.workers?.mode ?? "local-dev"}</span>
          </header>
          <div className="queue-grid">
            {workers.map((worker) => (
              <div key={worker.name}>
                <strong>{worker.name}</strong>
                <small>{worker.desired_concurrency} concurrency · {worker.status}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><HardDrive size={18} /><strong>Object Storage</strong></div>
            <span>{architecture.object_storage?.provider ?? "local"}</span>
          </header>
          <div className="architecture-ladder">
            <div>
              <strong>{architecture.object_storage?.artifact_count ?? 0} artifacts</strong>
              <small>{architecture.object_storage?.path}</small>
            </div>
            {(architecture.object_storage?.upgrade_path ?? []).map((item) => (
              <div key={item}>
                <strong>{item}</strong>
                <small>Commercial SaaS storage path</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><Database size={18} /><strong>PostgreSQL Readiness</strong></div>
            <span>{databaseState.engine ?? "sqlite"}</span>
          </header>
          <div className="architecture-ladder">
            <div>
              <strong>{databaseState.partitioning_strategy ?? "local storage"}</strong>
              <small>{databaseState.tenant_isolation ?? "workspace scoped"}</small>
            </div>
            {(databaseState.migration_plan ?? []).slice(0, 4).map((migration) => (
              <div key={migration.revision}>
                <strong>{migration.revision}</strong>
                <small>{migration.description}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><RadioTower size={18} /><strong>Observability</strong></div>
            <span>{observabilityState.prometheus?.enabled ? "Prometheus" : "Local"}</span>
          </header>
          <div className="queue-grid">
            {(observabilityState.dashboards ?? []).map((dashboard) => (
              <div key={dashboard}>
                <strong>{dashboard}</strong>
                <small>{observabilityState.prometheus?.endpoint ?? "/api/metrics"}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><Users size={18} /><strong>RBAC Enforcement</strong></div>
            <span>{platform?.rbac?.roles?.length ?? 0} roles</span>
          </header>
          <div className="queue-grid">
            {(platform?.rbac?.roles ?? []).map((role) => (
              <div key={role.role}>
                <strong>{role.role}</strong>
                <small>{role.permissions.join(", ")}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><KeyRound size={18} /><strong>Platform Security</strong></div>
            <span>{platform?.security?.headers?.length ?? 0} headers</span>
          </header>
          <div className="queue-grid">
            {(platform?.security?.controls ?? []).map((control) => (
              <div key={control}>
                <strong>{control}</strong>
                <small>Enforced control plane safeguard</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel platform-card">
          <header className="panel-header">
            <div><Activity size={18} /><strong>Continuous Monitoring</strong></div>
            <span>{monitoring.scheduler?.recurring_scan_count ?? 0} targets</span>
          </header>
          <div className="queue-grid">
            {(monitoring.alert_policies ?? []).map((policy) => (
              <div key={policy.name}>
                <strong>{policy.name}</strong>
                <small>{policy.condition} · {policy.channels.join(", ")}</small>
              </div>
            ))}
          </div>
        </article>
      </section>
    </section>
  );
}
