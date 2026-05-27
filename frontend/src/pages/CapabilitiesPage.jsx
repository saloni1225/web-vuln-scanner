import React, { useEffect, useState } from "react";
import { BrainCircuit, Building2, CheckCircle2, Clock3, GitBranch, KeyRound, Layers3, Network, ShieldCheck, Users } from "lucide-react";
import { fetchEnterpriseFoundation, fetchProductCapabilities, fetchTenancyOverview } from "../services/api.js";

const statusLabels = {
  implemented: "Implemented",
  partial: "In progress",
  planned: "Planned",
};

const statusIcons = {
  implemented: CheckCircle2,
  partial: Clock3,
  planned: Layers3,
};

export function CapabilitiesPage() {
  const [payload, setPayload] = useState({ capabilities: [], summary: {} });
  const [foundation, setFoundation] = useState({ lifecycle: [], compliance: [], ci_templates: [], distributed_architecture: [] });
  const [tenancy, setTenancy] = useState({ organizations: [], workspaces: [], team_members: [], api_keys: [], rbac_roles: [] });
  const [error, setError] = useState("");

  useEffect(() => {
    fetchProductCapabilities()
      .then(setPayload)
      .catch((err) => setError(String(err.message || "Could not load capability roadmap")));
    fetchEnterpriseFoundation()
      .then(setFoundation)
      .catch(() => setFoundation({ lifecycle: [], compliance: [], ci_templates: [], distributed_architecture: [] }));
    fetchTenancyOverview()
      .then(setTenancy)
      .catch(() => setTenancy({ organizations: [], workspaces: [], team_members: [], api_keys: [], rbac_roles: [] }));
  }, []);

  return (
    <section className="workspace capabilities-workspace hacker-surface">
      <section className="scan-hero">
        <div>
          <h1>Enterprise Coverage</h1>
          <p>Track the 14 product-grade security platform areas, what is already implemented, and what should be built next.</p>
        </div>
        <div className="hero-status-cluster">
          <div><span>Total areas</span><strong>{payload.summary?.total ?? 14}</strong></div>
          <div><span>In progress</span><strong>{payload.summary?.partial ?? 0}</strong></div>
        </div>
      </section>

      <section className="metrics-grid report-metrics">
        <article className="metric-card">
          <ShieldCheck size={18} />
          <span>Implemented</span>
          <strong>{payload.summary?.implemented ?? 0}</strong>
        </article>
        <article className="metric-card">
          <Clock3 size={18} />
          <span>In progress</span>
          <strong>{payload.summary?.partial ?? 0}</strong>
        </article>
        <article className="metric-card">
          <Layers3 size={18} />
          <span>Planned</span>
          <strong>{payload.summary?.planned ?? 0}</strong>
        </article>
        <article className="metric-card">
          <BrainCircuit size={18} />
          <span>Build path</span>
          <strong>14</strong>
        </article>
      </section>

      {error ? <article className="panel error-panel"><strong>{error}</strong></article> : null}

      <section className="enterprise-foundation-grid">
        <article className="panel enterprise-foundation-card">
          <header className="panel-header">
            <div><Building2 size={18} /><strong>SaaS Tenancy</strong></div>
            <span>{tenancy.organizations.length} orgs</span>
          </header>
          <div className="foundation-list">
            <div>
              <strong>Organizations</strong>
              <small>{tenancy.organizations.length ? tenancy.organizations.map((item) => item.name).join(", ") : "Create organizations from the API to isolate customers."}</small>
            </div>
            <div>
              <strong>Workspaces</strong>
              <small>{tenancy.workspaces.length} scoped scan environments</small>
            </div>
          </div>
        </article>

        <article className="panel enterprise-foundation-card">
          <header className="panel-header">
            <div><Users size={18} /><strong>RBAC Model</strong></div>
            <span>{tenancy.rbac_roles.length} roles</span>
          </header>
          <div className="foundation-list">
            {tenancy.rbac_roles.map((item) => (
              <div key={item.role}>
                <strong>{item.role}</strong>
                <small>{item.permissions.join(", ")}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel enterprise-foundation-card">
          <header className="panel-header">
            <div><KeyRound size={18} /><strong>API Keys</strong></div>
            <span>{tenancy.api_keys.length}</span>
          </header>
          <div className="foundation-list">
            {(tenancy.api_keys.length ? tenancy.api_keys : [{ key_id: "empty", name: "No keys issued", key_prefix: "Use POST /api/api-keys", scopes: [] }]).map((item) => (
              <div key={item.key_id}>
                <strong>{item.name}</strong>
                <small>{item.key_prefix} {item.scopes?.length ? `• ${item.scopes.join(", ")}` : ""}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel enterprise-foundation-card">
          <header className="panel-header">
            <div><ShieldCheck size={18} /><strong>Vulnerability Lifecycle</strong></div>
            <span>{foundation.lifecycle.length} states</span>
          </header>
          <div className="foundation-timeline">
            {foundation.lifecycle.map((item, index) => (
              <div key={item.state}>
                <strong>{index + 1}. {item.label}</strong>
                <small>{item.description}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel enterprise-foundation-card">
          <header className="panel-header">
            <div><GitBranch size={18} /><strong>CI/CD Templates</strong></div>
            <span>{foundation.ci_templates.length}</span>
          </header>
          <div className="foundation-list">
            {foundation.ci_templates.map((item) => (
              <div key={item.platform}>
                <strong>{item.platform}</strong>
                <small>{item.file}</small>
                <code>{item.command}</code>
              </div>
            ))}
          </div>
        </article>

        <article className="panel enterprise-foundation-card">
          <header className="panel-header">
            <div><Layers3 size={18} /><strong>Compliance Layer</strong></div>
            <span>{foundation.compliance.length}</span>
          </header>
          <div className="foundation-list">
            {foundation.compliance.map((item) => (
              <div key={item.framework}>
                <strong>{item.framework}</strong>
                <small>{Object.keys(item.mappings ?? {}).join(", ")}</small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel enterprise-foundation-card">
          <header className="panel-header">
            <div><Network size={18} /><strong>Distributed Architecture</strong></div>
            <span>{foundation.distributed_architecture.length}</span>
          </header>
          <div className="foundation-list">
            {foundation.distributed_architecture.map((item) => (
              <div key={item.layer}>
                <strong>{item.layer}</strong>
                <small>{item.current} → {item.target}</small>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="capability-roadmap-grid">
        {(payload.capabilities ?? []).map((capability, index) => {
          const StatusIcon = statusIcons[capability.status] ?? Layers3;
          return (
            <article key={capability.id} className={`panel capability-roadmap-card status-${capability.status}`}>
              <header className="panel-header">
                <div>
                  <StatusIcon size={18} />
                  <strong>{index + 1}. {capability.title}</strong>
                </div>
                <span>{statusLabels[capability.status] ?? capability.status}</span>
              </header>
              <div className="roadmap-columns">
                <section>
                  <strong>Implemented</strong>
                  <ul>
                    {(capability.implemented?.length ? capability.implemented : ["No production feature yet"]).map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </section>
                <section>
                  <strong>Next tasks</strong>
                  <ul>
                    {capability.next_tasks.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </section>
              </div>
            </article>
          );
        })}
      </section>
    </section>
  );
}
