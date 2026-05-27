import React, { useMemo, useState } from "react";
import {
  Activity,
  Bell,
  Boxes,
  Building2,
  ChevronLeft,
  ChevronRight,
  ClipboardCheck,
  Code2,
  Command,
  FileText,
  Gauge,
  GitBranch,
  Layers3,
  MonitorDot,
  Network,
  PlugZap,
  Radar,
  Rocket,
  Search,
  Settings,
  Shield,
  Siren,
  Sparkles,
  Telescope,
} from "lucide-react";

const navSections = [
  {
    label: "Command Center",
    items: [
      ["home", Gauge, "Executive Overview"],
      ["attack-surface", Network, "Attack Surface Intelligence"],
      ["exposure", Shield, "Exposure Operations"],
      ["research", Telescope, "Offensive Research"],
      ["threat-intel", Siren, "Threat Intelligence"],
    ],
  },
  {
    label: "Operations",
    items: [
      ["apis", Code2, "API Security"],
      ["monitoring", MonitorDot, "Monitoring"],
      ["findings", ClipboardCheck, "Findings & Validation"],
      ["assets", Boxes, "Asset Inventory"],
      ["recon", Radar, "Discovery"],
    ],
  },
  {
    label: "Platform",
    items: [
      ["platform", Layers3, "Platform"],
      ["cicd", GitBranch, "DevSecOps"],
      ["reports", FileText, "Reports"],
      ["compliance", ClipboardCheck, "Compliance"],
      ["integrations", PlugZap, "Integrations"],
      ["settings", Settings, "Settings"],
    ],
  },
];

export function EnterpriseLayout({ page, onNavigate, children }) {
  const [collapsed, setCollapsed] = useState(false);
  const current = useMemo(() => {
    for (const section of navSections) {
      const found = section.items.find(([key]) => key === page);
      if (found) return found[2];
    }
    return "Overview";
  }, [page]);

  return (
    <div className={`enterprise-shell ${collapsed ? "sidebar-collapsed" : ""}`}>
      <aside className="enterprise-sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark"><Shield size={18} /></div>
          <div className="brand-text">
            <strong>AdaptiveScan</strong>
            <span>Offensive Exposure OS</span>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="Primary navigation">
          {navSections.map((section) => (
            <div key={section.label} className="sidebar-section">
              <small>{section.label}</small>
              {section.items.map(([key, Icon, label]) => (
                <button
                  type="button"
                  key={key}
                  className={page === key ? "active" : ""}
                  onClick={() => onNavigate(key)}
                  title={label}
                >
                  <Icon size={18} />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>

        <button className="collapse-button" type="button" onClick={() => setCollapsed((value) => !value)}>
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          <span>Collapse</span>
        </button>
      </aside>

      <section className="enterprise-main">
        <header className="enterprise-topbar">
          <div className="workspace-switcher">
            <Building2 size={17} />
            <div>
              <span>Workspace</span>
              <strong>AdaptiveScan / Global Exposure</strong>
            </div>
          </div>
          <label className="global-search">
            <Search size={16} />
            <input placeholder="Search assets, APIs, CVEs, attack paths" />
          </label>
          <div className="topbar-actions">
            <button type="button" className="quick-scan" title="Start exposure assessment" onClick={() => onNavigate("scan")}><Rocket size={17} /></button>
            <button type="button" title="Command menu"><Command size={17} /></button>
            <button type="button" title="Notifications"><Bell size={17} /></button>
            <button type="button" title="Activity"><Activity size={17} /></button>
          </div>
        </header>
        <div className="workspace-frame">
          <main>{children}</main>
          <aside className="intelligence-drawer" aria-label="Contextual intelligence">
            <div className="drawer-signal">
              <Sparkles size={16} />
              <span>AI Triage</span>
              <strong>{current}</strong>
              <p>Prioritize exploitable internet exposure, identity boundary drift, and attack paths with clear owner handoff.</p>
            </div>
            <div className="drawer-mini-list">
              <div><span>Active telemetry</span><strong>Live</strong></div>
              <div><span>Exposure policy</span><strong>Enforced</strong></div>
              <div><span>Scope</span><strong>Production</strong></div>
            </div>
          </aside>
        </div>
      </section>
    </div>
  );
}
