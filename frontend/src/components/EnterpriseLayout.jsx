import React, { useEffect, useMemo, useState } from "react";
import { useCursorGlow } from "../hooks/useCursorGlow.js";
import { useAuth } from "../context/AuthContext.jsx";
import {
  Activity,
  Bell,
  Boxes,
  Building2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Circle,
  ClipboardCheck,
  Code2,
  Command,
  CreditCard,
  ExternalLink,
  FileText,
  Gauge,
  GitBranch,
  KeyRound,
  Layers3,
  LoaderCircle,
  Menu,
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
  Users,
  X,
  Sun,
  Moon,
} from "lucide-react";
import { fetchActiveScans, fetchOperationsIntelligence, fetchReports, startScan } from "../services/api.js";
import { Logo } from "./Logo.jsx";
import { createScanSocket } from "../services/socket.js";

const navSections = [
  {
    label: "Executive",
    icon: Gauge,
    route: "dashboard",
  },
  {
    label: "Organization",
    icon: Building2,
    items: [
      ["organization", Building2, "Organization"],
      ["team", Users, "Team"],
      ["billing", CreditCard, "Subscription"],
      ["settings", Settings, "Security Settings"],
    ],
  },
  {
    label: "Assets",
    icon: Boxes,
    items: [
      ["assets", Boxes, "Asset Inventory"],
      ["recon", Radar, "Discovery"],
      ["attack-surface", Network, "Attack Surface"],
      ["apis", Code2, "APIs"],
    ],
  },
  {
    label: "Monitoring",
    icon: MonitorDot,
    items: [
      ["monitoring", MonitorDot, "Continuous Monitoring"],
      ["workflows", GitBranch, "Workflows"],
      ["drift", Activity, "Drift Detection"],
      ["notifications", Bell, "Notifications"],
      ["telemetry", Command, "Activity Timeline"],
    ],
  },
  {
    label: "Exposure",
    icon: Shield,
    items: [
      ["exposure", Shield, "Exposure Overview"],
      ["threat-intel", Siren, "Threat Intelligence"],
      ["attack-paths", GitBranch, "Attack Paths"],
    ],
  },
  {
    label: "Findings",
    icon: ClipboardCheck,
    items: [
      ["findings", ClipboardCheck, "Findings"],
      ["validation", ClipboardCheck, "Validation"],
    ],
  },
  {
    label: "Reports",
    icon: FileText,
    items: [
      ["reports", FileText, "Executive Reports"],
      ["technical-reports", FileText, "Technical Reports"],
      ["compliance", ClipboardCheck, "Compliance Reports"],
    ],
  },
  {
    label: "Integrations",
    icon: PlugZap,
    items: [
      ["integrations", PlugZap, "Integrations"],
      ["cicd", GitBranch, "DevSecOps"],
      ["platform", Layers3, "API Platform"],
    ],
  },
];

function SidebarButton({ children, className = "", magnetic = true, ...props }) {
  const ref = useCursorGlow({ magnetic, magneticStrength: 0.12 });
  return (
    <button ref={ref} className={`${className} spotlight-sidebar-item`} {...props}>
      <span className="spotlight-sidebar-glow" />
      <span className="spotlight-sidebar-content" style={{ display: "inline-flex", alignItems: "center", width: "100%", gap: "inherit" }}>
        {children}
      </span>
    </button>
  );
}

const ROLE_PERMISSIONS = {
  owner: new Set([
    "org:admin", "workspace:admin", "workspace:read", "scan:run", "scan:read", "finding:manage", "report:read", "api_key:manage",
    "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read", "orchestration:read",
    "threat_intel:read", "ai:read", "compliance:read", "integration:manage", "devsecops:read", "rbac:admin", "monitoring:read"
  ]),
  admin: new Set([
    "workspace:admin", "workspace:read", "scan:run", "scan:read", "finding:manage", "report:read", "api_key:manage",
    "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read", "orchestration:read",
    "threat_intel:read", "ai:read", "compliance:read", "integration:manage", "devsecops:read", "monitoring:read"
  ]),
  security_engineer: new Set([
    "workspace:read", "scan:run", "scan:read", "finding:manage", "report:read",
    "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read",
    "threat_intel:read", "ai:read", "devsecops:read", "monitoring:read"
  ]),
  analyst: new Set(["workspace:read", "scan:run", "scan:read", "finding:manage", "report:read", "monitoring:read"]),
  viewer: new Set(["workspace:read", "scan:read", "report:read", "monitoring:read"]),
  "ci-bot": new Set(["scan:run", "scan:read", "report:read", "devsecops:read"]),
};

function hasPermission(role, permission) {
  if (!role) return false;
  const permissions = ROLE_PERMISSIONS[role.toLowerCase().replace("-", "_")] || ROLE_PERMISSIONS[role] || new Set();
  return permissions.has(permission);
}

const PAGE_PERMISSIONS = {
  dashboard: "scan:read",
  assets: "workspace:read",
  recon: "scan:read",
  scan: "scan:run",
  exposure: "exposure:read",
  "attack-paths": "attack_path:read",
  research: "ai:read",
  "threat-intel": "threat_intel:read",
  drift: "drift:read",
  telemetry: "telemetry:read",
  findings: "scan:read",
  "attack-surface": "attack_graph:read",
  apis: "scan:read",
  reports: "report:read",
  "technical-reports": "report:read",
  compliance: "compliance:read",
  integrations: "integration:manage",
  monitoring: "monitoring:read",
  workflows: "monitoring:read",
  notifications: "monitoring:read",
  cicd: "devsecops:read",
  capabilities: "scan:read",
  platform: "orchestration:read",
  team: "rbac:admin",
  billing: "org:admin",
  settings: "workspace:admin",
  "audit-logs": "rbac:admin",
  "system-health": "orchestration:read",
};

export function EnterpriseLayout({ page, onNavigate, theme = "dark", onChangeTheme, children }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [expandedSection, setExpandedSection] = useState(() => {
    if (typeof window === "undefined") return "Assets";
    return window.localStorage.getItem("adaptiveScan.expandedNav") || "Assets";
  });
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [target, setTarget] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [activePanel, setActivePanel] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [runMode, setRunMode] = useState("");
  const [progress, setProgress] = useState({ progress: 0, status: "idle", message: "Ready for an intelligence run." });
  const [operations, setOperations] = useState(null);
  const [reports, setReports] = useState([]);
  const [activeScans, setActiveScans] = useState([]);
  const [authOpen, setAuthOpen] = useState(false);
  const [jwtToken, setJwtToken] = useState("");
  const [authHeader, setAuthHeader] = useState("");
  const [toast, setToast] = useState("");
  const { user, logout } = useAuth();
  const [wsConnected, setWsConnected] = useState(false);

  const userRole = user?.role || "viewer";

  const filteredNavSections = useMemo(() => {
    return navSections
      .map((section) => {
        if (section.route) {
          const reqPerm = PAGE_PERMISSIONS[section.route];
          if (reqPerm && !hasPermission(userRole, reqPerm)) return null;
          return section;
        }
        const visibleItems = section.items.filter(([key]) => {
          const reqPerm = PAGE_PERMISSIONS[key];
          return !reqPerm || hasPermission(userRole, reqPerm);
        });
        if (visibleItems.length === 0) return null;
        return { ...section, items: visibleItems };
      })
      .filter(Boolean);
  }, [userRole]);

  const current = useMemo(() => {
    for (const section of navSections) {
      if (section.route === page) return section.label;
      const found = section.items?.find(([key]) => key === page);
      if (found) return found[2];
    }
    return "Overview";
  }, [page]);
  const notifications = useMemo(() => buildNotifications(operations), [operations]);
  const activities = useMemo(() => buildActivities(operations, reports, activeScans, progress), [operations, reports, activeScans, progress]);
  const unreadCount = notifications.filter((item) => item.status === "unread").length;
  const commandItems = useMemo(() => buildCommandItems(operations, reports, activeScans, launchScan, userRole), [operations, reports, activeScans, userRole]);
  const filteredCommands = useMemo(() => {
    const value = paletteQuery.trim().toLowerCase();
    if (!value) return commandItems.slice(0, 9);
    return commandItems
      .filter((item) => `${item.label} ${item.group} ${item.keywords ?? ""}`.toLowerCase().includes(value))
      .slice(0, 12);
  }, [commandItems, paletteQuery]);

  useEffect(() => {
    refreshOperations();
    const timer = setInterval(refreshOperations, 7000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const owningSection = navSections.find((section) => section.items?.some(([key]) => key === page));
    if (owningSection) {
      setExpandedSection(owningSection.label);
      window.localStorage.setItem("adaptiveScan.expandedNav", owningSection.label);
    }
  }, [page]);

  useEffect(() => {
    function handleCommandShortcut(event) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
      }
      if (event.key === "Escape") {
        setPaletteOpen(false);
        setMobileOpen(false);
      }
    }
    window.addEventListener("keydown", handleCommandShortcut);
    return () => window.removeEventListener("keydown", handleCommandShortcut);
  }, []);

  useEffect(() => {
    const socket = createScanSocket(
      (event) => {
        if (event.progress !== undefined || event.message) {
          setProgress((currentProgress) => ({
            progress: event.progress ?? currentProgress.progress,
            status: event.status ?? currentProgress.status,
            message: event.message ?? currentProgress.message,
          }));
        }
        if (event.event === "scan_started") {
          setIsRunning(true);
          setActivePanel("activity");
        }
        if (event.event === "scan_completed") {
          setIsRunning(false);
          setProgress({ progress: 100, status: "completed", message: event.message ?? "Intelligence run completed." });
          onNavigate("attack-surface");
          refreshOperations();
        }
        if (event.status === "failed") {
          setIsRunning(false);
          setActivePanel("activity");
        }
      },
      () => setWsConnected(true),
      () => setWsConnected(false)
    );
    return () => socket.close();
  }, [onNavigate]);


  async function refreshOperations() {
    try {
      const [ops, reportList, active] = await Promise.all([
        fetchOperationsIntelligence(),
        fetchReports(),
        fetchActiveScans(),
      ]);
      setOperations(ops);
      setReports(reportList);
      setActiveScans(active);
    } catch {
      // Keep the shell operational even when the API is starting.
    }
  }

  function setPanel(name) {
    setActivePanel((currentPanel) => (currentPanel === name ? "" : name));
  }

  function toggleSection(label) {
    setExpandedSection((currentSection) => {
      const nextSection = currentSection === label ? "" : label;
      window.localStorage.setItem("adaptiveScan.expandedNav", nextSection);
      return nextSection;
    });
  }

  function navigateTo(route) {
    onNavigate(route);
    setMobileOpen(false);
  }

  function runCommand(item) {
    setPaletteOpen(false);
    setPaletteQuery("");
    if (item.action) {
      item.action();
      return;
    }
    navigateTo(item.route);
  }

  function normalizeTarget(value) {
    const trimmed = value.trim();
    if (!trimmed) return "";
    return trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  }

  function targetHost(value) {
    try {
      return new URL(normalizeTarget(value)).hostname;
    } catch {
      return "";
    }
  }

  async function launchScan(mode) {
    const normalizedTarget = normalizeTarget(target);
    if (!normalizedTarget) {
      setToast("Enter a target first.");
      setDrawerOpen(true);
      return;
    }
    const host = targetHost(normalizedTarget);
    const modeConfig = {
      quick: { label: "Quick Intelligence Scan", profile: "quick", route: "attack-surface" },
      deep: { label: "Deep Exposure Analysis", profile: "deep", route: "exposure" },
      api: { label: "API Intelligence Scan", profile: "api", route: "apis" },
      monitoring: { label: "Continuous Monitoring", profile: "passive", route: "monitoring" },
      authenticated: { label: "Authenticated Scan", profile: "authenticated", route: "attack-paths" },
    }[mode] ?? { label: "Intelligence Run", profile: "deep", route: "attack-surface" };
    setRunMode(modeConfig.label);
    setIsRunning(true);
    setDrawerOpen(true);
    setActivePanel("activity");
    setToast("");
    setProgress({ progress: 4, status: "running", message: `${modeConfig.label} queued for ${normalizedTarget}` });
    try {
      const headers = authHeader.trim() ? { Authorization: authHeader.trim() } : {};
      const scan = await startScan(normalizedTarget, {
        scanProfile: modeConfig.profile,
        authorizationConfirmed: true,
        domainAllowlist: host ? [host] : [],
        jwtToken,
        headers,
        enableApiFuzzing: mode !== "monitoring",
        enableGraphqlChecks: mode !== "quick",
        enableFindingValidator: true,
      });
      setProgress({ progress: 100, status: "completed", message: `${modeConfig.label} completed: ${scan?.summary?.finding_count ?? 0} findings` });
      setIsRunning(false);
      onNavigate(modeConfig.route);
      refreshOperations();
    } catch (error) {
      setIsRunning(false);
      setProgress({ progress: 100, status: "failed", message: String(error.message || "Run failed") });
      setActivePanel("activity");
    }
  }

  return (
    <div className={`enterprise-shell ${collapsed ? "sidebar-collapsed" : ""} ${mobileOpen ? "mobile-nav-open" : ""}`}>
      <aside className="enterprise-sidebar">
        <div className="sidebar-brand">
          <Logo size={24} />
          <div className="brand-text">
            <strong>AdaptiveScan</strong>
            <span>External Exposure Platform</span>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="Primary navigation">
          {filteredNavSections.map((section) => (
            <div key={section.label} className={`sidebar-section ${section.route === page ? "active-section" : ""}`}>
              {section.route ? (
                <SidebarButton
                  type="button"
                  className={`sidebar-link root-link ${page === section.route ? "active" : ""}`}
                  onClick={() => navigateTo(section.route)}
                  title={section.label}
                >
                  <section.icon size={18} />
                  <span>{section.label}</span>
                </SidebarButton>
              ) : (
                <>
                  <SidebarButton
                    type="button"
                    className={`sidebar-group-trigger ${expandedSection === section.label ? "expanded" : ""}`}
                    aria-expanded={expandedSection === section.label}
                    aria-controls={`nav-section-${section.label.toLowerCase().replaceAll(" ", "-")}`}
                    onClick={() => toggleSection(section.label)}
                    title={section.label}
                  >
                    <section.icon size={18} />
                    <span>{section.label}</span>
                    <ChevronDown className="sidebar-chevron" size={15} />
                  </SidebarButton>
                  <div
                    id={`nav-section-${section.label.toLowerCase().replaceAll(" ", "-")}`}
                    className="sidebar-subnav"
                    data-expanded={expandedSection === section.label}
                  >
                    {section.items.map(([key, Icon, label]) => (
                      <SidebarButton
                        type="button"
                        key={key}
                        className={`sidebar-link ${page === key ? "active" : ""}`}
                        onClick={() => navigateTo(key)}
                        title={label}
                      >
                        <Icon size={16} />
                        <span>{label}</span>
                      </SidebarButton>
                    ))}
                  </div>
                </>
              )}
            </div>
          ))}
          <SidebarButton
            type="button"
            className="sidebar-link logout-button-sidebar"
            onClick={logout}
            title="Logout"
            style={{ marginTop: "12px", borderTop: "1px dashed var(--border-soft)", width: "100%" }}
          >
            <KeyRound size={16} />
            <span>Logout</span>
          </SidebarButton>
        </nav>

        <div className="ws-status-container" style={{ display: "flex", flexDirection: "column", gap: "4px", padding: "8px 18px", borderTop: "1px solid var(--border-soft)", marginBottom: "8px" }}>
          {!collapsed && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: wsConnected ? "#00ffff" : "#ff0055", fontSize: "0.75rem", fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase" }}>
              <span style={{
                display: "inline-block",
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                backgroundColor: wsConnected ? "#00ffff" : "#ff0055",
                boxShadow: wsConnected ? "0 0 8px #00ffff" : "0 0 8px #ff0055",
                animation: wsConnected ? "none" : "blink 1s infinite alternate"
              }} />
              Telemetry Feed: {wsConnected ? "ONLINE" : "OFFLINE"}
            </div>
          )}
        </div>


        {!collapsed && (
          <div className="sidebar-copyright-recoxy" style={{ padding: "8px 18px", fontSize: "0.7rem", color: "var(--subtle)", borderTop: "1px solid var(--border-soft)", marginBottom: "4px" }}>
            All rights reserved to Recoxy
          </div>
        )}

        <button className="collapse-button" type="button" onClick={() => setCollapsed((value) => !value)}>
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          <span>Collapse</span>
        </button>
      </aside>

      <section className="enterprise-main">
        <header className="enterprise-topbar">
          <button className="mobile-menu-button" type="button" onClick={() => setMobileOpen((value) => !value)} aria-label="Toggle navigation">
            {mobileOpen ? <X size={17} /> : <Menu size={17} />}
          </button>
          <div className="workspace-switcher">
            <Building2 size={17} />
            <div>
              <span>Workspace</span>
              <strong>AdaptiveScan / Global Exposure</strong>
            </div>
          </div>
          {hasPermission(userRole, "scan:run") && (
            <section className="ops-command-bar" aria-label="Operational scan command">
              <label className="ops-target-input">
                <Search size={16} />
                <input
                  value={target}
                  placeholder="Add domain, API, or internet-facing asset"
                  onChange={(event) => setTarget(event.target.value)}
                  onFocus={() => setDrawerOpen(true)}
                />
              </label>
              <button type="button" className="ops-run primary" onClick={() => launchScan("quick")} disabled={isRunning}>
                {isRunning && runMode.includes("Quick") ? <LoaderCircle className="spin" size={15} /> : <Radar size={15} />}
                Assess Asset
              </button>
              <button type="button" className="ops-run" onClick={() => launchScan("deep")} disabled={isRunning}>
                {isRunning && runMode.includes("Deep") ? <LoaderCircle className="spin" size={15} /> : <Shield size={15} />}
                Analyze Exposure
              </button>
              <button type="button" className="ops-run" onClick={() => launchScan("monitoring")} disabled={isRunning}>
                <MonitorDot size={15} />
                Start Monitoring
              </button>
            </section>
          )}
          <div className="topbar-actions">

            {hasPermission(userRole, "scan:run") && (
              <button type="button" className="quick-scan" title="Open scan drawer" onClick={() => setDrawerOpen(true)}><Rocket size={17} /></button>
            )}
            <button type="button" className={paletteOpen ? "active" : ""} title="Command palette" onClick={() => setPaletteOpen(true)}><Command size={17} /></button>
            <button type="button" className={activePanel === "notifications" ? "active" : ""} title="Notifications" onClick={() => setPanel("notifications")}>
              <Bell size={17} />
              {unreadCount ? <span className="action-badge">{unreadCount}</span> : null}
            </button>
            <button type="button" className={activePanel === "activity" ? "active" : ""} title="Activity" onClick={() => setPanel("activity")}><Activity size={17} /></button>
          </div>
        </header>
        {activePanel ? (
          <OperationalPanel
            panel={activePanel}
            notifications={notifications}
            activities={activities}
            progress={progress}
            isRunning={isRunning}
            onNavigate={onNavigate}
            onClose={() => setActivePanel("")}
            onOpenScan={(mode) => {
              setActivePanel("");
              setDrawerOpen(true);
              if (mode) launchScan(mode);
            }}
          />
        ) : null}
        <div className="workspace-frame">
          <main key={page} className="page-transition-wrapper">{children}</main>
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
      {mobileOpen ? <button className="mobile-nav-backdrop" type="button" aria-label="Close navigation" onClick={() => setMobileOpen(false)} /> : null}
      {paletteOpen ? (
        <CommandPalette
          query={paletteQuery}
          setQuery={setPaletteQuery}
          items={filteredCommands}
          onClose={() => setPaletteOpen(false)}
          onRun={runCommand}
        />
      ) : null}
      {drawerOpen ? (
        <ScanCommandDrawer
          target={target}
          setTarget={setTarget}
          progress={progress}
          runMode={runMode}
          isRunning={isRunning}
          authOpen={authOpen}
          setAuthOpen={setAuthOpen}
          jwtToken={jwtToken}
          setJwtToken={setJwtToken}
          authHeader={authHeader}
          setAuthHeader={setAuthHeader}
          toast={toast}
          onClose={() => setDrawerOpen(false)}
          onLaunch={launchScan}
          onNavigate={onNavigate}
        />
      ) : null}
    </div>
  );
}

function CommandPalette({ query, setQuery, items, onClose, onRun }) {
  return (
    <div className="command-palette-backdrop" onMouseDown={onClose}>
      <section className="command-palette" role="dialog" aria-modal="true" aria-label="Global search" onMouseDown={(event) => event.stopPropagation()}>
        <label className="command-search">
          <Search size={18} />
          <input
            value={query}
            placeholder="Search pages, assets, findings, reports, or scans"
            onChange={(event) => setQuery(event.target.value)}
            autoFocus
          />
          <kbd>Esc</kbd>
        </label>
        <div className="command-results" role="listbox">
          {items.length ? items.map((item) => {
            const Icon = item.icon || Search;
            return (
              <button type="button" key={`${item.group}-${item.label}`} onClick={() => onRun(item)} role="option">
                <Icon size={16} />
                <span>
                  <strong>{item.label}</strong>
                  <small>{item.group}</small>
                </span>
                <ChevronRight size={14} />
              </button>
            );
          }) : <div className="command-empty">No matching commands</div>}
        </div>
      </section>
    </div>
  );
}

function OperationalPanel({ panel, notifications, activities, progress, isRunning, onNavigate, onClose, onOpenScan }) {
  const title = panel === "notifications" ? "Notification Center" : panel === "activity" ? "Activity Center" : "Operations Menu";
  return (
    <aside className="ops-popover" aria-label={title}>
      <header>
        <div>
          <span>{panel}</span>
          <strong>{title}</strong>
        </div>
        <button type="button" onClick={onClose}>Close</button>
      </header>
      {panel === "command" ? (
        <div className="ops-action-grid">
          {[
            ["Start quick scan", Radar, () => onOpenScan("quick")],
            ["Start deep analysis", Shield, () => onOpenScan("deep")],
            ["Start API intelligence", Code2, () => onOpenScan("api")],
            ["Open attack graph", Network, () => onNavigate("attack-surface")],
            ["Open telemetry", Activity, () => onNavigate("telemetry")],
            ["Export report", FileText, () => onNavigate("reports")],
            ["Generate executive summary", Sparkles, () => onNavigate("dashboard")],
            ["Open monitoring center", MonitorDot, () => onNavigate("monitoring")],
          ].map(([label, Icon, action]) => (
            <button type="button" key={label} onClick={action}>
              <Icon size={16} />
              <span>{label}</span>
              <ExternalLink size={13} />
            </button>
          ))}
        </div>
      ) : null}
      {panel === "notifications" ? (
        <div className="ops-event-list">
          {notifications.map((item) => (
            <button type="button" key={item.id} className={`ops-event severity-${item.severity}`} onClick={() => onNavigate(item.route)}>
              <div>
                <strong>{item.title}</strong>
                <span>{item.detail}</span>
              </div>
              <small>{item.time}</small>
            </button>
          ))}
        </div>
      ) : null}
      {panel === "activity" ? (
        <div className="ops-event-list">
          <div className={`ops-progress-card ${isRunning ? "running" : ""}`}>
            <div>
              <strong>{progress.status === "idle" ? "No active run" : progress.message}</strong>
              <span>{progress.progress ?? 0}% complete</span>
            </div>
            <div className="inline-progress-track"><span className="inline-progress-fill" style={{ width: `${progress.progress ?? 0}%` }} /></div>
          </div>
          {activities.map((item) => (
            <button type="button" key={item.id} className="ops-event" onClick={() => onNavigate(item.route)}>
              <div>
                <strong>{item.title}</strong>
                <span>{item.detail}</span>
              </div>
              <small>{item.time}</small>
            </button>
          ))}
        </div>
      ) : null}
    </aside>
  );
}

function ScanCommandDrawer({
  target,
  setTarget,
  progress,
  runMode,
  isRunning,
  authOpen,
  setAuthOpen,
  jwtToken,
  setJwtToken,
  authHeader,
  setAuthHeader,
  toast,
  onClose,
  onLaunch,
  onNavigate,
}) {
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <section className="scan-command-drawer" onClick={(event) => event.stopPropagation()} aria-label="Scan command drawer">
        <header>
          <div>
            <span>Operational Command Center</span>
            <strong>Run exposure intelligence</strong>
          </div>
          <button type="button" onClick={onClose}>Close</button>
        </header>
        <label className="drawer-target">
          <span>Target</span>
          <input value={target} placeholder="https://app.example.com" onChange={(event) => setTarget(event.target.value)} autoFocus />
        </label>
        {toast ? <div className="drawer-toast">{toast}</div> : null}
        <div className="drawer-scan-modes">
          <button type="button" className="primary" disabled={isRunning} onClick={() => onLaunch("quick")}><Radar size={17} /> Quick Intelligence Scan</button>
          <button type="button" disabled={isRunning} onClick={() => onLaunch("deep")}><Shield size={17} /> Deep Exposure Analysis</button>
          <button type="button" disabled={isRunning} onClick={() => onLaunch("api")}><Code2 size={17} /> API Intelligence Scan</button>
          <button type="button" disabled={isRunning} onClick={() => onLaunch("monitoring")}><MonitorDot size={17} /> Continuous Monitoring</button>
        </div>
        <button type="button" className="drawer-auth-toggle" onClick={() => setAuthOpen(!authOpen)}>
          <KeyRound size={16} />
          Authenticated scan context
          <ChevronRight size={15} />
        </button>
        {authOpen ? (
          <div className="drawer-auth-fields">
            <input value={jwtToken} placeholder="JWT token" onChange={(event) => setJwtToken(event.target.value)} />
            <input value={authHeader} placeholder="Authorization header value" onChange={(event) => setAuthHeader(event.target.value)} />
          </div>
        ) : null}
        <div className="drawer-flow">
          {["Enter target", "Run intelligence analysis", "View attack surface", "View exposure intelligence", "View attack paths"].map((step, index) => (
            <div key={step} className={index === 0 || progress.status !== "idle" ? "active" : ""}>
              <Circle size={9} />
              <span>{step}</span>
            </div>
          ))}
        </div>
        <div className="ops-progress-card">
          <div>
            <strong>{runMode || "Ready"}</strong>
            <span>{progress.message}</span>
          </div>
          <div className="inline-progress-track"><span className="inline-progress-fill" style={{ width: `${progress.progress ?? 0}%` }} /></div>
        </div>
        <footer>
          <button type="button" onClick={() => onNavigate("attack-surface")}>Attack Surface</button>
          <button type="button" onClick={() => onNavigate("exposure")}>Exposure Intelligence</button>
          <button type="button" onClick={() => onNavigate("attack-paths")}>Attack Paths</button>
        </footer>
      </section>
    </div>
  );
}

function buildNotifications(operations) {
  const alerts = operations?.operational_telemetry?.alerts ?? [];
  const drift = operations?.drift_intelligence?.exposure_spikes ?? [];
  const research = operations?.offensive_research?.feed ?? [];
  const items = [
    ...alerts.map((alert, index) => ({
      id: `alert-${index}`,
      title: alert.title,
      detail: `${alert.count ?? 0} correlated signals`,
      severity: alert.severity ?? "medium",
      time: "now",
      status: "unread",
      route: alert.title?.toLowerCase().includes("path") ? "attack-paths" : "exposure",
    })),
    ...drift.slice(0, 4).map((item, index) => ({
      id: `drift-${index}`,
      title: "Exposure spike detected",
      detail: `${item.target} added ${item.new_endpoints} endpoints`,
      severity: item.severity ?? "medium",
      time: "recent",
      status: "unread",
      route: "drift",
    })),
    ...research.slice(0, 4).map((item, index) => ({
      id: `research-${index}`,
      title: item.title,
      detail: item.signal ?? item.target ?? "Research signal",
      severity: "medium",
      time: "recent",
      status: index < 2 ? "unread" : "read",
      route: "research",
    })),
  ];
  return items.length ? items : [
    { id: "empty-1", title: "Monitoring active", detail: "No critical exposure alerts right now", severity: "low", time: "now", status: "read", route: "monitoring" },
  ];
}

function buildActivities(operations, reports, activeScans, progress) {
  const telemetry = operations?.operational_telemetry?.stream ?? [];
  return [
    ...activeScans.map((scan) => ({
      id: `active-${scan.scan_id}`,
      title: `Running ${scan.target_url}`,
      detail: `${scan.progress}% · ${scan.message}`,
      time: "live",
      route: "telemetry",
    })),
    ...(progress.status !== "idle" ? [{
      id: "progress-current",
      title: progress.status === "completed" ? "Intelligence run completed" : "Intelligence run in progress",
      detail: progress.message,
      time: "live",
      route: "attack-surface",
    }] : []),
    ...telemetry.slice(0, 5).map((event, index) => ({
      id: `telemetry-${index}`,
      title: event.event,
      detail: `${event.value} · ${event.status}`,
      time: "recent",
      route: "telemetry",
    })),
    ...reports.slice(0, 5).map((report) => ({
      id: `report-${report.scan_id}`,
      title: `Completed ${report.target_url}`,
      detail: `${report.findings_count ?? 0} findings`,
      time: "recent",
      route: "reports",
    })),
  ];
}

function buildCommandItems(operations, reports, activeScans, launchScan, userRole) {
  const pageItems = navSections.flatMap((section) => {
    if (section.route) {
      return [{ label: section.label, group: "Page", route: section.route, icon: section.icon, keywords: "overview executive dashboard" }];
    }
    return section.items.map(([route, icon, label]) => ({
      label,
      group: section.label,
      route,
      icon,
      keywords: `${section.label} page navigation`,
    }));
  });
  const scanItems = hasPermission(userRole, "scan:run") ? [
    { label: "Start quick scan", group: "Scans", icon: Radar, action: () => launchScan("quick"), keywords: "launch intelligence target" },
    { label: "Start deep exposure analysis", group: "Scans", icon: Shield, action: () => launchScan("deep"), keywords: "launch exposure target" },
    { label: "Start API intelligence scan", group: "Scans", icon: Code2, action: () => launchScan("api"), keywords: "api launch target" },
    { label: "Start continuous monitoring", group: "Scans", icon: MonitorDot, action: () => launchScan("monitoring"), keywords: "monitoring launch target" },
  ] : [];
  const preservedRouteItems = [
    { label: "Offensive Research", group: "Advanced", route: "research", icon: Telescope, keywords: "research offensive exploit intelligence" },
    { label: "Platform Architecture", group: "Advanced", route: "platform", icon: Layers3, keywords: "platform architecture internals" },
    { label: "Capability Matrix", group: "Advanced", route: "capabilities", icon: Sparkles, keywords: "capabilities coverage detectors" },
  ];
  const assetItems = (operations?.asset_inventory?.assets ?? operations?.assets ?? []).slice(0, 4).map((asset, index) => ({
    label: asset.host || asset.target || asset.domain || `Asset ${index + 1}`,
    group: "Assets",
    route: "assets",
    icon: Boxes,
    keywords: "asset inventory domain host",
  }));
  const findingSource = operations?.findings?.critical ?? operations?.findings?.items ?? operations?.findings ?? [];
  const findingItems = Array.isArray(findingSource) ? findingSource.slice(0, 4).map((finding, index) => ({
    label: finding.title || finding.type || finding.name || `Finding ${index + 1}`,
    group: "Findings",
    route: "findings",
    icon: ClipboardCheck,
    keywords: "finding vulnerability validation",
  })) : [];
  const reportItems = reports.slice(0, 5).map((report) => ({
    label: report.target_url || report.title || `Report ${report.scan_id}`,
    group: "Reports",
    route: "reports",
    icon: FileText,
    keywords: "report executive technical compliance",
  }));
  const activeScanItems = activeScans.slice(0, 4).map((scan) => ({
    label: scan.target_url || scan.scan_id,
    group: "Active Scans",
    route: "telemetry",
    icon: Activity,
    keywords: "scan progress activity timeline",
  }));
  return [...scanItems, ...pageItems, ...preservedRouteItems, ...assetItems, ...findingItems, ...reportItems, ...activeScanItems];
}
