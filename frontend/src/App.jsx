import React, { useEffect, useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import { EnterpriseLayout } from "./components/EnterpriseLayout.jsx";
import { Home } from "./pages/Home.jsx";
import { ScanPage } from "./pages/ScanPage.jsx";
import { ReportsPage } from "./pages/ReportsPage.jsx";
import { PluginsPage } from "./pages/PluginsPage.jsx";
import { CICDPage } from "./pages/CICDPage.jsx";
import { CapabilitiesPage } from "./pages/CapabilitiesPage.jsx";
import { PlatformPage } from "./pages/PlatformPage.jsx";
import { ApiSecurityPage, AssetsPage, AttackPathAnalysisPage, AttackSurfacePage, CompliancePage, DriftIntelligencePage, ExposureOperationsPage, FindingsPage, MonitoringPage, OffensiveResearchPage, OperationalTelemetryPage, ReconPage, SettingsPage, ThreatIntelligencePage } from "./pages/EnterprisePages.jsx";
import { AuthPage, BillingPage, ContactPage, DocumentationPage, FeaturesPage, MarketingHome, MonitoringWorkflowsPage, NotificationCenterPage, OnboardingPage, PricingPage, SaaSSettingsPage, TeamManagementPage, TrustPage } from "./pages/SaaSPages.jsx";
import { Logo } from "./components/Logo.jsx";
import "./styles/dashboard.css";


const ROLE_PERMISSIONS = {
  owner: new Set([
    "org:admin", "workspace:admin", "scan:run", "scan:read", "finding:manage", "report:read", "api_key:manage",
    "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read", "orchestration:read",
    "threat_intel:read", "ai:read", "compliance:read", "integration:manage", "devsecops:read", "rbac:admin"
  ]),
  admin: new Set([
    "workspace:admin", "scan:run", "scan:read", "finding:manage", "report:read", "api_key:manage",
    "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read", "orchestration:read",
    "threat_intel:read", "ai:read", "compliance:read", "integration:manage", "devsecops:read"
  ]),
  security_engineer: new Set([
    "workspace:read", "scan:run", "scan:read", "finding:manage", "report:read",
    "exposure:read", "attack_graph:read", "attack_path:read", "drift:read", "telemetry:read",
    "threat_intel:read", "ai:read", "devsecops:read"
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
};


function AppContent() {
  const [page, setPage] = useState("marketing");
  const [theme, setTheme] = useState("cyberpunk-dark");
  const { isAuthenticated, loading, logout, user } = useAuth();

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-background-mode", "enterprise");
  }, [theme]);

  const publicPages = new Set(["marketing", "features", "pricing", "trust", "documentation", "contact", "login", "register", "otp", "forgot", "mfa", "onboarding"]);
  const authModes = new Set(["login", "register", "otp", "forgot", "mfa"]);
  const pageAliases = {
    home: "dashboard",
    certificates: "attack-surface",
    "cloud-assets": "assets",
    "exposure-overview": "exposure",
    "risk-prioritization": "exposure",
    alerts: "notifications",
    notifications: "notifications",
    workflows: "workflows",
    validation: "findings",
    "technical-reports": "reports",
    organization: "settings",
    profile: "settings",
  };
  const activePage = pageAliases[page] ?? page;

  // ── If authenticated user tries to visit login/register, redirect to dashboard ──
  useEffect(() => {
    if (isAuthenticated && authModes.has(page)) {
      setPage("dashboard");
    }
  }, [isAuthenticated, page]);

  // ── Show loading spinner during initial session check ──
  if (loading) {
    return (
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        height: "100vh", background: "#0a0a0f",
        color: "#00f0ff", fontFamily: "monospace", fontSize: "1.1rem",
      }}>
        <div style={{ textAlign: "center" }}>
          <div style={{
            width: 40, height: 40, border: "3px solid transparent",
            borderTop: "3px solid #00f0ff", borderRadius: "50%",
            animation: "spin 0.8s linear infinite", margin: "0 auto 16px",
          }} />
          <div>Initializing secure session…</div>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      </div>
    );
  }

  // ── PUBLIC PAGES (marketing, auth, etc.) ──────────────────────────────────
  if (publicPages.has(page)) {
    return (
      <div className="public-shell">
        <header className="public-nav">
          <button
            className="public-brand"
            type="button"
            onClick={() => setPage("marketing")}
            style={{ display: "inline-flex", alignItems: "center", gap: "8px", border: 0, background: "transparent", cursor: "pointer" }}
          >
            <Logo size={42} />
            <span style={{ fontSize: "1.5rem" }}>AdaptiveScan</span>
          </button>
          <nav>
            <button type="button" onClick={() => setPage("features")}>Features</button>
            <button type="button" onClick={() => setPage("pricing")}>Pricing</button>
            <button type="button" onClick={() => setPage("trust")}>Trust</button>
            <button type="button" onClick={() => setPage("documentation")}>Documentation</button>
            <button type="button" onClick={() => setPage("contact")}>Contact</button>
          </nav>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#ff007f", textShadow: "0 0 8px rgba(255, 0, 127, 0.4)", fontSize: "0.75rem", fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", marginRight: "10px" }}>
              <span style={{ display: "inline-block", width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#ff007f", boxShadow: "0 0 6px #ff007f" }}></span>
              Cyberpunk Edition
            </div>
            {isAuthenticated ? (
              <>
                <button className="ghost-button" type="button" onClick={() => setPage("dashboard")}>Dashboard</button>
                <button className="primary-action" type="button" onClick={logout}>Logout</button>
              </>
            ) : (
              <>
                <button className="ghost-button" type="button" onClick={() => setPage("login")}>Login</button>
                <button className="primary-action" type="button" onClick={() => setPage("register")}>Start Free Trial</button>
              </>
            )}
          </div>
        </header>
        {page === "marketing" && <MarketingHome onNavigate={setPage} />}
        {page === "features" && <FeaturesPage />}
        {page === "pricing" && <PricingPage />}
        {page === "trust" && <TrustPage />}
        {page === "documentation" && <DocumentationPage />}
        {page === "contact" && <ContactPage />}
        {authModes.has(page) && <AuthPage mode={page} onNavigate={setPage} />}
        {page === "onboarding" && <OnboardingPage onNavigate={setPage} />}
      </div>
    );
  }

  // ── PROTECTED PAGES — require authentication ──────────────────────────────
  if (!isAuthenticated) {
    // Redirect to login if trying to access any protected page
    return (
      <div className="public-shell">
        <header className="public-nav">
          <button
            className="public-brand"
            type="button"
            onClick={() => setPage("marketing")}
            style={{ display: "inline-flex", alignItems: "center", gap: "8px", border: 0, background: "transparent", cursor: "pointer" }}
          >
            <Logo size={42} />
            <span style={{ fontSize: "1.5rem" }}>AdaptiveScan</span>
          </button>
        </header>
        <div style={{
          display: "flex", flexDirection: "column", alignItems: "center",
          justifyContent: "center", minHeight: "60vh", color: "#e0e0e0",
          fontFamily: "monospace", textAlign: "center", padding: "2rem",
        }}>
          <div style={{
            fontSize: "3rem", marginBottom: "1rem",
            textShadow: "0 0 20px rgba(255,0,127,0.5)",
          }}>🔒</div>
          <h2 style={{
            color: "#ff007f", fontSize: "1.5rem", marginBottom: "0.5rem",
            textShadow: "0 0 10px rgba(255,0,127,0.3)",
          }}>Access Restricted</h2>
          <p style={{ color: "#888", marginBottom: "1.5rem", maxWidth: "400px" }}>
            This area requires authentication. Please log in with your admin credentials to continue.
          </p>
          <button
            className="primary-action"
            type="button"
            onClick={() => setPage("login")}
            style={{ padding: "10px 32px", fontSize: "1rem" }}
          >
            Log In
          </button>
        </div>
      </div>
    );
  }

  // ── ROLE-BASED ACCESS CONTROL (RBAC) GATING ───────────────────────────────
  const userRole = user?.role || "viewer";
  const requiredPermission = PAGE_PERMISSIONS[activePage];
  if (requiredPermission && !hasPermission(userRole, requiredPermission)) {
    return (
      <div className="public-shell">
        <header className="public-nav">
          <button
            className="public-brand"
            type="button"
            onClick={() => setPage("marketing")}
            style={{ display: "inline-flex", alignItems: "center", gap: "8px", border: 0, background: "transparent", cursor: "pointer" }}
          >
            <Logo size={42} />
            <span style={{ fontSize: "1.5rem" }}>AdaptiveScan</span>
          </button>
        </header>
        <div style={{
          display: "flex", flexDirection: "column", alignItems: "center",
          justifyContent: "center", minHeight: "60vh", color: "#e0e0e0",
          fontFamily: "monospace", textAlign: "center", padding: "2rem",
        }}>
          <div style={{
            fontSize: "3rem", marginBottom: "1rem",
            textShadow: "0 0 20px rgba(255,0,127,0.5)",
          }}>🚫</div>
          <h2 style={{
            color: "#ff007f", fontSize: "1.5rem", marginBottom: "0.5rem",
            textShadow: "0 0 10px rgba(255,0,127,0.3)",
          }}>Access Denied</h2>
          <p style={{ color: "#888", marginBottom: "1.5rem", maxWidth: "450px" }}>
            Your role (<strong>{userRole}</strong>) does not have sufficient permissions to access the <strong>{activePage}</strong> page.<br />
            Required scope: <code style={{ color: "#00f0ff" }}>{requiredPermission}</code>
          </p>
          <button
            className="primary-action"
            type="button"
            onClick={() => setPage("dashboard")}
            style={{ padding: "10px 32px", fontSize: "1rem" }}
          >
            Return to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <EnterpriseLayout page={page} onNavigate={setPage} theme={theme} onChangeTheme={setTheme}>
      {activePage === "dashboard" && <Home onStart={() => setPage("attack-surface")} />}
      {activePage === "assets" && <AssetsPage />}
      {activePage === "recon" && <ReconPage />}
      {activePage === "scan" && <ScanPage />}
      {activePage === "exposure" && <ExposureOperationsPage />}
      {activePage === "attack-paths" && <AttackPathAnalysisPage />}
      {activePage === "research" && <OffensiveResearchPage />}
      {activePage === "threat-intel" && <ThreatIntelligencePage />}
      {activePage === "drift" && <DriftIntelligencePage />}
      {activePage === "telemetry" && <OperationalTelemetryPage />}
      {activePage === "findings" && <FindingsPage />}
      {activePage === "attack-surface" && <AttackSurfacePage />}
      {activePage === "apis" && <ApiSecurityPage />}
      {activePage === "reports" && <ReportsPage />}
      {activePage === "compliance" && <CompliancePage />}
      {activePage === "integrations" && <PluginsPage />}
      {activePage === "monitoring" && <MonitoringPage />}
      {activePage === "workflows" && <MonitoringWorkflowsPage />}
      {activePage === "notifications" && <NotificationCenterPage />}
      {activePage === "cicd" && <CICDPage />}
      {activePage === "capabilities" && <CapabilitiesPage />}
      {activePage === "platform" && <PlatformPage />}
      {activePage === "team" && <TeamManagementPage />}
      {activePage === "billing" && <BillingPage />}
      {activePage === "settings" && <><SettingsPage /><SaaSSettingsPage /></>}
    </EnterpriseLayout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
