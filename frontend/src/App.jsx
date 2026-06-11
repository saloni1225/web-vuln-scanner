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
import { ApiSecurityPage, AssetsPage, AttackPathAnalysisPage, AttackSurfacePage, CompliancePage, DriftIntelligencePage, ExposureOperationsPage, FindingsPage, MonitoringPage, OffensiveResearchPage, OperationalTelemetryPage, ReconPage, SettingsPage, ThreatIntelligencePage, AuditLogsPage, SystemHealthPage } from "./pages/EnterprisePages.jsx";
import { AuthPage, BillingPage, ContactPage, DocumentationPage, FeaturesPage, MarketingHome, MonitoringWorkflowsPage, NotificationCenterPage, OnboardingPage, PricingPage, SaaSSettingsPage, TeamManagementPage, TrustPage } from "./pages/SaaSPages.jsx";
import { Logo } from "./components/Logo.jsx";
import "./styles/dashboard.css";


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


function RouteFallbackPage({ page }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", minHeight: "60vh", color: "#e0e0e0",
      fontFamily: "monospace", textAlign: "center", padding: "2rem",
      background: "rgba(10, 10, 15, 0.8)", border: "1px solid rgba(0, 255, 255, 0.15)",
      borderRadius: "8px", margin: "2rem auto", maxWidth: "600px",
      boxShadow: "0 0 30px rgba(0, 255, 255, 0.05)"
    }}>
      <div style={{
        fontSize: "3rem", marginBottom: "1rem",
        textShadow: "0 0 20px rgba(0,255,255,0.5)",
      }}>🗺️</div>
      <h2 style={{
        color: "#00ffff", fontSize: "1.5rem", marginBottom: "0.5rem",
        textShadow: "0 0 10px rgba(0,255,255,0.3)",
      }}>Route Not Found</h2>
      <p style={{ color: "#888", marginBottom: "1.5rem", maxWidth: "400px" }}>
        The requested path <code style={{ color: "#ff0055" }}>{page}</code> could not be mapped to any active vulnerability scanner feature.
      </p>
    </div>
  );
}

function AppContent() {
  const [page, setPage] = useState("marketing");
  const { isAuthenticated, loading, logout, user, backendOffline, authReady } = useAuth();

  useEffect(() => {
    // Single cohesive cyberpunk theme only (never mention light/dark mode selection)
    document.documentElement.setAttribute("data-theme", "cyberpunk-dark");
    document.documentElement.setAttribute("data-background-mode", "enterprise");
  }, []);

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

  const knownPages = new Set([
    "marketing", "features", "pricing", "trust", "documentation", "contact", "login", "register", "otp", "forgot", "mfa", "onboarding",
    "dashboard", "assets", "recon", "scan", "exposure", "attack-paths", "research", "threat-intel", "drift", "telemetry",
    "findings", "attack-surface", "apis", "reports", "compliance", "integrations", "monitoring", "workflows", "notifications",
    "cicd", "capabilities", "platform", "team", "billing", "settings", "audit-logs", "system-health"
  ]);

  const mfaRequired = user && (user.role === "owner" || user.role === "admin") && user.mfa_enabled && !user.mfa_verified;

  console.log("MFA Guard Diagnostics:", {
    role: user?.role,
    mfa_enabled: user?.mfa_enabled,
    page
  });

  // ── Centralized route guarding and request sequencing ──
  useEffect(() => {
    if (!authReady) return;
    if (isAuthenticated) {
      if (mfaRequired) {
        if (page !== "mfa") {
          setPage("mfa");
        }
      } else {
        if (authModes.has(page) && page !== "onboarding") {
          setPage("dashboard");
        }
      }
    } else {
      if (!publicPages.has(page)) {
        setPage("login");
      }
    }
  }, [isAuthenticated, authReady, mfaRequired, page]);

  // ── Show system offline screen if backend is unreachable ──
  if (backendOffline) {
    return (
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        height: "100vh", background: "#0a0a0f",
        color: "#ff0055", fontFamily: "monospace", fontSize: "1.1rem",
        border: "1px solid #ff0055", margin: "10px", borderRadius: "8px",
        boxShadow: "0 0 20px rgba(255, 0, 85, 0.15)",
        position: "relative", overflow: "hidden"
      }}>
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, bottom: 0,
          background: "linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%)",
          backgroundSize: "100% 4px", zIndex: 1, pointerEvents: "none"
        }} />
        <div style={{ textAlign: "center", zIndex: 2, padding: "24px" }}>
          <div style={{
            fontSize: "4rem", marginBottom: "16px",
            animation: "pulse 1.5s infinite ease-in-out"
          }}>⚠️</div>
          <h2 style={{ color: "#ff0055", fontSize: "1.8rem", marginBottom: "8px", fontWeight: 700, letterSpacing: "2px" }}>
            SYSTEM OFFLINE
          </h2>
          <p style={{ color: "#888", marginBottom: "24px", maxWidth: "450px", fontSize: "0.95rem" }}>
            AdaptiveScan exposure engine is currently unreachable. The backend service may be undergoing maintenance or boot sequences.
          </p>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "10px", fontSize: "0.85rem", color: "#00ffff", background: "rgba(0,255,255,0.05)", padding: "8px 16px", borderRadius: "4px", border: "1px solid rgba(0,255,255,0.2)" }}>
            <div style={{
              width: "8px", height: "8px", borderRadius: "50%",
              backgroundColor: "#00ffff", boxShadow: "0 0 8px #00ffff",
              animation: "blink 1s infinite alternate"
            }} />
            Reconnecting to exposure engine...
          </div>
          <style>{`
            @keyframes pulse {
              0% { transform: scale(1); opacity: 0.8; }
              50% { transform: scale(1.05); opacity: 1; }
              100% { transform: scale(1); opacity: 0.8; }
            }
            @keyframes blink {
              from { opacity: 0.3; }
              to { opacity: 1; }
            }
          `}</style>
        </div>
      </div>
    );
  }


  if (loading || !authReady) {
    return (
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        height: "100vh", background: "#0a0a0f",
        color: "#00ffff", fontFamily: "monospace", fontSize: "1.1rem",
        position: "relative", overflow: "hidden"
      }}>
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, bottom: 0,
          background: "linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%)",
          backgroundSize: "100% 4px", zIndex: 1, pointerEvents: "none"
        }} />
        <div style={{ textAlign: "center", zIndex: 2 }}>
          <div style={{
            width: 40, height: 40, border: "3px solid transparent",
            borderTop: "3px solid #00f0ff", borderRadius: "50%",
            animation: "spin 0.8s linear infinite", margin: "0 auto 16px",
            boxShadow: "0 0 10px rgba(0, 255, 255, 0.3)"
          }} />
          <div style={{ color: "#00ffff", textShadow: "0 0 8px rgba(0, 255, 255, 0.5)", letterSpacing: "1px" }}>INITIALIZING SECURE SESSION…</div>
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
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--accent)", fontSize: "0.75rem", fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", marginRight: "10px" }}>
              <span style={{ display: "inline-block", width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--accent)", boxShadow: "0 0 6px var(--accent)" }}></span>
              Enterprise Edition
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
            textShadow: "0 0 20px rgba(255,0,85,0.5)",
          }}>🔒</div>
          <h2 style={{
            color: "#ff0055", fontSize: "1.5rem", marginBottom: "0.5rem",
            textShadow: "0 0 10px rgba(255,0,85,0.3)",
          }}>Access Restricted</h2>
          <p style={{ color: "#888", marginBottom: "1.5rem", maxWidth: "400px" }}>
            This area requires authentication. Please log in with your credentials to continue.
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
          background: "rgba(10, 10, 15, 0.8)", border: "1px solid rgba(255, 0, 85, 0.2)",
          borderRadius: "8px", margin: "2rem auto", maxWidth: "600px",
          boxShadow: "0 0 30px rgba(255, 0, 85, 0.05)"
        }}>
          <div style={{
            fontSize: "3rem", marginBottom: "1rem",
            textShadow: "0 0 20px rgba(255, 0, 85, 0.5)",
          }}>🚫</div>
          <h2 style={{
            color: "#ff0055", fontSize: "1.5rem", marginBottom: "0.5rem",
            textShadow: "0 0 10px rgba(255, 0, 85, 0.3)",
          }}>Access Denied</h2>
          <p style={{ color: "#888", marginBottom: "1.5rem", maxWidth: "450px" }}>
            Your role (<strong>{userRole}</strong>) does not have sufficient permissions to access the <strong>{activePage}</strong> page.<br />
            Required scope: <code style={{ color: "#00ffff", textShadow: "0 0 6px rgba(0, 255, 255, 0.3)" }}>{requiredPermission}</code>
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

  // ── MFA ENFORCEMENT RENDERING GATE ──
  if (mfaRequired && !publicPages.has(page)) {
    return (
      <div className="public-shell">
        <AuthPage mode="mfa" onNavigate={setPage} />
      </div>
    );
  }

  const isKnownRoute = knownPages.has(activePage);

  return (
    <EnterpriseLayout page={page} onNavigate={setPage}>
      {isKnownRoute ? (
        <>
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
          {activePage === "audit-logs" && <AuditLogsPage />}
          {activePage === "system-health" && <SystemHealthPage />}
          {activePage === "settings" && <><SettingsPage /><SaaSSettingsPage /></>}
        </>
      ) : (
        <RouteFallbackPage page={page} />
      )}
    </EnterpriseLayout>
  );
}

function CustomCursor() {
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [trail, setTrail] = useState({ x: 0, y: 0 });
  const [hovered, setHovered] = useState(false);
  const [clicked, setClicked] = useState(false);
  const [visible, setVisible] = useState(false);
  const [isTouch, setIsTouch] = useState(false);

  useEffect(() => {
    const touchQuery = window.matchMedia("(hover: none)");
    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (touchQuery.matches || motionQuery.matches) {
      setIsTouch(true);
      return;
    }

    const handleMouseMove = (e) => {
      setPosition({ x: e.clientX, y: e.clientY });
      setVisible(true);
    };

    const handleMouseOver = (e) => {
      const target = e.target;
      const isInteractive = 
        target.tagName === "A" || 
        target.tagName === "BUTTON" || 
        target.tagName === "INPUT" || 
        target.tagName === "SELECT" || 
        target.tagName === "TEXTAREA" || 
        target.closest("a") || 
        target.closest("button") || 
        target.closest("[role='button']") || 
        target.closest(".stat-card") || 
        target.closest(".metric-card") || 
        target.closest(".as-card") || 
        target.closest(".sidebar-link") ||
        target.closest(".ops-run") ||
        window.getComputedStyle(target).cursor === "pointer";
      
      setHovered(!!isInteractive);
    };

    const handleMouseDown = () => setClicked(true);
    const handleMouseUp = () => setClicked(false);
    const handleMouseLeave = () => setVisible(false);
    const handleMouseEnter = () => setVisible(true);

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseover", handleMouseOver);
    window.addEventListener("mousedown", handleMouseDown);
    window.addEventListener("mouseup", handleMouseUp);
    document.addEventListener("mouseleave", handleMouseLeave);
    document.addEventListener("mouseenter", handleMouseEnter);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseover", handleMouseOver);
      window.removeEventListener("mousedown", handleMouseDown);
      window.removeEventListener("mouseup", handleMouseUp);
      document.removeEventListener("mouseleave", handleMouseLeave);
      document.removeEventListener("mouseenter", handleMouseEnter);
    };
  }, []);

  useEffect(() => {
    if (isTouch || !visible) return;
    let req;
    const updateTrail = () => {
      setTrail((prev) => {
        const dx = position.x - prev.x;
        const dy = position.y - prev.y;
        return {
          x: prev.x + dx * 0.15,
          y: prev.y + dy * 0.15,
        };
      });
      req = requestAnimationFrame(updateTrail);
    };
    req = requestAnimationFrame(updateTrail);
    return () => cancelAnimationFrame(req);
  }, [position, isTouch, visible]);

  if (isTouch || !visible) return null;

  return (
    <>
      <style>{`
        body, a, button, input, select, textarea, [role="button"], * {
          cursor: none !important;
        }
      `}</style>
      
      <div
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          backgroundColor: "#00ffff",
          boxShadow: "0 0 8px #00ffff, 0 0 15px #00ffff",
          transform: `translate3d(${position.x - 3}px, ${position.y - 3}px, 0)`,
          pointerEvents: "none",
          zIndex: 99999,
          transition: "transform 0.05s linear, width 0.1s, height 0.1s",
          opacity: visible ? 1 : 0,
        }}
      />

      <div
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: hovered ? "36px" : "22px",
          height: hovered ? "36px" : "22px",
          borderRadius: "50%",
          border: hovered ? "1.5px solid #ff0055" : "1px solid rgba(0, 255, 255, 0.4)",
          backgroundColor: hovered ? "rgba(255, 0, 85, 0.04)" : "rgba(0, 255, 255, 0.01)",
          boxShadow: hovered 
            ? "0 0 15px rgba(255, 0, 85, 0.3), inset 0 0 8px rgba(255, 0, 85, 0.1)" 
            : "0 0 6px rgba(0, 255, 255, 0.1)",
          transform: `translate3d(${trail.x - (hovered ? 18 : 11)}px, ${trail.y - (hovered ? 18 : 11)}px, 0) scale(${clicked ? 0.85 : 1})`,
          pointerEvents: "none",
          zIndex: 99998,
          transition: "width 0.2s ease-out, height 0.2s ease-out, border 0.2s ease-out, background-color 0.2s ease-out, box-shadow 0.2s ease-out, transform 0.08s ease-out",
          opacity: visible ? 0.85 : 0,
        }}
      />
    </>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <CustomCursor />
      <AppContent />
    </AuthProvider>
  );
}

