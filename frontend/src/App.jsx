import React, { useEffect, useState } from "react";
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
import "./styles/dashboard.css";

export default function App() {
  const [page, setPage] = useState("marketing");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", "dark");
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

  if (publicPages.has(page)) {
    return (
      <div className="public-shell">
        <header className="public-nav">
          <button className="public-brand" type="button" onClick={() => setPage("marketing")}>AdaptiveScan</button>
          <nav>
            <button type="button" onClick={() => setPage("features")}>Features</button>
            <button type="button" onClick={() => setPage("pricing")}>Pricing</button>
            <button type="button" onClick={() => setPage("trust")}>Trust</button>
            <button type="button" onClick={() => setPage("documentation")}>Documentation</button>
            <button type="button" onClick={() => setPage("contact")}>Contact</button>
          </nav>
          <div>
            <button className="ghost-button" type="button" onClick={() => setPage("login")}>Login</button>
            <button className="primary-action" type="button" onClick={() => setPage("register")}>Start Free Trial</button>
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

  return (
    <EnterpriseLayout page={page} onNavigate={setPage}>
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
