import React, { useEffect, useState } from "react";
import { EnterpriseLayout } from "./components/EnterpriseLayout.jsx";
import { Home } from "./pages/Home.jsx";
import { ScanPage } from "./pages/ScanPage.jsx";
import { ReportsPage } from "./pages/ReportsPage.jsx";
import { PluginsPage } from "./pages/PluginsPage.jsx";
import { CICDPage } from "./pages/CICDPage.jsx";
import { CapabilitiesPage } from "./pages/CapabilitiesPage.jsx";
import { PlatformPage } from "./pages/PlatformPage.jsx";
import { ApiSecurityPage, AssetsPage, AttackSurfacePage, CompliancePage, ExposureOperationsPage, FindingsPage, MonitoringPage, OffensiveResearchPage, ReconPage, SettingsPage, ThreatIntelligencePage } from "./pages/EnterprisePages.jsx";
import "./styles/dashboard.css";

export default function App() {
  const [page, setPage] = useState("home");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", "dark");
    document.documentElement.setAttribute("data-background-mode", "enterprise");
  }, []);

  return (
    <EnterpriseLayout page={page} onNavigate={setPage}>
      {page === "home" && <Home onStart={() => setPage("attack-surface")} />}
      {page === "assets" && <AssetsPage />}
      {page === "recon" && <ReconPage />}
      {page === "scan" && <ScanPage />}
      {page === "exposure" && <ExposureOperationsPage />}
      {page === "research" && <OffensiveResearchPage />}
      {page === "threat-intel" && <ThreatIntelligencePage />}
      {page === "findings" && <FindingsPage />}
      {page === "attack-surface" && <AttackSurfacePage />}
      {page === "apis" && <ApiSecurityPage />}
      {page === "reports" && <ReportsPage />}
      {page === "compliance" && <CompliancePage />}
      {page === "integrations" && <PluginsPage />}
      {page === "monitoring" && <MonitoringPage />}
      {page === "cicd" && <CICDPage />}
      {page === "capabilities" && <CapabilitiesPage />}
      {page === "platform" && <PlatformPage />}
      {page === "settings" && <SettingsPage />}
    </EnterpriseLayout>
  );
}
