import React, { useEffect, useState } from "react";
import { Navbar } from "./components/Navbar.jsx";
import { Home } from "./pages/Home.jsx";
import { ScanPage } from "./pages/ScanPage.jsx";
import { ReportsPage } from "./pages/ReportsPage.jsx";
import { PluginsPage } from "./pages/PluginsPage.jsx";
import { CICDPage } from "./pages/CICDPage.jsx";
import "./styles/dashboard.css";

export default function App() {
  const [page, setPage] = useState("scan");
  const [theme, setTheme] = useState(() => localStorage.getItem("aws-theme") || "light");
  const [backgroundMode, setBackgroundMode] = useState(() => localStorage.getItem("aws-background-mode") || "grid");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("aws-theme", theme);
  }, [theme]);

  useEffect(() => {
    document.documentElement.setAttribute("data-background-mode", backgroundMode);
    localStorage.setItem("aws-background-mode", backgroundMode);
  }, [backgroundMode]);

  return (
    <main className="app-shell">
      <Navbar
        page={page}
        onNavigate={setPage}
        theme={theme}
        backgroundMode={backgroundMode}
        onSelectBackgroundMode={setBackgroundMode}
        onToggleTheme={() => setTheme((current) => (current === "light" ? "dark" : "light"))}
      />
      {page === "home" && <Home onStart={() => setPage("scan")} />}
      {page === "scan" && <ScanPage />}
      {page === "reports" && <ReportsPage />}
      {page === "plugins" && <PluginsPage />}
      {page === "cicd" && <CICDPage />}
    </main>
  );
}
