import React, { useState } from "react";
import { Navbar } from "./components/Navbar.jsx";
import { Home } from "./pages/Home.jsx";
import { ScanPage } from "./pages/ScanPage.jsx";
import { ReportsPage } from "./pages/ReportsPage.jsx";
import "./styles/dashboard.css";

export default function App() {
  const [page, setPage] = useState("scan");

  return (
    <main className="app-shell">
      <Navbar page={page} onNavigate={setPage} />
      {page === "home" && <Home onStart={() => setPage("scan")} />}
      {page === "scan" && <ScanPage />}
      {page === "reports" && <ReportsPage />}
    </main>
  );
}
