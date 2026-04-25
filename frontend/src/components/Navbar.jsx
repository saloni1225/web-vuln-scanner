import React from "react";
import { Activity, FileText, Radar, Shield } from "lucide-react";

export function Navbar({ page, onNavigate }) {
  const items = [
    ["home", Activity, "Overview"],
    ["scan", Radar, "Scan"],
    ["reports", FileText, "Reports"],
  ];

  return (
    <nav className="navbar">
      <div className="brand-lockup">
        <div className="brand-mark">
          <Shield size={16} />
        </div>
        <div>
          <div className="brand">Adaptive Scanner</div>
          <div className="brand-subtitle">Offensive surface analysis console</div>
        </div>
      </div>
      <div className="nav-actions">
        {items.map(([key, Icon, label]) => (
          <button
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
    </nav>
  );
}
