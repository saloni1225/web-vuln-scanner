import React from "react";
import { Activity, FileText, GitBranch, Moon, Palette, PlugZap, Radar, Shield, Sun } from "lucide-react";

export function Navbar({ page, onNavigate, theme, backgroundMode, onSelectBackgroundMode, onToggleTheme }) {
  const items = [
    ["home", Activity, "Overview"],
    ["scan", Radar, "Scan"],
    ["reports", FileText, "Reports"],
    ["plugins", PlugZap, "Plugins"],
    ["cicd", GitBranch, "CI/CD"],
  ];
  const backgroundModes = [
    ["grid", "Grid"],
    ["soft", "Soft"],
    ["aurora", "Aurora"],
    ["ops", "Ops"],
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
        <div className="mode-switch" title="Background style">
          <div className="mode-switch-label">
            <Palette size={16} />
            <span>Background</span>
          </div>
          <div className="mode-switch-options">
            {backgroundModes.map(([key, label]) => (
              <button
                key={key}
                type="button"
                className={backgroundMode === key ? "active" : ""}
                onClick={() => onSelectBackgroundMode(key)}
                title={label}
              >
                <span>{label}</span>
              </button>
            ))}
          </div>
        </div>
        {items.map(([key, Icon, label]) => (
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
        <button type="button" className="theme-toggle" onClick={onToggleTheme} title="Toggle theme">
          {theme === "light" ? <Moon size={18} /> : <Sun size={18} />}
          <span>{theme === "light" ? "Dark" : "Light"}</span>
        </button>
      </div>
    </nav>
  );
}
