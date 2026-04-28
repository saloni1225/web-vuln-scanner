import React, { useEffect, useState } from "react";
import { Boxes, PlugZap, ShieldCheck } from "lucide-react";
import { fetchPluginMarketplace } from "../services/api.js";

export function PluginsPage() {
  const [marketplace, setMarketplace] = useState(null);

  useEffect(() => {
    fetchPluginMarketplace().then(setMarketplace).catch(() => setMarketplace({ detectors: [] }));
  }, []);

  const detectors = marketplace?.detectors ?? [];

  return (
    <section className="workspace">
      <section className="scan-hero">
        <div>
          <h1>Plugin Marketplace</h1>
          <p>Manage detector modules from the local registry and see what each plugin contributes to the platform.</p>
        </div>
        <div className="hero-status-cluster">
          <div><span>Registry</span><strong>{marketplace?.install_mode ?? "local-registry"}</strong></div>
          <div><span>Plugins</span><strong>{detectors.length}</strong></div>
        </div>
      </section>

      <section className="analytics-grid">
        <article className="panel analytics-panel">
          <header className="panel-header">
            <div><PlugZap size={18} /><strong>Detector Registry</strong></div>
            <span>{detectors.filter((item) => item.enabled).length} enabled</span>
          </header>
          <div className="timing-list">
            {detectors.map((detector) => (
              <div key={detector.name} className="timing-row">
                <div>
                  <strong>{detector.name}</strong>
                  <small>{detector.description}</small>
                </div>
                <span>{detector.enabled ? "enabled" : "off"}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel analytics-panel">
          <header className="panel-header">
            <div><Boxes size={18} /><strong>Capabilities</strong></div>
            <span>dynamic</span>
          </header>
          <div className="chip-list recon-chips">
            {detectors.flatMap((detector) => detector.supports ?? []).filter((item, index, list) => list.indexOf(item) === index).map((capability) => (
              <span key={capability}>{capability}</span>
            ))}
          </div>
          <p>{marketplace?.guidance}</p>
          <code className="drawer-code">{marketplace?.registry_path ?? "backend/detection/detectors.json"}</code>
        </article>

        <article className="panel analytics-panel">
          <header className="panel-header">
            <div><ShieldCheck size={18} /><strong>Engineering Status</strong></div>
            <span>ready</span>
          </header>
          <div className="scan-progress-meta">
            <div><span>Loading</span><strong>Dynamic import</strong></div>
            <div><span>Base API</span><strong>BaseDetector</strong></div>
            <div><span>Config</span><strong>JSON registry</strong></div>
            <div><span>UI</span><strong>Marketplace view</strong></div>
          </div>
        </article>
      </section>
    </section>
  );
}
