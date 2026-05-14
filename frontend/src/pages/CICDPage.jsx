import React from "react";
import { GitBranch, PlayCircle, ShieldCheck } from "lucide-react";

export function CICDPage() {
  return (
    <section className="workspace">
      <section className="scan-hero">
        <div>
          <h1>CI Security Scan</h1>
          <p>Run the scanner in GitHub Actions on pushes and pull requests, then keep HTML/PDF reports as build artifacts.</p>
        </div>
        <div className="hero-status-cluster">
          <div><span>Workflow</span><strong>security-scan.yml</strong></div>
          <div><span>Mode</span><strong>Quick profile</strong></div>
        </div>
      </section>

      <section className="analytics-grid">
        <article className="panel analytics-panel">
          <header className="panel-header">
            <div><GitBranch size={18} /><strong>Pipeline Steps</strong></div>
            <span>PR ready</span>
          </header>
          <div className="timeline-list">
            {["Install Python and Node", "Run backend tests", "Build frontend", "Run scanner CLI with quick profile", "Upload scan reports"].map((item, index) => (
              <div key={item} className="timeline-row">
                <strong>{index + 1}</strong>
                <small>{item}</small>
                <span>ready</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel analytics-panel">
          <header className="panel-header">
            <div><ShieldCheck size={18} /><strong>Controls</strong></div>
            <span>safe</span>
          </header>
          <div className="scan-progress-meta">
            <div><span>Profile</span><strong>quick</strong></div>
            <div><span>Target</span><strong>CI env var</strong></div>
            <div><span>External auth</span><strong>required</strong></div>
            <div><span>Artifacts</span><strong>reports</strong></div>
          </div>
        </article>

        <article className="panel analytics-panel">
          <header className="panel-header">
            <div><PlayCircle size={18} /><strong>Local Equivalent</strong></div>
            <span>CLI</span>
          </header>
          <code className="drawer-code">python scripts/run_scanner.py https://staging.example.com --profile quick</code>
        </article>
      </section>
    </section>
  );
}
