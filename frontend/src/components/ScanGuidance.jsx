import React from "react";
import { AlertTriangle, FileText, Globe2 } from "lucide-react";

export function ScanGuidance({ result, targetUrl }) {
  const advisory = result?.target_advisory;
  const targetExamples = advisory?.recommended_targets ?? ["https://staging.example.com", "https://app.example.com"];

  return (
    <section className="guidance-grid">
      <article className="panel guidance-card">
        <header className="panel-header">
          <div>
            <Globe2 size={18} />
            <strong>Hosted Targets</strong>
          </div>
        </header>
        <p>Scan authorized web apps, staging environments, or internal services by URL.</p>
        <ul className="chip-list">
          {targetExamples.map((target) => (
            <li key={target}>{target}</li>
          ))}
        </ul>
      </article>

      <article className={`panel guidance-card ${advisory?.safe_for_demo === false ? "warning-card" : ""}`}>
        <header className="panel-header">
          <div>
            <AlertTriangle size={18} />
            <strong>Target Advisory</strong>
          </div>
        </header>
        <p>{advisory?.message ?? "Use a local or explicitly authorized target while developing detectors."}</p>
        {!advisory ? <small>External targets require the authorization confirmation before scanning.</small> : null}
        {targetUrl ? <small>Current target: {targetUrl}</small> : null}
      </article>

      <article className="panel guidance-card">
        <header className="panel-header">
          <div>
            <FileText size={18} />
            <strong>Report</strong>
          </div>
        </header>
        {result?.report_url ? (
          <a className="report-link" href={`http://127.0.0.1:8000${result.report_url}`} target="_blank" rel="noreferrer">
            Open HTML report
          </a>
        ) : (
          <p>Run a scan to generate a downloadable report.</p>
        )}
      </article>
    </section>
  );
}
