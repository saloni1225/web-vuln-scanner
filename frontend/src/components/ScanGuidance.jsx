import React from "react";
import { AlertTriangle, FlaskConical, FileText } from "lucide-react";

export function ScanGuidance({ result, targetUrl }) {
  const advisory = result?.target_advisory;
  const recommendedTargets = advisory?.recommended_targets ?? ["http://127.0.0.1:3000"];

  return (
    <section className="guidance-grid">
      <article className="panel guidance-card">
        <header className="panel-header">
          <div>
            <FlaskConical size={18} />
            <strong>Recommended Lab</strong>
          </div>
        </header>
        <p>Run OWASP Juice Shop locally, then scan one of these addresses:</p>
        <ul className="chip-list">
          {recommendedTargets.map((target) => (
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
