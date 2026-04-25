import React from "react";
import { ArrowUpRight, CircleAlert, X } from "lucide-react";

export function FindingDetailDrawer({ finding, open, onClose }) {
  if (!open || !finding) {
    return null;
  }

  const evidenceRows = [
    ["Detector", String(finding.detector ?? "generic").toUpperCase()],
    ["Severity", finding.severity ?? "unknown"],
    ["Confidence", finding.confidence ?? "medium"],
    ["Score", finding.confidence_score ?? "-"],
    ["Priority", finding.remediation_priority ?? "-"],
    ["Method", String(finding.method ?? "get").toUpperCase()],
    ["Parameter", finding.parameter ?? "-"],
    ["Input", finding.input_location ?? "-"],
    ["Context", finding.reflection_context ?? "-"],
    ["DOM", finding.dom_observation ?? "-"],
    ["Validation", finding.validation_state ?? "-"],
  ];

  return (
    <div className="drawer-backdrop" onClick={onClose} role="presentation">
      <aside className="finding-drawer" onClick={(event) => event.stopPropagation()}>
        <header className="drawer-header">
          <div>
            <span className={`drawer-severity severity-pill severity-${finding.severity}`}>{finding.severity}</span>
            <h3>{String(finding.detector ?? "finding").toUpperCase()} Finding</h3>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close finding drawer">
            <X size={18} />
          </button>
        </header>

        <section className="drawer-block drawer-highlight">
          <div className="drawer-title">
            <CircleAlert size={18} />
            <strong>Evidence Summary</strong>
          </div>
          <p>{finding.evidence}</p>
          <small>{finding.reason ?? "No additional reasoning captured for this finding."}</small>
        </section>

        <section className="drawer-grid">
          {evidenceRows.map(([label, value]) => (
            <article key={label} className="drawer-stat">
              <span>{label}</span>
              <strong>{value}</strong>
            </article>
          ))}
        </section>

        <section className="drawer-block">
          <div className="drawer-title">
            <ArrowUpRight size={18} />
            <strong>Technical Detail</strong>
          </div>
          <div className="drawer-kv">
            <div><span>URL</span><strong>{finding.url}</strong></div>
            <div><span>Status delta</span><strong>{finding.baseline_status ?? "-"} {"->"} {finding.mutated_status ?? "-"}</strong></div>
            <div><span>Length delta</span><strong>{finding.baseline_length ?? "-"} {"->"} {finding.mutated_length ?? "-"}</strong></div>
            <div><span>CVSS</span><strong>{finding.cvss_score ?? "-"}</strong></div>
          </div>
          {finding.validation_signals?.length ? (
            <div className="drawer-chip-row">
              {finding.validation_signals.map((signal) => (
                <span key={signal} className="drawer-chip">{signal}</span>
              ))}
            </div>
          ) : null}
          {finding.poc ? <code className="drawer-code">{finding.poc}</code> : null}
          {finding.payload ? <code className="drawer-code">{finding.payload}</code> : null}
          {finding.request_snapshot ? <code className="drawer-code">{finding.request_snapshot}</code> : null}
          {finding.response_snapshot ? <code className="drawer-code">{finding.response_snapshot}</code> : null}
        </section>

        <section className="drawer-block">
          <div className="drawer-title">
            <strong>Recommended Action</strong>
          </div>
          <p>{finding.recommendation}</p>
        </section>
      </aside>
    </div>
  );
}
