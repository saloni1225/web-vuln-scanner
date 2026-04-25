import React, { useEffect, useMemo, useState } from "react";
import { Archive, FileCheck2, ShieldAlert, Sparkles } from "lucide-react";
import { FindingDetailDrawer } from "../components/FindingDetailDrawer.jsx";
import { VulnerabilityCard } from "../components/VulnerabilityCard.jsx";
import { fetchReportDetail, fetchReports } from "../services/api.js";

export function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [selectedReportId, setSelectedReportId] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => {
    fetchReports()
      .then((items) => {
        setReports(items);
        if (items.length) {
          setSelectedReportId(items[0].scan_id);
        }
      })
      .catch(() => setReports([]));
  }, []);

  useEffect(() => {
    if (!selectedReportId) {
      setSelectedReport(null);
      return;
    }
    fetchReportDetail(selectedReportId).then(setSelectedReport).catch(() => setSelectedReport(null));
  }, [selectedReportId]);

  const totalFindings = reports.reduce((sum, report) => sum + (report.findings_count ?? 0), 0);
  const latestTarget = reports[0]?.target_url ?? "No scans yet";
  const summary = selectedReport?.summary ?? {};

  const severityMix = useMemo(
    () => [
      { label: "High", value: summary.high_severity_count ?? 0 },
      { label: "Medium", value: summary.medium_severity_count ?? 0 },
      { label: "Low", value: summary.low_severity_count ?? 0 },
    ],
    [summary]
  );

  return (
    <section className="workspace">
      <section className="scan-hero">
        <div>
          <h1>Reports Vault</h1>
          <p>Review saved runs, inspect evidence in context, and move from broad scan history to the exact request pattern that matters.</p>
        </div>
      </section>

      <section className="metrics-grid report-metrics">
        <article className="metric-card">
          <Archive size={18} />
          <span>Saved scans</span>
          <strong>{reports.length}</strong>
        </article>
        <article className="metric-card">
          <ShieldAlert size={18} />
          <span>Total findings</span>
          <strong>{totalFindings}</strong>
        </article>
        <article className="metric-card">
          <FileCheck2 size={18} />
          <span>Latest target</span>
          <strong className="metric-compact">{latestTarget}</strong>
        </article>
        <article className="metric-card">
          <Sparkles size={18} />
          <span>Selected report</span>
          <strong>{selectedReport?.findings?.length ?? 0}</strong>
        </article>
      </section>

      <section className="reports-shell">
        <aside className="panel reports-sidebar">
          <header className="panel-header">
            <div>
              <Archive size={18} />
              <strong>Run History</strong>
            </div>
            <span>{reports.length}</span>
          </header>
          <div className="report-list report-list-sidebar">
            {reports.length ? (
              reports.map((report) => (
                <article
                  key={report.scan_id}
                  className={`report-row report-card ${selectedReportId === report.scan_id ? "selected" : ""}`}
                  onClick={() => setSelectedReportId(report.scan_id)}
                >
                  <div>
                    <strong>{report.target_url}</strong>
                    <small>{report.scan_id}</small>
                  </div>
                  <span>{report.findings_count} findings</span>
                  <small>{report.finished_at}</small>
                </article>
              ))
            ) : (
              <article className="panel empty-state">
                <strong>No saved reports yet.</strong>
                <p>Run the scanner once to populate this vault with historical scan summaries.</p>
              </article>
            )}
          </div>
        </aside>

        <section className="reports-main">
          <article className="panel report-overview">
            <header className="panel-header">
              <div>
                <FileCheck2 size={18} />
                <strong>Selected Run</strong>
              </div>
              <span>{selectedReport?.scan_id ?? "No report selected"}</span>
            </header>
            {selectedReport ? (
              <div className="report-overview-stack">
                <section className="report-hero-card">
                  <div>
                    <small>Target</small>
                    <strong>{selectedReport.target_url}</strong>
                  </div>
                  <div className="report-hero-meta">
                    <div><span>Duration</span><strong>{summary.duration_ms ?? 0} ms</strong></div>
                    <div><span>Auth</span><strong>{selectedReport.auth_used ? "Enabled" : "Anonymous"}</strong></div>
                    <div><span>Plugins</span><strong>{selectedReport.detector_registry?.length ?? 0}</strong></div>
                    <div><span>Avg anomaly</span><strong>{selectedReport.behavioral_summary?.average_anomaly_score ?? 0}</strong></div>
                  </div>
                </section>

                <section className="report-summary-cards report-summary-expanded">
                  <div><span>Pages</span><strong>{summary.page_count ?? 0}</strong></div>
                  <div><span>Forms</span><strong>{summary.form_count ?? 0}</strong></div>
                  <div><span>Endpoints</span><strong>{summary.endpoint_count ?? 0}</strong></div>
                  <div><span>API</span><strong>{summary.api_endpoint_count ?? 0}</strong></div>
                  <div><span>GraphQL</span><strong>{summary.graphql_endpoint_count ?? 0}</strong></div>
                  <div><span>Findings</span><strong>{summary.finding_count ?? 0}</strong></div>
                </section>

                <section className="reports-insight-grid">
                  <article className="insight-card">
                    <header className="panel-header">
                      <div>
                        <ShieldAlert size={18} />
                        <strong>Severity Mix</strong>
                      </div>
                    </header>
                    <div className="bar-chart compact-chart">
                      {severityMix.map((item) => (
                        <div key={item.label} className="bar-row">
                          <div className="bar-label">
                            <strong>{item.label}</strong>
                            <span>{item.value}</span>
                          </div>
                          <div className="bar-track">
                            <div
                              className={`bar-fill ${item.label.toLowerCase()}`}
                              style={{ width: `${Math.max(8, (item.value / Math.max(1, summary.finding_count ?? 1)) * 100)}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="insight-card">
                    <header className="panel-header">
                      <div>
                        <Sparkles size={18} />
                        <strong>Runtime Signal</strong>
                      </div>
                    </header>
                    <div className="timing-list">
                      <div className="timing-row">
                        <div>
                          <strong>Detector plugins</strong>
                          <small>{(selectedReport.detector_registry ?? []).map((item) => item.name).join(", ") || "none"}</small>
                        </div>
                        <span>{selectedReport.detector_registry?.length ?? 0}</span>
                      </div>
                      {(selectedReport.detector_timings ?? []).slice(0, 4).map((timing) => (
                        <div key={timing.detector} className="timing-row">
                          <div>
                            <strong>{timing.detector}</strong>
                            <small>{timing.finding_count} findings</small>
                          </div>
                          <span>{timing.elapsed_ms} ms</span>
                        </div>
                      ))}
                    </div>
                  </article>
                </section>

                <a
                  className="report-link"
                  href={`http://127.0.0.1:8000${selectedReport.report_url}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Open HTML report
                </a>
              </div>
            ) : (
              <div className="empty-panel">Select a saved scan to inspect detector timings and findings.</div>
            )}
          </article>

          <article className="panel findings-preview-panel">
            <header className="panel-header">
              <div>
                <ShieldAlert size={18} />
                <strong>Findings Preview</strong>
              </div>
              <span>{selectedReport?.findings?.length ?? 0}</span>
            </header>
            <div className="report-findings-list">
              {(selectedReport?.findings ?? []).length ? (
                selectedReport.findings.map((finding, index) => (
                  <VulnerabilityCard
                    key={`${finding.url}-${index}`}
                    finding={finding}
                    onOpenDetail={setSelectedFinding}
                  />
                ))
              ) : (
                <div className="empty-panel">This report has no findings recorded yet.</div>
              )}
            </div>
          </article>
        </section>
      </section>

      <FindingDetailDrawer finding={selectedFinding} open={Boolean(selectedFinding)} onClose={() => setSelectedFinding(null)} />
    </section>
  );
}
