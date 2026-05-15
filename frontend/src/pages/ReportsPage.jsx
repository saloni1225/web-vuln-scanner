import React, { useEffect, useMemo, useState } from "react";
import { Archive, FileCheck2, ShieldAlert, Sparkles, TrendingUp } from "lucide-react";
import { FindingDetailDrawer } from "../components/FindingDetailDrawer.jsx";
import { VulnerabilityCard } from "../components/VulnerabilityCard.jsx";
import { fetchReportComparison, fetchReportDetail, fetchReports, fetchRoleComparison, fetchScanHistory, resumeScan } from "../services/api.js";

export function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [selectedReportId, setSelectedReportId] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [compareLeftId, setCompareLeftId] = useState("");
  const [compareRightId, setCompareRightId] = useState("");
  const [comparison, setComparison] = useState(null);
  const [roleComparison, setRoleComparison] = useState(null);
  const [scanHistory, setScanHistory] = useState({ severity_trends: [] });
  const [resumeMessage, setResumeMessage] = useState("");

  useEffect(() => {
    fetchReports()
      .then((items) => {
        setReports(items);
        if (items.length) {
          setSelectedReportId(items[0].scan_id);
          setCompareLeftId(items[0].scan_id);
          setCompareRightId(items[1]?.scan_id ?? items[0].scan_id);
        }
      })
      .catch(() => setReports([]));
    fetchScanHistory()
      .then(setScanHistory)
      .catch(() => setScanHistory({ severity_trends: [] }));
  }, []);

  useEffect(() => {
    if (!selectedReportId) {
      setSelectedReport(null);
      return;
    }
    fetchReportDetail(selectedReportId).then(setSelectedReport).catch(() => setSelectedReport(null));
  }, [selectedReportId]);

  useEffect(() => {
    if (!compareLeftId || !compareRightId || compareLeftId === compareRightId) {
      setComparison(null);
      return;
    }
    fetchReportComparison(compareLeftId, compareRightId).then(setComparison).catch(() => setComparison(null));
    fetchRoleComparison(compareLeftId, compareRightId).then(setRoleComparison).catch(() => setRoleComparison(null));
  }, [compareLeftId, compareRightId]);

  async function onResumeSelected() {
    if (!selectedReport?.scan_id) {
      return;
    }
    setResumeMessage("Resuming scan...");
    try {
      const resumed = await resumeScan(selectedReport.scan_id);
      setResumeMessage(`Resumed as ${resumed.scan_id}`);
      const items = await fetchReports();
      setReports(items);
      setSelectedReportId(resumed.scan_id);
    } catch (error) {
      setResumeMessage(String(error.message || "Could not resume scan"));
    }
  }

  const totalFindings = reports.reduce((sum, report) => sum + (report.findings_count ?? 0), 0);
  const latestTarget = reports[0]?.target_url ?? "No scans yet";
  const summary = selectedReport?.summary ?? {};
  const latestRiskGate = selectedReport?.risk_gate ?? {};
  const trendPoints = scanHistory.severity_trends ?? [];
  const maxTrendTotal = Math.max(1, ...trendPoints.map((item) => item.total ?? 0));

  const severityMix = useMemo(
    () => [
      { label: "High", value: summary.high_severity_count ?? 0 },
      { label: "Medium", value: summary.medium_severity_count ?? 0 },
      { label: "Low", value: summary.low_severity_count ?? 0 },
    ],
    [summary]
  );

  return (
    <section className="workspace reports-workspace hacker-surface">
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
          <span>Risk gate</span>
          <strong>{latestRiskGate.status ?? reports[0]?.risk_gate_status ?? "unknown"}</strong>
        </article>
      </section>

      <section className="analytics-grid">
        <article className="panel analytics-panel trend-panel">
          <header className="panel-header">
            <div>
              <TrendingUp size={18} />
              <strong>Severity Trend</strong>
            </div>
            <span>{trendPoints.length} scans</span>
          </header>
          <div className="trend-legend" aria-label="Severity legend">
            <span><i className="high" />High</span>
            <span><i className="medium" />Medium</span>
            <span><i className="low" />Low</span>
          </div>
          <div className="trend-chart">
            {trendPoints.length ? (
              trendPoints.map((point, index) => (
                <div key={point.scan_id} className="trend-column" title={`${point.target_url} · ${point.total} findings`}>
                  <div className={`trend-status ${point.risk_gate_status === "failed" ? "failed" : "passed"}`} />
                  <div className="trend-stack">
                    <span className="trend-segment low" style={{ height: point.low ? `${Math.max(4, ((point.low ?? 0) / maxTrendTotal) * 100)}%` : 0 }} />
                    <span className="trend-segment medium" style={{ height: point.medium ? `${Math.max(4, ((point.medium ?? 0) / maxTrendTotal) * 100)}%` : 0 }} />
                    <span className="trend-segment high" style={{ height: point.high ? `${Math.max(4, ((point.high ?? 0) / maxTrendTotal) * 100)}%` : 0 }} />
                  </div>
                  <strong>{point.total ?? 0}</strong>
                  <small>Run {index + 1} · {point.high ?? 0}H</small>
                </div>
              ))
            ) : (
              <div className="empty-panel">Run scans to build severity trends and regression history.</div>
            )}
          </div>
        </article>

        <article className="panel analytics-panel">
          <header className="panel-header">
            <div>
              <ShieldAlert size={18} />
              <strong>Risk Gate Policy</strong>
            </div>
            <span>{latestRiskGate.status ?? "not evaluated"}</span>
          </header>
          <div className="timing-list">
            <div className="timing-row">
              <div>
                <strong>High severity gate</strong>
                <small>Default policy fails when high findings are above zero</small>
              </div>
              <span>{latestRiskGate.policy?.max_high ?? 0}</span>
            </div>
            {(latestRiskGate.failures ?? []).map((failure) => (
              <div key={failure} className="timing-row risk-failure">
                <div>
                  <strong>Pipeline blocker</strong>
                  <small>{failure}</small>
                </div>
                <span>fail</span>
              </div>
            ))}
            {latestRiskGate.passed ? (
              <div className="timing-row">
                <div>
                  <strong>No blockers</strong>
                  <small>This scan passed the configured CI policy.</small>
                </div>
                <span>pass</span>
              </div>
            ) : null}
          </div>
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
                    <div><span>Risk gate</span><strong>{selectedReport.risk_gate?.status ?? "unknown"}</strong></div>
                  </div>
                </section>

                <section className="report-summary-cards report-summary-expanded">
                  <div><span>Pages</span><strong>{summary.page_count ?? 0}</strong></div>
                  <div><span>Forms</span><strong>{summary.form_count ?? 0}</strong></div>
                  <div><span>Endpoints</span><strong>{summary.endpoint_count ?? 0}</strong></div>
                  <div><span>API</span><strong>{summary.api_endpoint_count ?? 0}</strong></div>
                  <div><span>GraphQL</span><strong>{summary.graphql_endpoint_count ?? 0}</strong></div>
                  <div><span>Schema modeled</span><strong>{summary.schema_modeled_endpoint_count ?? 0}</strong></div>
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
                      <div className="timing-row">
                        <div>
                          <strong>Attack-chain signals</strong>
                          <small>{(selectedReport.attack_chain_summary?.candidates ?? []).join(", ") || "none"}</small>
                        </div>
                        <span>{selectedReport.attack_chain_summary?.candidate_count ?? 0}</span>
                      </div>
                    </div>
                  </article>

                  <article className="insight-card">
                    <header className="panel-header">
                      <div>
                        <Archive size={18} />
                        <strong>Role / Session</strong>
                      </div>
                    </header>
                    <div className="timing-list">
                      <div className="timing-row">
                        <div>
                          <strong>Role</strong>
                          <small>{selectedReport.role_summary?.role_name ?? "default"}</small>
                        </div>
                        <span>{selectedReport.auth_summary?.login_performed ? "Logged in" : "Direct"}</span>
                      </div>
                      <div className="timing-row">
                        <div>
                          <strong>Cookies / Headers</strong>
                          <small>{selectedReport.auth_summary?.cookie_count ?? 0} cookies · {selectedReport.auth_summary?.header_count ?? 0} headers</small>
                        </div>
                        <span>{selectedReport.auth_used ? "Auth" : "Anon"}</span>
                      </div>
                    </div>
                  </article>
                </section>

                <div className="report-export-row">
                  <a
                    className="report-link"
                    href={`http://127.0.0.1:8000${selectedReport.report_url}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Open HTML report
                  </a>
                  {selectedReport.pdf_report_url ? (
                    <a
                      className="report-link secondary"
                      href={`http://127.0.0.1:8000${selectedReport.pdf_report_url}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Open PDF report
                    </a>
                  ) : null}
                  <button className="report-link secondary" type="button" onClick={onResumeSelected}>
                    Resume scan
                  </button>
                  {resumeMessage ? <small>{resumeMessage}</small> : null}
                </div>
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

          <article className="panel findings-preview-panel">
            <header className="panel-header">
              <div>
                <Archive size={18} />
                <strong>Report Comparison</strong>
              </div>
              <span>{comparison ? comparison.summary_delta?.finding_delta ?? 0 : "pick two"}</span>
            </header>
            <div className="compare-controls">
              <select value={compareLeftId} onChange={(event) => setCompareLeftId(event.target.value)}>
                {reports.map((report) => (
                  <option key={`left-${report.scan_id}`} value={report.scan_id}>{report.target_url} · {report.scan_id}</option>
                ))}
              </select>
              <select value={compareRightId} onChange={(event) => setCompareRightId(event.target.value)}>
                {reports.map((report) => (
                  <option key={`right-${report.scan_id}`} value={report.scan_id}>{report.target_url} · {report.scan_id}</option>
                ))}
              </select>
            </div>
            {comparison ? (
              <div className="timing-list">
                <div className="timing-row">
                  <div>
                    <strong>Finding delta</strong>
                    <small>new minus baseline</small>
                  </div>
                  <span>{comparison.summary_delta?.finding_delta ?? 0}</span>
                </div>
                <div className="timing-row">
                  <div>
                    <strong>New findings</strong>
                    <small>{comparison.new_findings?.length ?? 0} introduced</small>
                  </div>
                  <span>{comparison.new_findings?.length ?? 0}</span>
                </div>
                <div className="timing-row">
                  <div>
                    <strong>Resolved findings</strong>
                    <small>{comparison.resolved_findings?.length ?? 0} removed</small>
                  </div>
                  <span>{comparison.resolved_findings?.length ?? 0}</span>
                </div>
              </div>
            ) : (
              <div className="empty-panel">Select two different reports to compare changes in coverage and findings.</div>
            )}
            {roleComparison ? (
              <div className="timing-list">
                <div className="timing-row">
                  <div>
                    <strong>Role compare</strong>
                    <small>{roleComparison.left_role} vs {roleComparison.right_role}</small>
                  </div>
                  <span>{roleComparison.shared_endpoint_count}</span>
                </div>
                <div className="timing-row">
                  <div>
                    <strong>Privileged overlap</strong>
                    <small>{(roleComparison.suspicious_shared_privileged_endpoints ?? []).slice(0, 2).join(", ") || "none"}</small>
                  </div>
                  <span>{roleComparison.suspicious_shared_privileged_endpoints?.length ?? 0}</span>
                </div>
              </div>
            ) : null}
          </article>
        </section>
      </section>

      <FindingDetailDrawer finding={selectedFinding} open={Boolean(selectedFinding)} onClose={() => setSelectedFinding(null)} />
    </section>
  );
}
