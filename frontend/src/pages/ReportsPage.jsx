import React, { useEffect, useState } from "react";
import { Archive, FileCheck2, ShieldAlert } from "lucide-react";
import { VulnerabilityCard } from "../components/VulnerabilityCard.jsx";
import { fetchReportDetail, fetchReports } from "../services/api.js";

export function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [selectedReportId, setSelectedReportId] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);

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

  return (
    <section className="workspace">
      <section className="scan-hero">
        <div>
          <h1>Reports Vault</h1>
          <p>Review saved scan runs, compare targets, and keep an eye on how much signal your scanner is producing over time.</p>
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
          <strong className="metric-compact">{reports[0]?.target_url ?? "No scans yet"}</strong>
        </article>
      </section>

      <div className="report-list">
        {reports.length ? (
          reports.map((report) => (
            <article
              key={report.scan_id}
              className={`report-row ${selectedReportId === report.scan_id ? "selected" : ""}`}
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

      <section className="report-detail-grid">
        <article className="panel">
          <header className="panel-header">
            <div>
              <FileCheck2 size={18} />
              <strong>Run Detail</strong>
            </div>
            <span>{selectedReport?.scan_id ?? "No report selected"}</span>
          </header>
          {selectedReport ? (
            <div className="report-detail-stack">
              <div className="report-summary-cards">
                <div><span>Pages</span><strong>{selectedReport.summary?.page_count ?? 0}</strong></div>
                <div><span>Forms</span><strong>{selectedReport.summary?.form_count ?? 0}</strong></div>
                <div><span>Endpoints</span><strong>{selectedReport.summary?.endpoint_count ?? 0}</strong></div>
                <div><span>Duration</span><strong>{selectedReport.summary?.duration_ms ?? 0} ms</strong></div>
              </div>
              <a
                className="report-link"
                href={`http://127.0.0.1:8000${selectedReport.report_url}`}
                target="_blank"
                rel="noreferrer"
              >
                Open HTML report
              </a>
              <div className="timing-list">
                {(selectedReport.detector_timings ?? []).length ? (
                  selectedReport.detector_timings.map((timing) => (
                    <div key={timing.detector} className="timing-row">
                      <div>
                        <strong>{timing.detector}</strong>
                        <small>{timing.finding_count} findings</small>
                      </div>
                      <span>{timing.elapsed_ms} ms</span>
                    </div>
                  ))
                ) : (
                  <div className="empty-panel">No detector timing data recorded for this run.</div>
                )}
              </div>
            </div>
          ) : (
            <div className="empty-panel">Select a saved scan to inspect detector timings and findings.</div>
          )}
        </article>

        <article className="panel">
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
                <VulnerabilityCard key={`${finding.url}-${index}`} finding={finding} />
              ))
            ) : (
              <div className="empty-panel">This report has no findings recorded yet.</div>
            )}
          </div>
        </article>
      </section>
    </section>
  );
}
