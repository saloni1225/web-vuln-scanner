import React from "react";
import { ActivitySquare, Radar, ShieldCheck, Siren, Timer } from "lucide-react";

export function Dashboard({ result, progress, detectorTimings }) {
  const summary = result?.summary ?? {};
  const findings = [
    { label: "High", value: summary.high_severity_count ?? 0, tone: "high" },
    { label: "Medium", value: summary.medium_severity_count ?? 0, tone: "medium" },
    {
      label: "Info",
      value: Math.max(
        0,
        (summary.finding_count ?? 0) - (summary.high_severity_count ?? 0) - (summary.medium_severity_count ?? 0)
      ),
      tone: "info",
    },
  ];
  const maxFindingBucket = Math.max(1, ...findings.map((item) => item.value));
  const pages = summary.page_count ?? 0;
  const forms = summary.form_count ?? 0;
  const endpoints = summary.endpoint_count ?? 0;
  const apiEndpoints = summary.api_endpoint_count ?? result?.api_summary?.api_endpoint_count ?? 0;
  const graphqlEndpoints = summary.graphql_endpoint_count ?? result?.api_summary?.graphql_endpoint_count ?? 0;
  const enabledDetectors = result?.detector_registry?.length ?? 0;
  const anomalyScore = result?.behavioral_summary?.average_anomaly_score ?? 0;
  const surfaceTotal = Math.max(1, pages + forms + endpoints);
  const chartCircumference = 314;
  const endpointRatio = endpoints / surfaceTotal;
  const chartOffset = chartCircumference - chartCircumference * endpointRatio;
  const timingSource = detectorTimings?.length ? detectorTimings : result?.detector_timings ?? [];
  const progressValue = progress?.progress ?? (result ? 100 : 0);

  return (
    <>
      <section className="metrics-grid">
        <article className="metric-card">
          <ShieldCheck />
          <span>Pages</span>
          <strong>{pages}</strong>
        </article>
        <article className="metric-card">
          <Siren />
          <span>Findings</span>
          <strong>{summary.finding_count ?? 0}</strong>
        </article>
        <article className="metric-card">
          <Radar />
          <span>Endpoints</span>
          <strong>{endpoints}</strong>
        </article>
        <article className="metric-card">
          <Timer />
          <span>Status</span>
          <strong>{result ? "Complete" : "Ready"}</strong>
        </article>
        <article className="metric-card">
          <ActivitySquare />
          <span>API / GraphQL</span>
          <strong>{apiEndpoints} / {graphqlEndpoints}</strong>
        </article>
        <article className="metric-card">
          <ShieldCheck />
          <span>Detectors</span>
          <strong>{enabledDetectors}</strong>
        </article>
      </section>

      <section className="analytics-grid">
        <article className="panel analytics-panel">
          <header className="panel-header">
            <div>
              <ActivitySquare size={18} />
              <strong>Threat Distribution</strong>
            </div>
            <span>{summary.finding_count ?? 0} total</span>
          </header>
          <div className="bar-chart">
            {findings.map((item) => (
              <div key={item.label} className="bar-row">
                <div className="bar-label">
                  <strong>{item.label}</strong>
                  <span>{item.value}</span>
                </div>
                <div className="bar-track">
                  <div
                    className={`bar-fill ${item.tone}`}
                    style={{ width: `${(item.value / maxFindingBucket) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </article>

        <article className="panel analytics-panel">
          <header className="panel-header">
            <div>
              <Timer size={18} />
              <strong>Live Progress</strong>
            </div>
            <span>{progressValue}%</span>
          </header>
          <div className="scan-progress-panel">
            <div className="scan-progress-track">
              <div className="scan-progress-fill" style={{ width: `${progressValue}%` }} />
            </div>
            <p>{progress?.message ?? (result ? "Scan completed." : "Waiting for a scan run.")}</p>
            <div className="scan-progress-meta">
              <div><span>Status</span><strong>{progress?.status ?? (result ? "completed" : "idle")}</strong></div>
              <div><span>Duration</span><strong>{result?.summary?.duration_ms ?? 0} ms</strong></div>
              <div><span>Avg anomaly</span><strong>{anomalyScore}</strong></div>
            </div>
          </div>
        </article>

        <article className="panel analytics-panel">
          <header className="panel-header">
            <div>
              <Radar size={18} />
              <strong>Attack Surface Coverage</strong>
            </div>
            <span>{surfaceTotal} assets</span>
          </header>
          <div className="radial-layout">
            <div className="radial-chart">
              <svg viewBox="0 0 120 120" aria-hidden="true">
                <circle cx="60" cy="60" r="50" className="radial-track" />
                <circle
                  cx="60"
                  cy="60"
                  r="50"
                  className="radial-fill"
                  strokeDasharray={chartCircumference}
                  strokeDashoffset={chartOffset}
                />
              </svg>
              <div className="radial-center">
                <strong>{Math.round(endpointRatio * 100)}%</strong>
                <span>mapped</span>
              </div>
            </div>
            <div className="surface-breakdown">
              <div><span>Pages</span><strong>{pages}</strong></div>
              <div><span>Forms</span><strong>{forms}</strong></div>
              <div><span>Endpoints</span><strong>{endpoints}</strong></div>
              <div><span>API</span><strong>{apiEndpoints}</strong></div>
              <div><span>GraphQL</span><strong>{graphqlEndpoints}</strong></div>
            </div>
          </div>
        </article>

        <article className="panel analytics-panel timing-panel">
          <header className="panel-header">
            <div>
              <ActivitySquare size={18} />
              <strong>Detector Timing</strong>
            </div>
            <span>{timingSource.length} stages</span>
          </header>
          <div className="timing-list">
            {timingSource.length ? (
              timingSource.map((timing) => (
                <div key={timing.detector} className="timing-row">
                  <div>
                    <strong>{timing.detector}</strong>
                    <small>{timing.finding_count} findings</small>
                  </div>
                  <span>{timing.elapsed_ms} ms</span>
                </div>
              ))
            ) : (
              <div className="empty-panel">Detector timings will appear during or after a scan.</div>
            )}
          </div>
        </article>
      </section>
    </>
  );
}
