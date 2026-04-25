import React, { useEffect, useMemo, useState } from "react";
import { Dashboard } from "../components/Dashboard.jsx";
import { DiscoveryPanel } from "../components/DiscoveryPanel.jsx";
import { LogsViewer } from "../components/LogsViewer.jsx";
import { ScanGuidance } from "../components/ScanGuidance.jsx";
import { ScanPanel } from "../components/ScanPanel.jsx";
import { VulnerabilityCard } from "../components/VulnerabilityCard.jsx";
import { startScan } from "../services/api.js";
import { createScanSocket } from "../services/socket.js";

export function ScanPage() {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:3000");
  const [authHeaderName, setAuthHeaderName] = useState("Authorization");
  const [authHeaderValue, setAuthHeaderValue] = useState("");
  const [authCookieName, setAuthCookieName] = useState("");
  const [authCookieValue, setAuthCookieValue] = useState("");
  const [result, setResult] = useState(null);
  const [logs, setLogs] = useState([
    "Scanner ready.",
    "Tip: launch OWASP Juice Shop locally on http://127.0.0.1:3000 for a safer demo target.",
  ]);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState({ progress: 0, status: "idle", message: "Waiting for the next scan run." });
  const [detectorTimings, setDetectorTimings] = useState([]);

  useEffect(() => {
    const socket = createScanSocket((event) => {
      setProgress((current) => ({
        progress: event.progress ?? current.progress,
        status: event.status ?? current.status,
        message: event.message ?? current.message,
      }));
      if (event.event === "scan_started") {
        setLogs((current) => [...current, event.message]);
      }
      if (event.event === "crawl_completed") {
        setLogs((current) => [...current, event.message]);
      }
      if (event.event === "detector_completed") {
        setDetectorTimings((current) => {
          const remaining = current.filter((item) => item.detector !== event.detector);
          return [...remaining, { detector: event.detector, elapsed_ms: event.elapsed_ms, finding_count: event.finding_count }];
        });
        setLogs((current) => [...current, `${event.detector} detector finished in ${event.elapsed_ms} ms`]);
      }
      if (event.event === "scan_completed") {
        setDetectorTimings(event.detector_timings ?? []);
        setLogs((current) => [...current, event.message]);
      }
    });
    return () => socket.close();
  }, []);

  const mergedDetectorTimings = useMemo(
    () => (detectorTimings.length ? detectorTimings : result?.detector_timings ?? []),
    [detectorTimings, result]
  );

  async function onScan(event) {
    event.preventDefault();
    setIsScanning(true);
    setProgress({ progress: 3, status: "running", message: `Queued scan for ${targetUrl}` });
    setDetectorTimings([]);
    setLogs((current) => [...current, `Starting scan for ${targetUrl}`, "Crawling pages and enumerating forms..."]);
    try {
      const authHeaders = {};
      const authCookies = {};
      if (authHeaderName.trim() && authHeaderValue.trim()) {
        authHeaders[authHeaderName.trim()] = authHeaderValue.trim();
      }
      if (authCookieName.trim() && authCookieValue.trim()) {
        authCookies[authCookieName.trim()] = authCookieValue.trim();
      }
      const scan = await startScan(targetUrl, { headers: authHeaders, cookies: authCookies });
      setResult(scan);
      setProgress({ progress: 100, status: "completed", message: `Scan completed in ${scan.summary.duration_ms} ms` });
      setDetectorTimings(scan.detector_timings ?? []);
      setLogs((current) => [
        ...current,
        `Scan complete: ${scan.summary.finding_count} findings`,
        `Discovered ${scan.summary.page_count} pages, ${scan.summary.form_count} forms, and ${scan.summary.endpoint_count} endpoints`,
      ]);
    } catch (error) {
      setLogs((current) => [...current, `Scan failed: ${error.message}`]);
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <section className="workspace">
      <section className="scan-hero">
        <div>
          <h1>Scan Workspace</h1>
          <p>Profile a target, inspect discovered attack surface, review evidence-backed findings, and watch the scan behave like a live security console.</p>
        </div>
        <div className="hero-status-cluster">
          <div>
            <span>Target</span>
            <strong>{targetUrl}</strong>
          </div>
          <div>
            <span>Mode</span>
            <strong>Local Lab</strong>
          </div>
        </div>
      </section>
      <ScanPanel
        targetUrl={targetUrl}
        setTargetUrl={setTargetUrl}
        authHeaderName={authHeaderName}
        setAuthHeaderName={setAuthHeaderName}
        authHeaderValue={authHeaderValue}
        setAuthHeaderValue={setAuthHeaderValue}
        authCookieName={authCookieName}
        setAuthCookieName={setAuthCookieName}
        authCookieValue={authCookieValue}
        setAuthCookieValue={setAuthCookieValue}
        isScanning={isScanning}
        onScan={onScan}
        progress={progress}
      />
      <Dashboard result={result} progress={progress} detectorTimings={mergedDetectorTimings} />
      <ScanGuidance result={result} targetUrl={targetUrl} />
      <section className="findings-section">
        <div className="section-header">
          <h2>Findings</h2>
          <span>{result?.summary?.finding_count ?? 0}</span>
        </div>
        <section className="findings-list">
          {(result?.findings ?? []).length ? (
            (result?.findings ?? []).map((finding, index) => (
              <VulnerabilityCard key={`${finding.url}-${index}`} finding={finding} />
            ))
          ) : (
            <article className="panel empty-state">
              <strong>No findings yet.</strong>
              <p>The improved scanner now still records pages, forms, and endpoints even when no detector fires.</p>
            </article>
          )}
        </section>
      </section>
      <DiscoveryPanel result={result} />
      <LogsViewer logs={logs} />
    </section>
  );
}
