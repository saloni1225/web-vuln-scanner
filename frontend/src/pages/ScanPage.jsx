import React, { useEffect, useMemo, useState } from "react";
import { Dashboard } from "../components/Dashboard.jsx";
import { DiscoveryPanel } from "../components/DiscoveryPanel.jsx";
import { FindingDetailDrawer } from "../components/FindingDetailDrawer.jsx";
import { LogsViewer } from "../components/LogsViewer.jsx";
import { ScanGuidance } from "../components/ScanGuidance.jsx";
import { ScanPanel } from "../components/ScanPanel.jsx";
import { VulnerabilityCard } from "../components/VulnerabilityCard.jsx";
import { fetchActiveScans, fetchDetectors, startScan } from "../services/api.js";
import { createScanSocket } from "../services/socket.js";

export function ScanPage() {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:3000");
  const [jwtToken, setJwtToken] = useState("");
  const [authHeaderName, setAuthHeaderName] = useState("Authorization");
  const [authHeaderValue, setAuthHeaderValue] = useState("");
  const [authCookieName, setAuthCookieName] = useState("");
  const [authCookieValue, setAuthCookieValue] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [usernameField, setUsernameField] = useState("email");
  const [passwordField, setPasswordField] = useState("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [rateLimitPerSecond, setRateLimitPerSecond] = useState("3");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [domainAllowlist, setDomainAllowlist] = useState("");
  const [availableDetectors, setAvailableDetectors] = useState([]);
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [enableApiFuzzing, setEnableApiFuzzing] = useState(true);
  const [enableGraphqlChecks, setEnableGraphqlChecks] = useState(true);
  const [result, setResult] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeScans, setActiveScans] = useState([]);
  const [scanError, setScanError] = useState("");
  const [logs, setLogs] = useState([
    "Scanner ready.",
    "Tip: launch OWASP Juice Shop locally on http://127.0.0.1:3000 for a safer demo target.",
  ]);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState({ progress: 0, status: "idle", message: "Waiting for the next scan run." });
  const [detectorTimings, setDetectorTimings] = useState([]);

  useEffect(() => {
    fetchDetectors()
      .then((detectors) => {
        setAvailableDetectors(detectors);
        setSelectedDetectors(detectors.filter((item) => item.enabled !== false).map((item) => item.name));
      })
      .catch(() => {
        setAvailableDetectors([]);
        setSelectedDetectors([]);
      });
  }, []);

  useEffect(() => {
    const socket = createScanSocket((event) => {
      refreshActiveScans();
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

  async function refreshActiveScans() {
    try {
      setActiveScans(await fetchActiveScans());
    } catch {
      setActiveScans([]);
    }
  }

  useEffect(() => {
    refreshActiveScans();
    const timer = setInterval(refreshActiveScans, 4000);
    return () => clearInterval(timer);
  }, []);

  const mergedDetectorTimings = useMemo(
    () => (detectorTimings.length ? detectorTimings : result?.detector_timings ?? []),
    [detectorTimings, result]
  );

  async function onScan(event) {
    event.preventDefault();
    setIsScanning(true);
    setScanError("");
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
      const scan = await startScan(targetUrl, {
        headers: authHeaders,
        cookies: authCookies,
        jwtToken,
        loginUrl,
        usernameField,
        passwordField,
        username,
        password,
        rateLimitPerSecond: Number(rateLimitPerSecond),
        authorizationConfirmed,
        domainAllowlist: domainAllowlist.split(",").map((item) => item.trim()).filter(Boolean),
        detectorNames: selectedDetectors,
        enableApiFuzzing,
        enableGraphqlChecks,
      });
      setResult(scan);
      refreshActiveScans();
      setProgress({ progress: 100, status: "completed", message: `Scan completed in ${scan.summary.duration_ms} ms` });
      setDetectorTimings(scan.detector_timings ?? []);
      setLogs((current) => [
        ...current,
        `Scan complete: ${scan.summary.finding_count} findings`,
        `Discovered ${scan.summary.page_count} pages, ${scan.summary.form_count} forms, and ${scan.summary.endpoint_count} endpoints`,
      ]);
    } catch (error) {
      const message = String(error.message || "Unknown scan error");
      setScanError(message);
      setProgress({ progress: 100, status: "failed", message: "Scan failed before crawl could complete." });
      setLogs((current) => {
        if (message.toLowerCase().includes("target is unreachable")) {
          return [
            ...current,
            `Scan failed: ${message}`,
            "Target seems offline. Start Juice Shop first: docker compose -f docker/docker-compose.yml up -d juice-shop",
          ];
        }
        return [...current, `Scan failed: ${message}`];
      });
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
        jwtToken={jwtToken}
        setJwtToken={setJwtToken}
        authHeaderName={authHeaderName}
        setAuthHeaderName={setAuthHeaderName}
        authHeaderValue={authHeaderValue}
        setAuthHeaderValue={setAuthHeaderValue}
        authCookieName={authCookieName}
        setAuthCookieName={setAuthCookieName}
        authCookieValue={authCookieValue}
        setAuthCookieValue={setAuthCookieValue}
        loginUrl={loginUrl}
        setLoginUrl={setLoginUrl}
        usernameField={usernameField}
        setUsernameField={setUsernameField}
        passwordField={passwordField}
        setPasswordField={setPasswordField}
        username={username}
        setUsername={setUsername}
        password={password}
        setPassword={setPassword}
        rateLimitPerSecond={rateLimitPerSecond}
        setRateLimitPerSecond={setRateLimitPerSecond}
        authorizationConfirmed={authorizationConfirmed}
        setAuthorizationConfirmed={setAuthorizationConfirmed}
        domainAllowlist={domainAllowlist}
        setDomainAllowlist={setDomainAllowlist}
        availableDetectors={availableDetectors}
        selectedDetectors={selectedDetectors}
        setSelectedDetectors={setSelectedDetectors}
        enableApiFuzzing={enableApiFuzzing}
        setEnableApiFuzzing={setEnableApiFuzzing}
        enableGraphqlChecks={enableGraphqlChecks}
        setEnableGraphqlChecks={setEnableGraphqlChecks}
        isScanning={isScanning}
        onScan={onScan}
        progress={progress}
      />
      <Dashboard result={result} progress={progress} detectorTimings={mergedDetectorTimings} />
      {scanError ? (
        <section className="guidance-grid">
          <article className="panel error-panel">
            <header className="panel-header">
              <div>
                <strong>Scan Error</strong>
              </div>
              <span>Needs attention</span>
            </header>
            <p>{scanError}</p>
            <small>
              For `http://127.0.0.1:3000`, start Docker Desktop first, then bring up Juice Shop and retry.
            </small>
          </article>
        </section>
      ) : null}
      <section className="guidance-grid">
        <article className="panel">
          <header className="panel-header">
            <div>
              <strong>Scan Queue</strong>
            </div>
            <span>{activeScans.length}</span>
          </header>
          <div className="timing-list">
            {activeScans.length ? (
              activeScans.map((job) => (
                <div key={job.scan_id} className="timing-row">
                  <div>
                    <strong>{job.target_url}</strong>
                    <small>{job.status} · {job.message}</small>
                  </div>
                  <span>{job.progress}%</span>
                </div>
              ))
            ) : (
              <div className="empty-panel">No queued or recent scans yet.</div>
            )}
          </div>
        </article>
      </section>
      <ScanGuidance result={result} targetUrl={targetUrl} />
      <section className="findings-section">
        <div className="section-header">
          <h2>Findings</h2>
          <span>{result?.summary?.finding_count ?? 0}</span>
        </div>
        <section className="findings-list">
          {(result?.findings ?? []).length ? (
            (result?.findings ?? []).map((finding, index) => (
              <VulnerabilityCard key={`${finding.url}-${index}`} finding={finding} onOpenDetail={setSelectedFinding} />
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
      <FindingDetailDrawer finding={selectedFinding} open={Boolean(selectedFinding)} onClose={() => setSelectedFinding(null)} />
    </section>
  );
}
