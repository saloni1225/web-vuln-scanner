import React, { useEffect, useMemo, useState } from "react";
import { Dashboard } from "../components/Dashboard.jsx";
import { DiscoveryPanel } from "../components/DiscoveryPanel.jsx";
import { FindingDetailDrawer } from "../components/FindingDetailDrawer.jsx";
import { LogsViewer } from "../components/LogsViewer.jsx";
import { ScanGuidance } from "../components/ScanGuidance.jsx";
import { ScanPanel } from "../components/ScanPanel.jsx";
import { VulnerabilityCard } from "../components/VulnerabilityCard.jsx";
import { fetchActiveScans, fetchDetectors, fetchReportDetail, fetchScanProfiles, startScan } from "../services/api.js";
import { createScanSocket } from "../services/socket.js";

const EMPTY_LIVE_SUMMARY = {
  page_count: 0,
  form_count: 0,
  endpoint_count: 0,
  finding_count: 0,
  high_severity_count: 0,
  medium_severity_count: 0,
  low_severity_count: 0,
  validated_finding_count: 0,
  passive_security_score: 0,
  open_port_count: 0,
  high_risk_endpoint_count: 0,
  api_endpoint_count: 0,
  graphql_endpoint_count: 0,
  schema_fuzz_probe_count: 0,
  duration_ms: 0,
};

function getTargetHost(value) {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    return parsed.hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isPrivateTargetHost(host) {
  const normalized = host.toLowerCase();
  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized.startsWith("10.") ||
    normalized.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(normalized)
  );
}

function mergeProgressEvent(current, event) {
  let detectorFindingCounts = current.detectorFindingCounts ?? {};
  let summary = { ...EMPTY_LIVE_SUMMARY, ...(current.summary ?? {}) };

  if (event.event === "scan_started") {
    detectorFindingCounts = {};
    summary = { ...EMPTY_LIVE_SUMMARY };
  }

  if (event.event === "crawl_completed") {
    summary = {
      ...summary,
      page_count: event.page_count ?? summary.page_count,
      form_count: event.form_count ?? summary.form_count,
      endpoint_count: event.endpoint_count ?? summary.endpoint_count,
      api_endpoint_count: event.api_endpoint_count ?? summary.api_endpoint_count,
      graphql_endpoint_count: event.graphql_endpoint_count ?? summary.graphql_endpoint_count,
      schema_fuzz_probe_count: event.schema_fuzz_probe_count ?? summary.schema_fuzz_probe_count,
    };
  }

  if (event.event === "detector_completed" && event.detector) {
    detectorFindingCounts = {
      ...detectorFindingCounts,
      [event.detector]: event.finding_count ?? 0,
    };
    summary = {
      ...summary,
      finding_count: Object.values(detectorFindingCounts).reduce((total, count) => total + Number(count || 0), 0),
    };
  }

  if (event.summary) {
    summary = { ...summary, ...event.summary };
  }

  return {
    progress: event.progress ?? current.progress,
    status: event.status ?? current.status,
    message: event.message ?? current.message,
    summary,
    detectorFindingCounts,
  };
}

export function ScanPage() {
  const [targetUrl, setTargetUrl] = useState("");
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
  const [retryAttempts, setRetryAttempts] = useState("2");
  const [scanProfile, setScanProfile] = useState("deep");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(true);
  const [domainAllowlist, setDomainAllowlist] = useState("");
  const [failOnHigh, setFailOnHigh] = useState(true);
  const [maxHighSeverity, setMaxHighSeverity] = useState("0");
  const [maxMediumSeverity, setMaxMediumSeverity] = useState("");
  const [maxTotalFindings, setMaxTotalFindings] = useState("");
  const [slackWebhookUrl, setSlackWebhookUrl] = useState("");
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState("");
  const [availableDetectors, setAvailableDetectors] = useState([]);
  const [scanProfiles, setScanProfiles] = useState([]);
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [enableApiFuzzing, setEnableApiFuzzing] = useState(true);
  const [enableGraphqlChecks, setEnableGraphqlChecks] = useState(true);
  const [enableFindingValidator, setEnableFindingValidator] = useState(true);
  const [enableOpenapiDiscovery, setEnableOpenapiDiscovery] = useState(true);
  const [enableActivePostTesting, setEnableActivePostTesting] = useState(false);
  const [result, setResult] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeScans, setActiveScans] = useState([]);
  const [scanError, setScanError] = useState("");
  const [logs, setLogs] = useState([
    "Intelligence workflow ready.",
    "Enter a scoped asset and launch an exposure analysis.",
  ]);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState({ progress: 0, status: "idle", message: "Waiting for the next intelligence run." });
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
    fetchScanProfiles()
      .then(setScanProfiles)
      .catch(() => setScanProfiles([]));
  }, []);

  useEffect(() => {
    const socket = createScanSocket((event) => {
      refreshActiveScans();
      setProgress((current) => mergeProgressEvent(current, event));
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
        if (event.scan_id) {
          fetchReportDetail(event.scan_id)
            .then(setResult)
            .catch(() => {
              setLogs((current) => [...current, "Scan summary received, but the full report is still being finalized."]);
            });
        }
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
  const targetHost = useMemo(() => getTargetHost(targetUrl), [targetUrl]);
  const requiresAuthorization = Boolean(targetHost && !isPrivateTargetHost(targetHost));

  useEffect(() => {
    if (authorizationConfirmed && requiresAuthorization && targetHost && !domainAllowlist.trim()) {
      setDomainAllowlist(targetHost);
    }
  }, [authorizationConfirmed, domainAllowlist, requiresAuthorization, targetHost]);

  async function onScan(event) {
    event.preventDefault();
    const scopedAllowlist = domainAllowlist.split(",").map((item) => item.trim()).filter(Boolean);
    if (
      requiresAuthorization &&
      authorizationConfirmed &&
      targetHost &&
      !scopedAllowlist.some((item) => item.toLowerCase() === targetHost)
    ) {
      scopedAllowlist.push(targetHost);
    }

    setIsScanning(true);
    setResult(null);
    setScanError("");
    setProgress({
      progress: 3,
      status: "running",
      message: `Queued scan for ${targetUrl}`,
      summary: { ...EMPTY_LIVE_SUMMARY },
      detectorFindingCounts: {},
    });
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
        retryAttempts: Number(retryAttempts),
        scanProfile,
        authorizationConfirmed,
        domainAllowlist: scopedAllowlist,
        detectorNames: selectedDetectors,
        enableApiFuzzing,
        enableGraphqlChecks,
        enableFindingValidator,
        enableOpenapiDiscovery,
        enableUnsafeStateChangingFuzz: enableActivePostTesting,
        failOnHigh,
        maxHighSeverity: Number(maxHighSeverity || 0),
        maxMediumSeverity: maxMediumSeverity === "" ? null : Number(maxMediumSeverity),
        maxTotalFindings: maxTotalFindings === "" ? null : Number(maxTotalFindings),
        slackWebhookUrl,
        discordWebhookUrl,
      });
      setResult(scan);
      refreshActiveScans();
      setProgress({
        progress: 100,
        status: "completed",
        message: `Scan completed in ${scan.summary.duration_ms} ms`,
        summary: scan.summary,
        detectorFindingCounts: {},
      });
      setDetectorTimings(scan.detector_timings ?? []);
      setLogs((current) => [
        ...current,
        `Scan complete: ${scan.summary.finding_count} findings`,
        `Discovered ${scan.summary.page_count} pages, ${scan.summary.form_count} forms, and ${scan.summary.endpoint_count} endpoints`,
      ]);
    } catch (error) {
      const message = String(error.message || "Unknown scan error");
      setScanError(message);
      setProgress({ progress: 100, status: "failed", message });
      setLogs((current) => {
        if (message.toLowerCase().includes("target is unreachable")) {
          return [
            ...current,
            `Scan failed: ${message}`,
            "Check the target URL, VPN/network access, DNS, and whether the site allows requests from this machine.",
          ];
        }
        return [...current, `Scan failed: ${message}`];
      });
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <section className="workspace scanner-workspace hacker-surface">
      <section className="scan-hero">
        <div>
          <span className="eyebrow">Exposure Workflow</span>
          <h1>Intelligence launchpad</h1>
          <p>Run quick intelligence, deep exposure analysis, API intelligence, continuous monitoring, and attack surface discovery workflows.</p>
        </div>
        <div className="hero-status-cluster">
          <div>
            <span>Target</span>
            <strong>{targetUrl || "Not selected"}</strong>
          </div>
          <div>
            <span>Mode</span>
            <strong>{scanProfiles.find((profile) => profile.name === scanProfile)?.label ?? "Deep Scan"}</strong>
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
        retryAttempts={retryAttempts}
        setRetryAttempts={setRetryAttempts}
        scanProfile={scanProfile}
        setScanProfile={setScanProfile}
        scanProfiles={scanProfiles}
        authorizationConfirmed={authorizationConfirmed}
        setAuthorizationConfirmed={setAuthorizationConfirmed}
        domainAllowlist={domainAllowlist}
        setDomainAllowlist={setDomainAllowlist}
        failOnHigh={failOnHigh}
        setFailOnHigh={setFailOnHigh}
        maxHighSeverity={maxHighSeverity}
        setMaxHighSeverity={setMaxHighSeverity}
        maxMediumSeverity={maxMediumSeverity}
        setMaxMediumSeverity={setMaxMediumSeverity}
        maxTotalFindings={maxTotalFindings}
        setMaxTotalFindings={setMaxTotalFindings}
        slackWebhookUrl={slackWebhookUrl}
        setSlackWebhookUrl={setSlackWebhookUrl}
        discordWebhookUrl={discordWebhookUrl}
        setDiscordWebhookUrl={setDiscordWebhookUrl}
        availableDetectors={availableDetectors}
        selectedDetectors={selectedDetectors}
        setSelectedDetectors={setSelectedDetectors}
        enableApiFuzzing={enableApiFuzzing}
        setEnableApiFuzzing={setEnableApiFuzzing}
        enableGraphqlChecks={enableGraphqlChecks}
        setEnableGraphqlChecks={setEnableGraphqlChecks}
        enableFindingValidator={enableFindingValidator}
        setEnableFindingValidator={setEnableFindingValidator}
        enableOpenapiDiscovery={enableOpenapiDiscovery}
        setEnableOpenapiDiscovery={setEnableOpenapiDiscovery}
        enableActivePostTesting={enableActivePostTesting}
        setEnableActivePostTesting={setEnableActivePostTesting}
        isScanning={isScanning}
        onScan={onScan}
        progress={progress}
        targetHost={targetHost}
        requiresAuthorization={false}
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
              Check the target URL, network path, authorization scope, and any required authentication values before retrying.
            </small>
          </article>
        </section>
      ) : null}
      <section className="guidance-grid">
        <article className="panel scan-queue-panel">
          <header className="panel-header">
            <div>
              <strong>Scan Queue</strong>
            </div>
            <span>{activeScans.length}</span>
          </header>
          <div className="timing-list scan-queue-list">
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
          <h2>Findings workflow</h2>
          <span>{result?.summary?.finding_count ?? progress?.summary?.finding_count ?? 0}</span>
        </div>
        <section className="findings-list">
          {(result?.findings ?? []).length ? (
            (result?.findings ?? []).map((finding, index) => (
              <VulnerabilityCard
                key={`${finding.url}-${index}`}
                finding={{ ...finding, scan_id: result.scan_id, finding_index: index }}
                onOpenDetail={setSelectedFinding}
              />
            ))
          ) : (
            <article className="panel empty-state">
              <strong>No findings yet.</strong>
              <p>Findings, validation state, and replay evidence will appear here as detectors complete.</p>
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
