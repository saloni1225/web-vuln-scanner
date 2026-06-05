import React, { useState } from "react";
import { CalendarClock, ChevronDown, KeyRound, LoaderCircle, Play, ShieldCheck, SlidersHorizontal, Sparkles } from "lucide-react";

export function ScanPanel({
  targetUrl,
  setTargetUrl,
  jwtToken,
  setJwtToken,
  authHeaderName,
  setAuthHeaderName,
  authHeaderValue,
  setAuthHeaderValue,
  authCookieName,
  setAuthCookieName,
  authCookieValue,
  setAuthCookieValue,
  loginUrl,
  setLoginUrl,
  usernameField,
  setUsernameField,
  passwordField,
  setPasswordField,
  username,
  setUsername,
  password,
  setPassword,
  rateLimitPerSecond,
  setRateLimitPerSecond,
  retryAttempts,
  setRetryAttempts,
  scanProfile,
  setScanProfile,
  scanProfiles,
  authorizationConfirmed,
  setAuthorizationConfirmed,
  domainAllowlist,
  setDomainAllowlist,
  failOnHigh,
  setFailOnHigh,
  maxHighSeverity,
  setMaxHighSeverity,
  maxMediumSeverity,
  setMaxMediumSeverity,
  maxTotalFindings,
  setMaxTotalFindings,
  slackWebhookUrl,
  setSlackWebhookUrl,
  discordWebhookUrl,
  setDiscordWebhookUrl,
  availableDetectors,
  selectedDetectors,
  setSelectedDetectors,
  enableApiFuzzing,
  setEnableApiFuzzing,
  enableGraphqlChecks,
  setEnableGraphqlChecks,
  enableFindingValidator,
  setEnableFindingValidator,
  enableOpenapiDiscovery,
  setEnableOpenapiDiscovery,
  enableActivePostTesting,
  setEnableActivePostTesting,
  isScanning,
  onScan,
  progress,
  targetHost,
  requiresAuthorization,
}) {
  const [openPanel, setOpenPanel] = useState("");
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const profiles = scanProfiles?.length ? scanProfiles : [{ name: "deep", label: "Deep Scan" }];

  function toggleDetector(name) {
    setSelectedDetectors((current) =>
      current.includes(name) ? current.filter((item) => item !== name) : [...current, name]
    );
  }

  return (
    <form className="scan-command scan-command-center" onSubmit={onScan}>
      <div className="command-center-header">
        <div>
          <span className="eyebrow">Operational workflow</span>
          <strong>Exposure intelligence run</strong>
        </div>
        <div className="command-ai-chip"><Sparkles size={14} /> Scope-aware defaults</div>
      </div>
      <section className="scan-command-main">
        <div className="scan-target-input">
          <label htmlFor="target-url">Target</label>
          <input
            id="target-url"
            type="url"
            value={targetUrl}
            placeholder="https://app.example.com"
            onChange={(event) => setTargetUrl(event.target.value)}
            required
          />
        </div>
        <button className="primary-action scan-start" type="submit" disabled={isScanning}>
          {isScanning ? <LoaderCircle className="spin" size={18} /> : <Play size={18} />}
          {isScanning ? "Running" : "Launch"}
        </button>
      </section>

      <section className="scan-type-row" aria-label="Scan type">
        {profiles.map((profile) => (
          <button
            key={profile.name}
            type="button"
            className={scanProfile === profile.name ? "selected" : ""}
            onClick={() => setScanProfile(profile.name)}
          >
            <strong>{profile.label}</strong>
            <span>{profile.name} profile</span>
          </button>
        ))}
        <button type="button" className="schedule-button" onClick={() => setScheduleOpen(true)}>
          <CalendarClock size={16} /> Continuous
        </button>
      </section>

      <section className="scope-strip command-scope-strip">
        <div className="scope-chip ok"><ShieldCheck size={15} /> Scope controls enforced</div>
        <div className="scope-chip ok">{targetHost || "No target"} · monitored asset</div>
        <input
          className="scope-allowlist"
          value={domainAllowlist}
          onChange={(event) => setDomainAllowlist(event.target.value)}
          placeholder="Asset scope"
        />
      </section>

      <section className="progress-rail">
        <div><span style={{ width: `${progress?.progress ?? 0}%` }} /></div>
        <small>{progress?.message ?? "Ready"}</small>
      </section>

      <section className="scan-accordion">
        <button type="button" className="accordion-trigger" onClick={() => setOpenPanel(openPanel === "auth" ? "" : "auth")}>
          <KeyRound size={16} /> Identity context <ChevronDown size={15} />
        </button>
        {openPanel === "auth" ? (
          <div className="accordion-body auth-fields">
            <input value={authHeaderName} placeholder="Header name" onChange={(event) => setAuthHeaderName(event.target.value)} />
            <input value={authHeaderValue} placeholder="Header value" onChange={(event) => setAuthHeaderValue(event.target.value)} />
            <input value={jwtToken} placeholder="JWT token" onChange={(event) => setJwtToken(event.target.value)} />
            <input value={authCookieName} placeholder="Cookie name" onChange={(event) => setAuthCookieName(event.target.value)} />
            <input value={authCookieValue} placeholder="Cookie value" onChange={(event) => setAuthCookieValue(event.target.value)} />
            <input type="url" value={loginUrl} placeholder="Login URL" onChange={(event) => setLoginUrl(event.target.value)} />
            <input value={usernameField} placeholder="Username field" onChange={(event) => setUsernameField(event.target.value)} />
            <input value={passwordField} placeholder="Password field" onChange={(event) => setPasswordField(event.target.value)} />
            <input value={username} placeholder="Username" onChange={(event) => setUsername(event.target.value)} />
            <input type="password" value={password} placeholder="Password" onChange={(event) => setPassword(event.target.value)} />
          </div>
        ) : null}

        <button type="button" className="accordion-trigger" onClick={() => setOpenPanel(openPanel === "advanced" ? "" : "advanced")}>
          <SlidersHorizontal size={16} /> Advanced intelligence drawer <ChevronDown size={15} />
        </button>
        {openPanel === "advanced" ? (
          <div className="accordion-body">
            <div className="compact-fields">
              <input type="number" min="0.5" max="20" step="0.5" value={rateLimitPerSecond} onChange={(event) => setRateLimitPerSecond(event.target.value)} placeholder="Rate/sec" />
              <input type="number" min="0" max="5" value={retryAttempts} onChange={(event) => setRetryAttempts(event.target.value)} placeholder="Retries" />
              <input type="number" min="0" value={maxHighSeverity} onChange={(event) => setMaxHighSeverity(event.target.value)} placeholder="Max high" />
              <input type="number" min="0" value={maxMediumSeverity} onChange={(event) => setMaxMediumSeverity(event.target.value)} placeholder="Max medium" />
              <input type="number" min="0" value={maxTotalFindings} onChange={(event) => setMaxTotalFindings(event.target.value)} placeholder="Max total" />
              <input type="url" value={slackWebhookUrl} onChange={(event) => setSlackWebhookUrl(event.target.value)} placeholder="Slack webhook" />
              <input type="url" value={discordWebhookUrl} onChange={(event) => setDiscordWebhookUrl(event.target.value)} placeholder="Discord webhook" />
            </div>
            <div className="toggle-grid">
              {[
                ["Risk gate", failOnHigh, setFailOnHigh],
                ["API fuzzing", enableApiFuzzing, setEnableApiFuzzing],
                ["GraphQL", enableGraphqlChecks, setEnableGraphqlChecks],
                ["Validation", enableFindingValidator, setEnableFindingValidator],
                ["OpenAPI", enableOpenapiDiscovery, setEnableOpenapiDiscovery],
                ["Active POST", enableActivePostTesting, setEnableActivePostTesting],
              ].map(([label, value, setter]) => (
                <label key={label} className="switch-row compact">
                  <input type="checkbox" checked={value} onChange={(event) => setter(event.target.checked)} />
                  <span>{label}</span>
                </label>
              ))}
            </div>
            <div className="detector-pills compact-detectors">
              {availableDetectors.map((detector) => (
                <button
                  key={detector.name}
                  type="button"
                  className={selectedDetectors.includes(detector.name) ? "active" : ""}
                  onClick={() => toggleDetector(detector.name)}
                >
                  {detector.name}
                </button>
              ))}
            </div>
          </div>
        ) : null}
      </section>

      {scheduleOpen ? (
        <div className="modal-backdrop" onClick={() => setScheduleOpen(false)}>
          <section className="schedule-modal" onClick={(event) => event.stopPropagation()}>
            <header>
            <strong>Continuous monitoring</strong>
              <button type="button" onClick={() => setScheduleOpen(false)}>Close</button>
            </header>
            <div className="compact-fields">
              <select defaultValue="daily"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select>
              <input type="time" defaultValue="02:00" />
              <input placeholder="Notification channel" />
            </div>
            <p>Recurring monitoring is prepared for the operations queue. The current local run remains on-demand.</p>
          </section>
        </div>
      ) : null}
    </form>
  );
}
