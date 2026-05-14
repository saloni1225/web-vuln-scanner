import React from "react";
import { LoaderCircle, Play } from "lucide-react";

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
  function toggleDetector(name) {
    setSelectedDetectors((current) =>
      current.includes(name) ? current.filter((item) => item !== name) : [...current, name]
    );
  }

  return (
    <form className="scan-panel" onSubmit={onScan}>
      <label htmlFor="target-url">Target URL</label>
      <div className="target-row">
        <input
          id="target-url"
          type="url"
          value={targetUrl}
          placeholder="https://staging.example.com"
          onChange={(event) => setTargetUrl(event.target.value)}
          required
        />
        <button type="submit" disabled={isScanning || (requiresAuthorization && !authorizationConfirmed)}>
          {isScanning ? <LoaderCircle className="spin" size={18} /> : <Play size={18} />}
          <span>{isScanning ? "Scanning" : "Start"}</span>
        </button>
      </div>
      <label htmlFor="auth-header-name">Auth Header (optional)</label>
      <div className="target-row">
        <input
          id="auth-header-name"
          type="text"
          value={authHeaderName}
          placeholder="Authorization"
          onChange={(event) => setAuthHeaderName(event.target.value)}
        />
        <input
          id="auth-header-value"
          type="text"
          value={authHeaderValue}
          placeholder="Bearer eyJ..."
          onChange={(event) => setAuthHeaderValue(event.target.value)}
        />
      </div>
      <label htmlFor="jwt-token">JWT Token (optional)</label>
      <input
        id="jwt-token"
        type="text"
        value={jwtToken}
        placeholder="eyJhbGciOi..."
        onChange={(event) => setJwtToken(event.target.value)}
      />
      <label htmlFor="auth-cookie-name">Session Cookie (optional)</label>
      <div className="target-row">
        <input
          id="auth-cookie-name"
          type="text"
          value={authCookieName}
          placeholder="token"
          onChange={(event) => setAuthCookieName(event.target.value)}
        />
        <input
          id="auth-cookie-value"
          type="text"
          value={authCookieValue}
          placeholder="session-value"
          onChange={(event) => setAuthCookieValue(event.target.value)}
        />
      </div>
      <label htmlFor="login-url">Login Flow (optional)</label>
      <div className="auth-grid">
        <input
          id="login-url"
          type="url"
          value={loginUrl}
          placeholder="https://target.example/login"
          onChange={(event) => setLoginUrl(event.target.value)}
        />
        <input
          type="text"
          value={usernameField}
          placeholder="username field"
          onChange={(event) => setUsernameField(event.target.value)}
        />
        <input
          type="text"
          value={passwordField}
          placeholder="password field"
          onChange={(event) => setPasswordField(event.target.value)}
        />
        <input
          type="text"
          value={username}
          placeholder="username"
          onChange={(event) => setUsername(event.target.value)}
        />
        <input
          type="password"
          value={password}
          placeholder="password"
          onChange={(event) => setPassword(event.target.value)}
        />
      </div>
      <label htmlFor="scan-profile">Scan Profile</label>
      <div className="target-row profile-row">
        <select id="scan-profile" value={scanProfile} onChange={(event) => setScanProfile(event.target.value)}>
          {(scanProfiles?.length ? scanProfiles : [{ name: "deep", label: "Deep Scan", description: "Broad discovery and validation." }]).map((profile) => (
            <option key={profile.name} value={profile.name}>
              {profile.label}
            </option>
          ))}
        </select>
        <div className="profile-description">
          {scanProfiles?.find((profile) => profile.name === scanProfile)?.description ?? "Balanced authorized assessment with SPA crawling, API probes, validation, and recon."}
        </div>
      </div>
      <label htmlFor="rate-limit">Safety Controls</label>
      <div className="target-row safety-row">
        <input
          id="rate-limit"
          type="number"
          min="0.5"
          max="20"
          step="0.5"
          value={rateLimitPerSecond}
          placeholder="Rate limit / second"
          onChange={(event) => setRateLimitPerSecond(event.target.value)}
        />
        <input
          type="number"
          min="0"
          max="5"
          step="1"
          value={retryAttempts}
          placeholder="Retry attempts"
          onChange={(event) => setRetryAttempts(event.target.value)}
        />
        <input
          type="text"
          value={domainAllowlist}
          placeholder="Allowed domains, e.g. staging.example.com, app.example.com"
          onChange={(event) => setDomainAllowlist(event.target.value)}
        />
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={authorizationConfirmed}
          onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
        />
        <span>I confirm this target is in scope and I have explicit authorization to test it.</span>
      </label>
      {targetHost ? (
        <div className={`scope-notice ${requiresAuthorization ? (authorizationConfirmed ? "confirmed" : "warning") : "private"}`}>
          <strong>{requiresAuthorization ? "Hosted target scope" : "Private target scope"}</strong>
          <span>
            {requiresAuthorization
              ? authorizationConfirmed
                ? `${targetHost} is confirmed in scope and will be sent with the scan allowlist.`
                : `${targetHost} needs authorization confirmation before scanning.`
              : `${targetHost} is a private/local target, so the hosted-target confirmation gate is not required.`}
          </span>
        </div>
      ) : null}
      <div className="options-grid">
        <div>
          <label>Detector Plugins</label>
          <div className="detector-chip-grid">
            {availableDetectors.length ? (
              availableDetectors.map((detector) => {
                const active = selectedDetectors.includes(detector.name);
                return (
                  <button
                    key={detector.name}
                    type="button"
                    className={`detector-chip ${active ? "active" : ""}`}
                    onClick={() => toggleDetector(detector.name)}
                  >
                    <strong>{detector.name}</strong>
                    <small>{detector.category}</small>
                  </button>
                );
              })
            ) : (
              <div className="empty-inline">Loading detectors...</div>
            )}
          </div>
        </div>
        <div>
          <label>API / GraphQL Coverage</label>
          <div className="toggle-stack">
            <label className="checkbox-row">
              <input type="checkbox" checked={enableApiFuzzing} onChange={(event) => setEnableApiFuzzing(event.target.checked)} />
              <span>Enable API probe coverage</span>
            </label>
            <label className="checkbox-row">
              <input type="checkbox" checked={enableGraphqlChecks} onChange={(event) => setEnableGraphqlChecks(event.target.checked)} />
              <span>Enable GraphQL checks</span>
            </label>
            <label className="checkbox-row">
              <input type="checkbox" checked={enableFindingValidator} onChange={(event) => setEnableFindingValidator(event.target.checked)} />
              <span>Enable finding validation</span>
            </label>
            <label className="checkbox-row">
              <input type="checkbox" checked={enableOpenapiDiscovery} onChange={(event) => setEnableOpenapiDiscovery(event.target.checked)} />
              <span>Enable OpenAPI discovery</span>
            </label>
            <label className="checkbox-row bounty-toggle">
              <input type="checkbox" checked={enableActivePostTesting} onChange={(event) => setEnableActivePostTesting(event.target.checked)} />
              <span>Active POST testing for confirmed in-scope targets</span>
            </label>
          </div>
        </div>
      </div>
      <div className="inline-progress">
        <div className="inline-progress-track">
          <div className="inline-progress-fill" style={{ width: `${progress?.progress ?? 0}%` }} />
        </div>
        <small>{progress?.message ?? "Waiting for the next scan run."}</small>
      </div>
    </form>
  );
}
