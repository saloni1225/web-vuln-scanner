import React from "react";
import { LoaderCircle, Play } from "lucide-react";

export function ScanPanel({
  targetUrl,
  setTargetUrl,
  authHeaderName,
  setAuthHeaderName,
  authHeaderValue,
  setAuthHeaderValue,
  authCookieName,
  setAuthCookieName,
  authCookieValue,
  setAuthCookieValue,
  isScanning,
  onScan,
  progress,
}) {
  return (
    <form className="scan-panel" onSubmit={onScan}>
      <label htmlFor="target-url">Target URL</label>
      <div className="target-row">
        <input
          id="target-url"
          type="url"
          value={targetUrl}
          placeholder="https://example.com"
          onChange={(event) => setTargetUrl(event.target.value)}
          required
        />
        <button type="submit" disabled={isScanning}>
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
      <div className="inline-progress">
        <div className="inline-progress-track">
          <div className="inline-progress-fill" style={{ width: `${progress?.progress ?? 0}%` }} />
        </div>
        <small>{progress?.message ?? "Waiting for the next scan run."}</small>
      </div>
    </form>
  );
}
