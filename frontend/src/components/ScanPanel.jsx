import React from "react";
import { LoaderCircle, Play } from "lucide-react";

export function ScanPanel({ targetUrl, setTargetUrl, isScanning, onScan, progress }) {
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
      <div className="inline-progress">
        <div className="inline-progress-track">
          <div className="inline-progress-fill" style={{ width: `${progress?.progress ?? 0}%` }} />
        </div>
        <small>{progress?.message ?? "Waiting for the next scan run."}</small>
      </div>
    </form>
  );
}
