import React from "react";
import { Boxes, Cloud, Network, Route } from "lucide-react";
import { Card, CardHeader, DataTable, StatusPill } from "./ui.jsx";

export function DiscoveryPanel({ result }) {
  const endpoints = result?.endpoints ?? [];
  const endpointRisk = result?.recon_summary?.endpoint_risk_ranking ?? [];
  const subdomains = result?.recon_summary?.subdomain_summary?.resolved ?? [];
  const cloudAssets = result?.recon_summary?.cloud_asset_summary ?? {};
  const exposedCloud = cloudAssets.exposed ?? [];
  const tech = result?.recon_summary?.technology_fingerprint?.technologies ?? [];

  return (
    <section className="enterprise-grid">
      <Card className="wide-card">
        <CardHeader icon={Route} title="Endpoint inventory" meta={`${endpoints.length} endpoints`} />
        <DataTable
          rows={endpoints.map((endpoint) => ({
            url: endpoint.url,
            method: String(endpoint.method ?? "GET").toUpperCase(),
            type: endpoint.type,
            source: endpoint.source,
            params: (endpoint.query_params ?? endpoint.schema_fields ?? []).join(", "),
          }))}
          columns={[
            { key: "url", label: "Endpoint" },
            { key: "method", label: "Method" },
            { key: "type", label: "Type", render: (row) => <StatusPill>{row.type}</StatusPill> },
            { key: "source", label: "Source" },
            { key: "params", label: "Parameters" },
          ]}
          empty="No endpoint inventory yet"
        />
      </Card>

      <Card>
        <CardHeader icon={Network} title="Risk ranking" meta={`${endpointRisk.length} ranked`} />
        <DataTable
          rows={endpointRisk.slice(0, 20).map((item) => ({
            url: item.url,
            risk: item.risk_score,
            method: item.method,
            reasons: (item.reasons ?? []).join(", "),
          }))}
          columns={[
            { key: "url", label: "Endpoint" },
            { key: "risk", label: "Risk" },
            { key: "method", label: "Method" },
            { key: "reasons", label: "Signal" },
          ]}
          empty="Risk ranking appears after recon"
        />
      </Card>

      <Card>
        <CardHeader icon={Boxes} title="Technology inventory" meta={`${tech.length} detected`} />
        <div className="tag-cloud">
          {tech.length ? tech.map((item) => <span key={`${item.technology}-${item.evidence}`}>{item.technology}</span>) : <small>No technology fingerprint yet.</small>}
        </div>
      </Card>

      <Card>
        <CardHeader icon={Cloud} title="Internet exposure" meta={`${exposedCloud.length} exposed`} />
        <DataTable
          rows={[
            ...subdomains.map((item) => ({ asset: item.host, type: "Subdomain", signal: (item.addresses ?? []).join(", ") })),
            ...exposedCloud.map((item) => ({ asset: item.url, type: item.provider, signal: `HTTP ${item.status_code}` })),
          ]}
          columns={[
            { key: "asset", label: "Asset" },
            { key: "type", label: "Type" },
            { key: "signal", label: "Signal" },
          ]}
          empty="No additional exposure detected"
        />
      </Card>
    </section>
  );
}
