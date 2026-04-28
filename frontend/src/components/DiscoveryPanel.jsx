import React from "react";
import { ExternalLink, FileInput, Link2 } from "lucide-react";

export function DiscoveryPanel({ result }) {
  const pages = result?.page_details ?? [];
  const forms = result?.forms ?? [];
  const endpoints = result?.endpoints ?? [];
  const apiSummary = result?.api_summary ?? {};
  const endpointRisk = result?.recon_summary?.endpoint_risk_ranking ?? [];
  const directoryFuzzing = result?.recon_summary?.directory_fuzzing ?? [];
  const subdomains = result?.recon_summary?.subdomain_summary?.resolved ?? [];
  const passive = result?.recon_summary?.passive_security ?? {};

  return (
    <section className="discovery-grid">
      <section className="panel">
        <header className="panel-header">
          <div>
            <Link2 size={18} />
            <strong>Discovered Pages</strong>
          </div>
          <span>{pages.length}</span>
        </header>
        <div className="panel-list">
          {pages.length ? (
            pages.map((page) => (
              <article key={page.url} className="panel-row">
                <div>
                  <strong>{page.url}</strong>
                  <small>Depth {page.depth} · HTTP {page.status_code}</small>
                </div>
                <small>{(page.query_params ?? []).join(", ") || "No query params"}</small>
              </article>
            ))
          ) : (
            <div className="empty-panel">No pages crawled yet.</div>
          )}
        </div>
      </section>

      <section className="panel">
        <header className="panel-header">
          <div>
            <FileInput size={18} />
            <strong>Forms</strong>
          </div>
          <span>{forms.length}</span>
        </header>
        <div className="panel-list">
          {forms.length ? (
            forms.map((form, index) => (
              <article key={`${form.action}-${index}`} className="panel-row">
                <div>
                  <strong>{form.action}</strong>
                  <small>{String(form.method).toUpperCase()} · source {form.page}</small>
                </div>
                <small>{(form.inputs ?? []).join(", ") || "No named inputs"}</small>
              </article>
            ))
          ) : (
            <div className="empty-panel">No forms found on the crawled pages.</div>
          )}
        </div>
      </section>

      <section className="panel">
        <header className="panel-header">
          <div>
            <ExternalLink size={18} />
            <strong>Endpoints</strong>
          </div>
          <span>{endpoints.length}</span>
        </header>
        <div className="discovery-summary-strip">
          <small>API {apiSummary.api_endpoint_count ?? 0}</small>
          <small>GraphQL {apiSummary.graphql_endpoint_count ?? 0}</small>
          <small>Parameterized {apiSummary.parameterized_endpoint_count ?? 0}</small>
        </div>
        <div className="panel-list">
          {endpoints.length ? (
            endpoints.map((endpoint, index) => (
              <article key={`${endpoint.type}-${endpoint.url}-${index}`} className="panel-row">
                <div>
                  <strong>{endpoint.url}</strong>
                  <small>{String(endpoint.method).toUpperCase()} · {endpoint.type} · {endpoint.source}</small>
                </div>
                <small>
                  {(endpoint.query_params ?? endpoint.inputs ?? []).join(", ") || "No parameters discovered"}
                </small>
              </article>
            ))
          ) : (
            <div className="empty-panel">No endpoints recorded yet.</div>
          )}
        </div>
      </section>

      <section className="panel">
        <header className="panel-header">
          <div>
            <ExternalLink size={18} />
            <strong>Endpoint Risk</strong>
          </div>
          <span>{endpointRisk.length}</span>
        </header>
        <div className="panel-list">
          {endpointRisk.length ? (
            endpointRisk.slice(0, 10).map((endpoint, index) => (
              <article key={`${endpoint.url}-${index}`} className="panel-row risk-row">
                <div>
                  <strong>{endpoint.url}</strong>
                  <small>{endpoint.method} · {endpoint.source}</small>
                </div>
                <small>{endpoint.risk_score}% · {(endpoint.reasons ?? []).join(", ")}</small>
              </article>
            ))
          ) : (
            <div className="empty-panel">Endpoint risk ranking appears after recon completes.</div>
          )}
        </div>
      </section>

      <section className="panel">
        <header className="panel-header">
          <div>
            <Link2 size={18} />
            <strong>Hidden Surface</strong>
          </div>
          <span>{directoryFuzzing.length + subdomains.length}</span>
        </header>
        <div className="discovery-summary-strip">
          <small>Dirs {directoryFuzzing.length}</small>
          <small>Subdomains {subdomains.length}</small>
          <small>Headers {passive.missing_headers?.length ?? 0} missing</small>
        </div>
        <div className="panel-list">
          {directoryFuzzing.length || subdomains.length ? (
            [...directoryFuzzing.map((item) => ({ label: item.url, meta: `HTTP ${item.status_code} · ${item.path}` })),
             ...subdomains.map((item) => ({ label: item.host, meta: (item.addresses ?? []).join(", ") }))].map((item, index) => (
              <article key={`${item.label}-${index}`} className="panel-row">
                <div>
                  <strong>{item.label}</strong>
                  <small>{item.meta}</small>
                </div>
              </article>
            ))
          ) : (
            <div className="empty-panel">No hidden endpoints or subdomains resolved yet.</div>
          )}
        </div>
      </section>
    </section>
  );
}
