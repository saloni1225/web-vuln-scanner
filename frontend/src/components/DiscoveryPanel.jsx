import React from "react";
import { ExternalLink, FileInput, Link2 } from "lucide-react";

export function DiscoveryPanel({ result }) {
  const pages = result?.page_details ?? [];
  const forms = result?.forms ?? [];
  const endpoints = result?.endpoints ?? [];

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
        <div className="panel-list">
          {endpoints.length ? (
            endpoints.map((endpoint, index) => (
              <article key={`${endpoint.type}-${endpoint.url}-${index}`} className="panel-row">
                <div>
                  <strong>{endpoint.url}</strong>
                  <small>{String(endpoint.method).toUpperCase()} · {endpoint.type}</small>
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
    </section>
  );
}
