import React from "react";
import {
  ArrowRight,
  Bell,
  CalendarClock,
  FileCheck2,
  Gauge,
  Globe2,
  Network,
  PlugZap,
  ShieldCheck,
  Sparkles,
  Wrench,
} from "lucide-react";

const capabilityCards = [
  {
    icon: Globe2,
    title: "External Web Scans",
    text: "Run authorized scans against hosted websites, staging apps, APIs, and public-facing services.",
  },
  {
    icon: Network,
    title: "Attack Surface Mapping",
    text: "Discover pages, routes, API endpoints, GraphQL surfaces, technologies, headers, ports, and risky paths.",
  },
  {
    icon: FileCheck2,
    title: "Audit-Ready Reports",
    text: "Generate HTML and PDF reports with CVSS, CWE, evidence, payloads, replay plans, and remediation guidance.",
  },
  {
    icon: PlugZap,
    title: "Scanner Modules",
    text: "Enable SQL injection, XSS, CSRF, authorization, recon, schema-aware API probing, and custom detectors.",
  },
  {
    icon: CalendarClock,
    title: "Automation Ready",
    text: "Use scan profiles, CLI runs, CI pipelines, and saved reports to repeat checks without manual setup.",
  },
  {
    icon: Wrench,
    title: "Remediation Workflow",
    text: "Prioritize findings, inspect request and response evidence, replay context, and track before-and-after scans.",
  },
];

const healthItems = [
  ["Coverage", "Web, API, GraphQL, recon"],
  ["Reports", "HTML, PDF, comparisons"],
  ["Controls", "Allowlist, rate limit, profiles"],
  ["Evidence", "Payloads, snapshots, replay"],
];

export function Home({ onStart }) {
  return (
    <section className="home-band platform-home">
      <div className="home-copy platform-hero">
        <p className="eyebrow">Hosted web vulnerability scanning</p>
        <h1>Continuous security checks for the websites you own.</h1>
        <p>
          Manage authorized targets, map attack surface, run web and API scans, and turn findings into reports your team can act on.
        </p>
        <div className="hero-actions">
          <button onClick={onStart}>
            <ArrowRight size={18} />
            <span>New scan</span>
          </button>
        </div>
      </div>

      <section className="platform-console" aria-label="Platform overview">
        <div className="console-header">
          <div>
            <span>Target health</span>
            <strong>Ready for scope</strong>
          </div>
          <Gauge size={22} />
        </div>
        <div className="health-score">
          <strong>92</strong>
          <span>service score</span>
        </div>
        <div className="console-grid">
          {healthItems.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
        <div className="console-alert">
          <Bell size={18} />
          <span>Run repeat scans from CI and compare remediation progress.</span>
        </div>
      </section>

      <section className="platform-strip">
        <article>
          <ShieldCheck size={18} />
          <strong>Authorized by design</strong>
          <span>External targets require explicit scope confirmation and optional domain allowlists.</span>
        </article>
        <article>
          <Sparkles size={18} />
          <strong>Built for teams</strong>
          <span>Use scan history, report comparisons, and detector controls to support repeatable reviews.</span>
        </article>
      </section>

      <section className="capability-grid">
        {capabilityCards.map(({ icon: Icon, title, text }) => (
          <article key={title} className="capability-card">
            <Icon size={20} />
            <strong>{title}</strong>
            <span>{text}</span>
          </article>
        ))}
      </section>
    </section>
  );
}
