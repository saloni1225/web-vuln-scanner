import React from "react";
import { ArrowRight, FileSearch, FlaskConical, ShieldAlert } from "lucide-react";

export function Home({ onStart }) {
  return (
    <section className="home-band">
      <div className="home-copy">
        <p className="eyebrow">Adaptive Web Vulnerability Scanner</p>
        <h1>Dark-mode offensive surface console for local security labs.</h1>
        <p>
          Crawl a target, map forms and routes, inspect attack surface coverage, and review evidence-backed findings in a tighter
          operator workflow.
        </p>
        <div className="hero-actions">
          <button onClick={onStart}>
            <ArrowRight size={18} />
            <span>Open scanner</span>
          </button>
        </div>
      </div>
      <section className="home-stats">
        <article>
          <FlaskConical size={18} />
          <strong>Local lab ready</strong>
          <span>Built to point at Juice Shop on `127.0.0.1:3000`.</span>
        </article>
        <article>
          <FileSearch size={18} />
          <strong>Evidence driven</strong>
          <span>Shows discovered pages, forms, endpoints, payloads, and report output.</span>
        </article>
        <article>
          <ShieldAlert size={18} />
          <strong>Safer workflow</strong>
          <span>Pushes you away from production targets and toward explicit local testing.</span>
        </article>
      </section>
    </section>
  );
}
