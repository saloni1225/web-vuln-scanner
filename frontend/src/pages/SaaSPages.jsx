import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  Bell,
  BookOpen,
  Building2,
  Check,
  Code2,
  CreditCard,
  FileText,
  Github,
  GitBranch,
  KeyRound,
  LockKeyhole,
  Mail,
  MonitorDot,
  Network,
  Radar,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Sparkles,
  Users,
} from "lucide-react";
import { fetchAuthArchitecture, fetchBillingCatalog, fetchMonitoringWorkflows, fetchNotificationCenter, fetchOnboarding, fetchSubscriptionStatus, fetchTeamDirectory, fetchTrustCenter, loginAccount, registerAccount, requestPasswordReset, verifyOtp } from "../services/api.js";

const featureGroups = [
  ["Attack Surface Discovery", Network, "Continuously discover internet-facing domains, services, APIs, and ownership signals."],
  ["Exposure Intelligence", Shield, "Score exploitable exposure, identity drift, evidence quality, and business blast radius."],
  ["API Security", Code2, "Analyze OpenAPI, GraphQL, Postman, and discovered endpoints with safe fuzzing controls."],
  ["Threat Intelligence", Bell, "Correlate current exploit pressure, technology signals, and operational alerting."],
  ["Continuous Monitoring", MonitorDot, "Detect surface drift, new findings, and posture changes before they become incidents."],
  ["Attack Path Analysis", GitBranch, "Connect exposed assets, findings, identities, and remediation owners into risk paths."],
  ["AI Risk Prioritization", Sparkles, "Summarize validated impact and next actions for executives and security teams."],
  ["Reporting", FileText, "Generate executive, technical, compliance, and evidence-backed reports."],
  ["DevSecOps Integration", BadgeCheck, "Bring exposure gates, scan profiles, and APIs into delivery pipelines."],
];

const docs = ["Getting Started", "Authentication", "Organizations", "Assets", "Monitoring", "Exposure Intelligence", "APIs", "Reports", "Team Management", "Integrations"];
const roles = ["Owner", "Admin", "Security Engineer", "Analyst", "Viewer"];

export function MarketingHome({ onNavigate }) {
  return (
    <section className="saas-page">
      <section className="saas-hero">
        <div className="hero-copy">
          <span className="saas-eyebrow">AdaptiveScan Commercial SaaS</span>
          <h1>AI-Powered Attack Surface Intelligence Platform</h1>
          <p>Discover assets, identify exposure, validate risks, and monitor continuously from one enterprise security workspace.</p>
          <div className="hero-actions">
            <button className="primary-action" type="button" onClick={() => onNavigate("register")}><Sparkles size={17} /> Start Free Trial</button>
            <button className="ghost-button" type="button" onClick={() => onNavigate("contact")}><Users size={17} /> Request Demo</button>
          </div>
          <div className="hero-points">
            {["Discover Assets", "Identify Exposure", "Validate Risks", "Monitor Continuously"].map((item) => <span key={item}><Check size={14} /> {item}</span>)}
          </div>
        </div>
        <div className="hero-product-shot" aria-label="AdaptiveScan product screenshot">
          <div className="shot-top"><span /> <span /> <span /></div>
          <div className="shot-grid">
            <div className="shot-score"><strong>82</strong><span>Exposure Score</span></div>
            <div className="shot-panel"><span>Attack paths</span><strong>14 validated</strong></div>
            <div className="shot-panel"><span>Assets</span><strong>2,418 monitored</strong></div>
            <div className="shot-wide">{["api.acme.com", "vpn.acme.com", "cdn.acme.com", "login.acme.com"].map((host) => <em key={host}>{host}</em>)}</div>
          </div>
        </div>
      </section>

      <FeatureBand />
      <section className="saas-section split">
        <div>
          <span className="saas-eyebrow">Platform Overview</span>
          <h2>Built for exposure operations, not one-off scans.</h2>
          <p>AdaptiveScan combines ASM, vulnerability assessment, monitoring, attack graphing, AI triage, and reporting into a SaaS-ready operating model.</p>
        </div>
        <div className="workflow-list">
          {["Define scope and ownership", "Discover and validate exposure", "Prioritize attack paths", "Route remediation and monitor drift"].map((item, index) => <div key={item}><strong>{index + 1}</strong><span>{item}</span></div>)}
        </div>
      </section>

      <section className="saas-section">
        <span className="saas-eyebrow">Customer Benefits</span>
        <div className="benefit-grid">
          {["Reduce unknown internet exposure", "Unify technical and executive reporting", "Protect APIs and modern apps", "Operationalize continuous monitoring"].map((item) => <article key={item}><ShieldCheck size={20} /><strong>{item}</strong><p>Security teams get evidence, context, and workflow-ready next steps.</p></article>)}
        </div>
      </section>

      <section className="saas-section testimonials">
        <article><p>AdaptiveScan turned a fragmented external surface review into a daily operating rhythm.</p><strong>CISO, fintech platform</strong></article>
        <article><p>The attack path view helped engineering fix what actually changed risk, not just what looked noisy.</p><strong>Director of AppSec</strong></article>
      </section>

      <section className="saas-section faq">
        {["Can I start with one domain?", "Does it support APIs?", "Is MFA and RBAC included?", "Can I request a demo?"].map((q) => <details key={q}><summary>{q}</summary><p>Yes. AdaptiveScan is structured for trial usage, enterprise workflows, and secure team collaboration.</p></details>)}
      </section>
      <SaaSFooter onNavigate={onNavigate} />
    </section>
  );
}

export function FeaturesPage() {
  return <section className="saas-page"><PageTitle eyebrow="Features" title="Enterprise exposure intelligence across the whole attack surface." /><FeatureBand expanded /></section>;
}

export function PricingPage() {
  const [catalog, setCatalog] = useState(null);
  useEffect(() => { fetchBillingCatalog().then(setCatalog).catch(() => setCatalog(null)); }, []);
  const plans = catalog?.plans ?? [
    { name: "Starter", price: "$99/mo", monitored_assets: 50, team_members: 3, api_access: "limited", monitoring: "weekly", support: "community" },
    { name: "Professional", price: "$399/mo", monitored_assets: 500, team_members: 10, api_access: "standard", monitoring: "daily", support: "business hours" },
    { name: "Business", price: "$999/mo", monitored_assets: 2500, team_members: 30, api_access: "advanced", monitoring: "continuous", support: "priority" },
    { name: "Enterprise", price: "Custom", monitored_assets: "unlimited", team_members: "unlimited", api_access: "enterprise", monitoring: "continuous", support: "dedicated" },
  ];
  return (
    <section className="saas-page">
      <PageTitle eyebrow="Pricing" title="Billing-ready plans for every exposure program." />
      <div className="pricing-grid">
        {plans.map((plan) => (
          <article className="price-card" key={plan.name}>
            <span>{plan.name}</span>
            <strong>{plan.price}</strong>
            <p>{plan.monitored_assets} monitored assets</p>
            <ul>
              <li><Users size={15} /> {plan.team_members} team members</li>
              <li><Code2 size={15} /> {plan.api_access} API access</li>
              <li><MonitorDot size={15} /> {plan.monitoring} monitoring</li>
              <li><Shield size={15} /> {plan.support} support</li>
            </ul>
          </article>
        ))}
      </div>
    </section>
  );
}

export function DocumentationPage() {
  const [query, setQuery] = useState("");
  const filtered = docs.filter((item) => item.toLowerCase().includes(query.toLowerCase()));
  return (
    <section className="saas-page">
      <PageTitle eyebrow="Documentation" title="AdaptiveScan documentation portal." />
      <label className="doc-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search documentation" /></label>
      <div className="docs-grid">
        {filtered.map((item) => <article key={item}><BookOpen size={20} /><strong>{item}</strong><p>Guides, API patterns, operational practices, and security workflows for {item.toLowerCase()}.</p></article>)}
      </div>
    </section>
  );
}

export function ContactPage() {
  return (
    <section className="saas-page">
      <PageTitle eyebrow="Contact" title="Talk with AdaptiveScan." />
      <div className="contact-grid">
        {["Contact form", "Demo request", "Enterprise inquiry", "Support inquiry"].map((item) => <ContactForm key={item} title={item} />)}
      </div>
    </section>
  );
}

export function AuthPage({ mode = "login", onNavigate }) {
  const [form, setForm] = useState(() => ({ first_name: "", last_name: "", company_name: "", work_email: "", email: window.localStorage.getItem("adaptiveScan.pendingEmail") || "", password: "", confirm_password: "", code: "" }));
  const [message, setMessage] = useState("");
  const isRegister = mode === "register";
  const isOtp = mode === "otp" || mode === "mfa";
  const isForgot = mode === "forgot";
  const title = isRegister ? "Create your AdaptiveScan workspace" : isOtp ? "Verify secure access" : isForgot ? "Reset your password" : "Sign in to AdaptiveScan";

  async function submit(event) {
    event.preventDefault();
    setMessage("Working...");
    try {
      if (isRegister) {
        const result = await registerAccount(form);
        window.localStorage.setItem("adaptiveScan.pendingEmail", form.work_email);
        setMessage(`Workspace created. Dev OTP: ${result.verification?.dev_code ?? "sent"}`);
        onNavigate("otp");
      } else if (isOtp) {
        const result = await verifyOtp({ email: form.email || form.work_email, code: form.code, purpose: mode === "mfa" ? "login_mfa" : "email_verification" });
        setMessage(result.verified ? "Verified." : "Enter a valid six-digit code.");
        if (result.verified) {
          window.localStorage.removeItem("adaptiveScan.pendingEmail");
          onNavigate(mode === "mfa" ? "home" : "onboarding");
        }
      } else if (isForgot) {
        const result = await requestPasswordReset({ email: form.email });
        setMessage(`Reset OTP issued. Dev OTP: ${result.reset?.dev_code ?? "sent"}`);
      } else {
        const result = await loginAccount({ email: form.email, password: form.password });
        setMessage(result.requires_mfa ? `MFA required. Dev OTP: ${result.mfa?.challenge?.dev_code ?? "sent"}` : "Signed in.");
        window.localStorage.setItem("adaptiveScan.pendingEmail", form.email);
        window.localStorage.setItem("adaptiveScan.accessToken", result.tokens?.access_token ?? "");
        window.localStorage.setItem("adaptiveScan.refreshToken", result.tokens?.refresh_token ?? "");
        if (result.requires_mfa) onNavigate("mfa");
        if (!result.requires_mfa) onNavigate("home");
      }
    } catch (error) {
      setMessage(String(error.message ?? error));
    }
  }

  return (
    <section className="auth-stage">
      <form className="auth-card" onSubmit={submit}>
        <span className="saas-eyebrow">{mode}</span>
        <h1>{title}</h1>
        {isRegister ? (
          <><input placeholder="First Name" value={form.first_name} onChange={(event) => setForm({ ...form, first_name: event.target.value })} /><input placeholder="Last Name" value={form.last_name} onChange={(event) => setForm({ ...form, last_name: event.target.value })} /><input placeholder="Company Name" value={form.company_name} onChange={(event) => setForm({ ...form, company_name: event.target.value })} /><input placeholder="Work Email" value={form.work_email} onChange={(event) => setForm({ ...form, work_email: event.target.value })} /></>
        ) : null}
        {!isRegister && !isOtp ? <input placeholder="Work Email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} /> : null}
        {!isOtp && !isForgot ? <><input type="password" placeholder="Password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />{isRegister ? <input type="password" placeholder="Confirm Password" value={form.confirm_password} onChange={(event) => setForm({ ...form, confirm_password: event.target.value })} /> : null}</> : null}
        {isOtp ? <><input placeholder="Email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} /><input placeholder="Six-digit code" value={form.code} onChange={(event) => setForm({ ...form, code: event.target.value })} /></> : null}
        <button className="primary-action" type="submit"><LockKeyhole size={16} /> Continue</button>
        <div className="social-row">
          <button type="button"><Search size={15} /> Google</button>
          <button type="button"><Github size={15} /> GitHub</button>
          <button type="button"><Building2 size={15} /> Microsoft</button>
        </div>
        <div className="auth-links">
          <button type="button" onClick={() => onNavigate("login")}>Login</button>
          <button type="button" onClick={() => onNavigate("register")}>Register</button>
          <button type="button" onClick={() => onNavigate("forgot")}>Forgot Password</button>
          <button type="button" onClick={() => onNavigate("mfa")}>MFA</button>
        </div>
        {message ? <p className="auth-message">{message}</p> : null}
      </form>
      <AuthArchitecturePanel />
    </section>
  );
}

export function OnboardingPage({ onNavigate }) {
  const [state, setState] = useState(null);
  const [setup, setSetup] = useState({ organization: "", primaryAsset: "", cadence: "Daily exposure monitoring", invite: "" });
  useEffect(() => { fetchOnboarding().then(setState).catch(() => setState(null)); }, []);
  const steps = state?.steps ?? [];
  return (
    <section className="saas-page">
      <PageTitle eyebrow="Onboarding" title="Launch your first exposure program." />
      <div className="onboarding-layout">
        <div className="onboarding-grid">
          {steps.map((step, index) => <article key={step.id}><span>{index + 1}</span><strong>{step.title}</strong><p>{step.options?.join(", ") || step.roles?.join(", ") || step.placeholder || step.status}</p></article>)}
        </div>
        <form className="onboarding-form">
          <label><span>Organization</span><input value={setup.organization} placeholder="Acme Security" onChange={(event) => setSetup({ ...setup, organization: event.target.value })} /></label>
          <label><span>Primary Asset</span><input value={setup.primaryAsset} placeholder="example.com" onChange={(event) => setSetup({ ...setup, primaryAsset: event.target.value })} /></label>
          <label><span>Monitoring Cadence</span><select value={setup.cadence} onChange={(event) => setSetup({ ...setup, cadence: event.target.value })}>{["Daily exposure monitoring", "Weekly executive review", "On-demand assessment"].map((item) => <option key={item}>{item}</option>)}</select></label>
          <label><span>Invite Owner</span><input value={setup.invite} placeholder="appsec@example.com" onChange={(event) => setSetup({ ...setup, invite: event.target.value })} /></label>
        </form>
      </div>
      <button className="primary-action" type="button" onClick={() => onNavigate("dashboard")}><Radar size={16} /> Start Monitoring</button>
    </section>
  );
}

export function TeamManagementPage() {
  const [team, setTeam] = useState(null);
  useEffect(() => { fetchTeamDirectory().then(setTeam).catch(() => setTeam(null)); }, []);
  const items = team?.members?.map((member) => `${member.name} · ${member.role} · ${member.status}`) ?? roles.map((role) => `${role} role policy`);
  return <PlatformAdminPage eyebrow="Team Management" title="Invite users, assign roles, and enforce MFA." items={items} icon={Users} />;
}

export function BillingPage() {
  const [subscription, setSubscription] = useState(null);
  useEffect(() => { fetchSubscriptionStatus().then(setSubscription).catch(() => setSubscription(null)); }, []);
  const usage = subscription?.usage ?? {};
  return <PlatformAdminPage eyebrow="Billing" title="Plans, subscription, usage, and invoices." items={[
    `Current plan: ${subscription?.plan ?? "Professional"}`,
    `Status: ${subscription?.status ?? "trialing"}`,
    `Assets: ${usage.monitored_assets ?? 128}/${usage.asset_limit ?? 500}`,
    `API usage: ${usage.api_calls_this_month ?? 0} calls this month`,
  ]} icon={CreditCard} />;
}

export function SaaSSettingsPage() {
  return <PlatformAdminPage eyebrow="Settings" title="Profile, MFA, API keys, notifications, and organization settings." items={["Profile security", "MFA methods", "API key management", "Notification routing", "Organization settings"]} icon={Settings} />;
}

export function NotificationCenterPage() {
  const [center, setCenter] = useState(null);
  useEffect(() => { fetchNotificationCenter().then(setCenter).catch(() => setCenter(null)); }, []);
  const items = [
    ...(center?.channels ?? []).map((channel) => `${channel.name} · ${channel.status} · ${channel.routing}`),
    ...(center?.rules ?? []).map((rule) => `${rule.name} · ${rule.severity} · ${rule.channels.join(", ")}`),
  ];
  return <PlatformAdminPage eyebrow="Notification Center" title="Route exposure alerts to the right teams." items={items.length ? items : ["Email routing", "Slack alerts", "Webhook delivery", "Executive digest"]} icon={Bell} />;
}

export function MonitoringWorkflowsPage() {
  const [catalog, setCatalog] = useState(null);
  useEffect(() => { fetchMonitoringWorkflows().then(setCatalog).catch(() => setCatalog(null)); }, []);
  const items = catalog?.workflows?.map((workflow) => `${workflow.name} · ${workflow.cadence} · ${workflow.status}`) ?? ["Continuous external monitoring", "New asset discovery", "Executive reporting", "Finding retest"];
  return <PlatformAdminPage eyebrow="Monitoring Workflows" title="Operational monitoring built around assets and exposure." items={items} icon={MonitorDot} />;
}

export function TrustPage() {
  const [trust, setTrust] = useState(null);
  useEffect(() => { fetchTrustCenter().then(setTrust).catch(() => setTrust(null)); }, []);
  const sections = [
    ["Security", ShieldCheck, trust?.security ?? ["MFA enforcement", "RBAC", "Audit logging"]],
    ["Compliance", BadgeCheck, trust?.compliance ?? ["SOC 2 readiness", "ISO 27001 mapping", "OWASP evidence exports"]],
    ["Privacy", LockKeyhole, trust?.privacy ?? ["Tenant isolation", "Least privilege tokens", "Retention controls"]],
  ];
  return (
    <section className="saas-page">
      <PageTitle eyebrow="Trust Center" title="Security, compliance, and privacy for enterprise buyers." />
      <div className="docs-grid">
        {sections.map(([title, Icon, items]) => <article key={title}><Icon size={20} /><strong>{title}</strong><p>{items.join(", ")}</p></article>)}
      </div>
    </section>
  );
}

function PageTitle({ eyebrow, title }) {
  return <header className="saas-title"><span className="saas-eyebrow">{eyebrow}</span><h1>{title}</h1></header>;
}

function FeatureBand({ expanded = false }) {
  return <section className={`feature-band ${expanded ? "expanded" : ""}`}>{featureGroups.map(([title, Icon, copy]) => <article key={title}><Icon size={22} /><strong>{title}</strong><p>{copy}</p></article>)}</section>;
}

function ContactForm({ title }) {
  return <form className="contact-form"><strong>{title}</strong><input placeholder="Name" /><input placeholder="Work Email" /><textarea placeholder="Message" /><button type="button">Submit</button></form>;
}

function AuthArchitecturePanel() {
  const [architecture, setArchitecture] = useState(null);
  useEffect(() => { fetchAuthArchitecture().then(setArchitecture).catch(() => setArchitecture(null)); }, []);
  const controls = architecture?.security_controls ?? ["JWT auth", "Refresh tokens", "RBAC", "MFA", "Audit logging"];
  return <aside className="auth-architecture"><KeyRound size={24} /><strong>Enterprise auth architecture</strong>{controls.map((item) => <span key={item}><Check size={14} /> {item}</span>)}</aside>;
}

function PlatformAdminPage({ eyebrow, title, items, icon: Icon }) {
  return <section className="page-stack"><header className="saas-title compact"><span className="saas-eyebrow">{eyebrow}</span><h1>{title}</h1></header><div className="admin-grid">{items.map((item) => <article key={item}><Icon size={20} /><strong>{item}</strong><p>Configured for SaaS operations and enterprise governance.</p></article>)}</div></section>;
}

function SaaSFooter({ onNavigate }) {
  return <footer className="saas-footer"><strong>AdaptiveScan</strong><nav>{["features", "pricing", "documentation", "contact", "login"].map((item) => <button key={item} type="button" onClick={() => onNavigate(item)}>{item}</button>)}</nav></footer>;
}
