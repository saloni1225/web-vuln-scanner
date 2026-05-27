PRODUCT_CAPABILITIES: list[dict[str, object]] = [
    {
        "id": "recon-engine",
        "title": "Core Reconnaissance Engine",
        "status": "partial",
        "implemented": [
            "subdomain enumeration",
            "DNS resolution",
            "TLS analysis",
            "WAF detection",
            "safe port scanning",
            "service banner hints",
            "technology fingerprinting",
            "hidden route probing",
            "JS/API endpoint discovery",
            "cloud storage candidate checks",
            "DNS address and PTR analysis",
        ],
        "next_tasks": [
            "deeper service fingerprinting",
            "ASN/IP range expansion",
            "MX/NS/TXT DNS records",
            "cloud provider asset inventory enrichment",
        ],
    },
    {
        "id": "web-vulnerability-coverage",
        "title": "Full Web Vulnerability Coverage",
        "status": "partial",
        "implemented": ["SQL injection", "reflected XSS", "CSRF", "authorization bypass", "security headers"],
        "next_tasks": [
            "NoSQL injection",
            "command injection",
            "LDAP/XPath injection",
            "SSTI",
            "XXE",
            "DOM/stored XSS",
            "JWT/session/MFA checks",
            "IDOR/RBAC detectors",
            "file upload bypasses",
            "cloud metadata and bucket exposure",
        ],
    },
    {
        "id": "validation-engine",
        "title": "Advanced Validation Engine",
        "status": "partial",
        "implemented": ["finding validation", "response diffing", "behavioral anomaly scoring", "replay plans"],
        "next_tasks": ["timing validation", "exploit proof scoring", "deduplicated validation cache", "safe replay runner"],
    },
    {
        "id": "spa-api-awareness",
        "title": "Modern SPA & API Awareness",
        "status": "partial",
        "implemented": ["Playwright crawling", "dynamic route discovery", "REST endpoint tracking", "GraphQL probing", "schema fuzzing"],
        "next_tasks": ["DOM sink analysis", "JS AST parsing", "API schema learning", "SPA state exploration"],
    },
    {
        "id": "authenticated-scanning",
        "title": "Authenticated Scanning",
        "status": "partial",
        "implemented": ["JWT reuse", "custom headers", "cookie reuse", "basic login form fields", "role naming"],
        "next_tasks": ["OAuth flows", "session recording", "login recorder", "MFA step support", "role comparison automation"],
    },
    {
        "id": "continuous-monitoring",
        "title": "Continuous Monitoring",
        "status": "planned",
        "implemented": ["scan history", "report comparison", "CI risk gate metadata"],
        "next_tasks": ["scheduled scans", "attack surface drift detection", "continuous asset monitoring", "alert policies"],
    },
    {
        "id": "vulnerability-lifecycle",
        "title": "Real Vulnerability Lifecycle",
        "status": "planned",
        "implemented": ["saved findings", "retesting through resumed scans"],
        "next_tasks": ["Open/Triaged/Assigned/Retesting/Resolved/Closed workflow", "comments", "owners", "SLA tracking"],
    },
    {
        "id": "team-collaboration",
        "title": "Team Collaboration",
        "status": "planned",
        "implemented": [],
        "next_tasks": ["multi-user orgs", "RBAC", "workspaces", "notes", "assignments"],
    },
    {
        "id": "enterprise-dashboard",
        "title": "Enterprise Dashboard",
        "status": "partial",
        "implemented": ["risk trends", "severity distribution", "scan history", "endpoint inventory panels"],
        "next_tasks": ["asset inventory", "attack surface map", "exposure tracking", "remediation metrics"],
    },
    {
        "id": "devsecops-cicd",
        "title": "DevSecOps & CI/CD",
        "status": "partial",
        "implemented": ["CLI scan runner", "risk gate", "fail-on-high policy", "CI/CD guidance page"],
        "next_tasks": ["GitHub Actions template", "Jenkinsfile", "GitLab CI", "Azure DevOps", "critical finding policy"],
    },
    {
        "id": "reporting-system",
        "title": "Real Reporting System",
        "status": "partial",
        "implemented": ["HTML reports", "PDF reports", "technical evidence", "remediation guidance"],
        "next_tasks": ["executive report", "compliance report", "custom report templates", "export bundles"],
    },
    {
        "id": "compliance-layer",
        "title": "Compliance Layer",
        "status": "partial",
        "implemented": ["CWE mapping", "CVSS-style scoring", "OWASP category mapping"],
        "next_tasks": ["PCI DSS mapping", "ISO 27001 mapping", "NIST mapping", "compliance summary reports"],
    },
    {
        "id": "distributed-architecture",
        "title": "Distributed Scanning Architecture",
        "status": "planned",
        "implemented": ["FastAPI backend", "React frontend", "SQLite persistence"],
        "next_tasks": ["API gateway", "Redis queue", "distributed workers", "PostgreSQL", "object storage"],
    },
    {
        "id": "ai-assisted-features",
        "title": "AI-Assisted Features",
        "status": "planned",
        "implemented": ["remediation text helpers"],
        "next_tasks": ["finding deduplication", "exploitability prediction", "risk prioritization", "AI remediation suggestions"],
    },
]


def list_product_capabilities() -> dict[str, object]:
    totals = {"implemented": 0, "partial": 0, "planned": 0}
    for capability in PRODUCT_CAPABILITIES:
        status = str(capability["status"])
        totals[status] = totals.get(status, 0) + 1
    return {
        "capabilities": PRODUCT_CAPABILITIES,
        "summary": {
            "total": len(PRODUCT_CAPABILITIES),
            **totals,
        },
    }
