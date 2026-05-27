VULNERABILITY_LIFECYCLE = [
    {"state": "open", "label": "Open", "description": "New finding awaiting review."},
    {"state": "triaged", "label": "Triaged", "description": "Reviewed and confirmed for ownership."},
    {"state": "assigned", "label": "Assigned", "description": "Assigned to an owner or team."},
    {"state": "retesting", "label": "Retesting", "description": "Fix is ready and needs scanner validation."},
    {"state": "resolved", "label": "Resolved", "description": "Validated as fixed."},
    {"state": "closed", "label": "Closed", "description": "Accepted final lifecycle state."},
]

COMPLIANCE_FRAMEWORKS = [
    {
        "framework": "OWASP Top 10",
        "mappings": {
            "injection": "A03:2021 Injection",
            "xss": "A03:2021 Injection",
            "auth": "A07:2021 Identification and Authentication Failures",
            "access-control": "A01:2021 Broken Access Control",
            "misconfiguration": "A05:2021 Security Misconfiguration",
        },
    },
    {
        "framework": "PCI DSS",
        "mappings": {
            "injection": "Requirement 6.2.4",
            "xss": "Requirement 6.2.4",
            "tls": "Requirement 4.2.1",
            "access-control": "Requirement 7",
        },
    },
    {
        "framework": "ISO 27001",
        "mappings": {
            "vulnerability-management": "A.8.8 Management of technical vulnerabilities",
            "access-control": "A.5.15 Access control",
            "logging-monitoring": "A.8.15 Logging",
        },
    },
    {
        "framework": "NIST",
        "mappings": {
            "vulnerability-management": "RA-5 Vulnerability Monitoring and Scanning",
            "access-control": "AC-3 Access Enforcement",
            "incident-response": "IR-4 Incident Handling",
        },
    },
]

CI_TEMPLATES = [
    {
        "platform": "GitHub Actions",
        "file": ".github/workflows/security-scan.yml",
        "command": "python scripts/run_scanner.py ${{ secrets.SCAN_TARGET_URL }} --profile quick --fail-on-high --max-high 0",
    },
    {
        "platform": "GitLab CI",
        "file": ".gitlab-ci.yml",
        "command": "python scripts/run_scanner.py \"$SCAN_TARGET_URL\" --profile quick --fail-on-high --max-high 0",
    },
    {
        "platform": "Jenkins",
        "file": "Jenkinsfile",
        "command": "python scripts/run_scanner.py \"$SCAN_TARGET_URL\" --profile quick --fail-on-high --max-high 0",
    },
    {
        "platform": "Azure DevOps",
        "file": "azure-pipelines.yml",
        "command": "python scripts/run_scanner.py $(SCAN_TARGET_URL) --profile quick --fail-on-high --max-high 0",
    },
]

DISTRIBUTED_ARCHITECTURE = [
    {"layer": "Frontend", "current": "React/Vite", "target": "React or Next.js app shell"},
    {"layer": "API Gateway", "current": "FastAPI router", "target": "FastAPI gateway with auth, orgs, RBAC"},
    {"layer": "Queue", "current": "in-process job registry", "target": "Redis queue"},
    {"layer": "Workers", "current": "single scanner process", "target": "distributed scan workers"},
    {"layer": "Database", "current": "SQLite", "target": "PostgreSQL"},
    {"layer": "Object Storage", "current": "local exports", "target": "S3/GCS/Azure Blob report artifacts"},
]


def get_enterprise_foundation() -> dict[str, object]:
    return {
        "lifecycle": VULNERABILITY_LIFECYCLE,
        "compliance": COMPLIANCE_FRAMEWORKS,
        "ci_templates": CI_TEMPLATES,
        "distributed_architecture": DISTRIBUTED_ARCHITECTURE,
        "next_platform_tasks": [
            "persist finding lifecycle state",
            "add team/workspace ownership",
            "create scheduled scan runner",
            "add Redis worker queue",
            "migrate scan storage to PostgreSQL",
            "add compliance report exports",
            "add AI-assisted deduplication and prioritization",
        ],
    }
