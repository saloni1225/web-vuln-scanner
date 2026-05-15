# 🔐 AdaptiveScan — Offensive Surface & VAPT Assessment Platform

AdaptiveScan is a modular offensive security and VAPT assessment platform designed for automated reconnaissance, attack surface mapping, authenticated web scanning, API/GraphQL analysis, and evidence-driven vulnerability assessment workflows.

The platform combines SPA-aware crawling, extensible detector plugins, real-time telemetry, and DevSecOps-oriented CI/CD workflows into a single hosted-style security assessment experience.

---

# 🚀 Key Capabilities

* Attack surface discovery and endpoint mapping
* SPA-aware crawling using Playwright
* REST API and GraphQL discovery
* SQL Injection, XSS, CSRF, and authentication analysis
* Authenticated scanning with JWT, cookies, headers, and login bootstrap
* Plugin-based detector framework
* Real-time scan telemetry using WebSockets
* Behavioral anomaly and response-diff analysis
* Evidence-rich HTML/PDF reporting
* CI/CD security workflow integration
* Live dashboard with scan metrics and findings
* Detector benchmarking and validation workflows

---

# 🏗️ Architecture

AdaptiveScan is organized into modular security-engineering layers:

```text
Frontend UI
   ↓
FastAPI API Layer
   ↓
Recon & Crawling Engine
   ↓
Detector Plugin Framework
   ↓
Validation & Anomaly Analysis
   ↓
Evidence & Reporting Engine
   ↓
Persistence & Export Layer
```

---

# 🔍 Detector Plugin System

Detector loading is config-driven through:

```text
backend/detection/detectors.json
```

Each detector declares:

* detector name
* module path
* class
* category
* supported surfaces

The frontend dynamically loads detector metadata through:

```text
/api/detectors
```

This allows detectors to be enabled or disabled per scan profile.

---

# 🌐 Supported Scanning Features

## Web Vulnerability Detection

* SQL Injection

  * Boolean-based
  * Error-based
  * Time-based
* Cross-Site Scripting (XSS)
* CSRF workflow analysis
* Authentication analysis
* API/GraphQL fuzzing

## Reconnaissance & Discovery

* JavaScript endpoint extraction
* API discovery
* GraphQL discovery
* SPA route crawling
* Endpoint risk mapping
* Response anomaly analysis

## Authenticated Scanning

* JWT support
* Cookie-based sessions
* Authorization headers
* Login flow bootstrap

---

# 📊 Reporting

AdaptiveScan generates evidence-driven reports including:

* severity split
* payload evidence
* request/response metadata
* detector timings
* API/GraphQL coverage
* behavioral anomaly summaries
* HTML export
* PDF export

---

# ⚡ Real-Time Telemetry

The platform uses WebSockets for:

* live scan progress
* detector runtime updates
* queue state
* live KPI updates
* real-time findings telemetry

---

# 🔄 CI / CD Security Workflows

GitHub Actions workflow:

```text
.github/workflows/scanner-ci.yml
```

Pipeline workflow:

1. Install backend dependencies
2. Run backend tests
3. Build frontend
4. Start local test environment
5. Execute scanner smoke test
6. Upload HTML/PDF reports as artifacts

---

# 🧪 Safe Testing Environment

Start the local vulnerable lab target:

```bash
docker compose -f docker/docker-compose.yml up -d juice-shop
```

Safe local scan target:

```text
http://127.0.0.1:3000
```

---

# ⚙️ Backend Setup

```bash
pip install -r requirements.txt
python -m playwright install chromium
uvicorn backend.app:app --reload
```

Backend API:

```text
http://127.0.0.1:8000
```

---

# 💻 Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend URL:

```text
http://127.0.0.1:5173
```

---

# 🖥️ CLI Usage

Basic scan:

```bash
python scripts/run_scanner.py https://example.com
```

Authenticated scan:

```bash
python scripts/run_scanner.py http://127.0.0.1:3000 --auth-header "Authorization=Bearer <token>" --auth-cookie "token=<session>"
```

---

# 🧪 Validation

Run all tests:

```bash
pytest
```

Current validation includes:

* detector testing
* crawler validation
* response analysis
* reporting validation
* plugin registry tests
* CI smoke testing

---

# 🛣️ Roadmap

Planned improvements:

* Context-aware XSS detection
* Advanced SQLi validation engine
* Headless browser DOM analysis
* Distributed async scan workers
* Technology fingerprinting
* Port and service reconnaissance
* CVSS-based risk normalization
* Attack-chain correlation engine
* False positive reduction system
* Risk-based endpoint prioritization

---

# 🧰 Tech Stack

| Layer      | Technologies    |
| ---------- | --------------- |
| Backend    | Python, FastAPI |
| Frontend   | React, Vite     |
| Crawling   | Playwright      |
| Realtime   | WebSockets      |
| Reporting  | HTML/PDF        |
| CI/CD      | GitHub Actions  |
| Containers | Docker          |
| Testing    | Pytest          |

---

# 🔐 Responsible Usage

AdaptiveScan is intended only for authorized security testing, internal environments, staging systems, and systems where explicit permission has been granted.

Unauthorized scanning of third-party systems is prohibited.

---

# 📌 Project Positioning

AdaptiveScan is designed as an offensive security and DevSecOps-oriented assessment platform focused on:

* attack surface visibility
* automated reconnaissance
* authenticated security testing
* evidence-driven vulnerability assessment
* CI/CD-integrated security workflows
