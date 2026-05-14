AdaptiveScan — Hosted Offensive Surface & VAPT Assessment Platform

A full-stack scanner for crawling a target site, running extensible vulnerability probes, storing scan results, and generating evidence-rich HTML reports.

## What It Supports

- Detector plugin registry loaded from `backend/detection/detectors.json`
- SPA-aware crawling with Playwright
- API and GraphQL surface discovery
- Authenticated scanning with headers, cookies, JWT, or login flow bootstrap
- Behavioral anomaly summaries and response-diff metadata
- Live scan progress and queue state over WebSocket
- HTML reporting with severity, payload, PoC, and request/response evidence
- GitHub Actions CI that runs tests, builds the frontend, and smoke-scans Juice Shop on push

## Backend

```bash
pip install -r requirements.txt
python -m playwright install chromium
uvicorn backend.app:app --reload
```

The API runs at `http://127.0.0.1:8000`.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

The Vite app runs at `http://127.0.0.1:5173`.

## Local Lab Target

Use a safe local target instead of a public production site.

```bash
docker compose -f docker/docker-compose.yml up -d juice-shop
```

Then scan:

```text
http://127.0.0.1:3000
```

## CLI Scan

```bash
python scripts/run_scanner.py https://example.com
```

Authenticated scan example:

```bash
python scripts/run_scanner.py http://127.0.0.1:3000 --auth-header "Authorization=Bearer <token>" --auth-cookie "token=<session>"
```

## Juice Shop Validation

Run the local lab target and scan it with the default scanner profile:

```bash
docker compose -f docker/docker-compose.yml up -d juice-shop
python scripts/run_scanner.py http://127.0.0.1:3000
```

You should now see richer finding evidence in both the API result and exported HTML report, including severity split, API/GraphQL coverage, detector plugin metadata, and response diff metadata.

## Detector Plugins

Detector loading is config-driven:

```text
backend/detection/detectors.json
```

Each entry declares the detector name, Python module, class, category, and supported input surfaces. The frontend reads this registry through `/api/detectors` and lets you enable or disable detector plugins per scan run.

## CI / CD

GitHub Actions is configured in:

```text
.github/workflows/scanner-ci.yml
```

On every push or pull request it:

1. installs backend dependencies
2. runs `pytest`
3. builds the frontend
4. starts Juice Shop in Docker
5. runs a scanner smoke test against `http://127.0.0.1:3000`

## Tests

```bash
pytest
```

Only scan systems you own or have explicit permission to test.
# Web Vulnerability Scanner

## Features
- SQL Injection detection
- XSS detection
- Automated crawling
- Real-time dashboard

## Tech Stack
- FastAPI
- React
- Docker

## How to Run
1. Backend:
   uvicorn backend.app:app --reload

2. Frontend:
   npm install
   npm run dev

3. Juice Shop:
   docker compose up -d
