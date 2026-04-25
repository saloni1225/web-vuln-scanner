# Adaptive Web Vulnerability Scanner

A starter full-stack scanner for crawling a target site, running lightweight vulnerability probes, storing scan results, and generating HTML reports.

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

You should now see richer finding evidence in both the API result and exported HTML report, including severity split and response diff metadata.

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
