# Monitoring Report

AdaptiveScan now has a continuous monitoring architecture centered on scheduled ASM, exposure drift, notification routing, and executive reporting.

## Implemented

- `/api/monitoring/workflows`
- `/api/monitoring/scheduler`
- `/api/monitoring/jobs`
- `/api/public/monitoring`
- Monitoring dashboard page
- Notification center and activity center

## Scheduler Architecture

- Celery-compatible scheduler
- Redis queue boundary
- Monitoring jobs and monitoring runs model
- Supported cadences: daily, weekly, monthly, custom cron

## Detection Events

- New asset
- New API
- New subdomain
- Certificate change
- Exposure drift
- New finding

## Remaining Production Work

- Persist monitoring jobs and runs.
- Add user-created schedules.
- Wire Celery beat in production deployment.
