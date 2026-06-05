# PostgreSQL Migration Report

AdaptiveScan has a PostgreSQL-ready SQLAlchemy schema and Alembic foundation.

## Implemented

- SQLAlchemy declarative models
- PostgreSQL JSONB column strategy
- Alembic directory
- Production-oriented tenant-owned table registry
- psycopg2 and asyncpg dependencies

## Core Tables

- users
- organizations
- organization_members
- roles
- permissions
- assets
- findings
- reports
- notifications/alerts
- subscriptions
- plans via billing catalog
- monitoring jobs/monitors
- monitoring runs via scheduler architecture
- audit_logs
- refresh_tokens

## Remaining Production Work

- Make PostgreSQL the default production database URL.
- Add full Alembic revisions for all SaaS tables.
- Retire local SQLite compatibility after migration.
