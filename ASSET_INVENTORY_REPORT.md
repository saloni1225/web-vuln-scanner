# Asset Inventory Report

AdaptiveScan treats assets as first-class SaaS objects instead of temporary scan output.

## Tracked Asset Types

- Domains
- Subdomains
- APIs
- GraphQL endpoints
- Certificates
- Services
- Cloud assets
- Findings

## Implemented

- Assets page with enterprise inventory table
- Public assets API at `/api/public/assets`
- Asset relationship model in documentation and API output
- SQLAlchemy `assets` table with organization ownership
- Exposure scoring and last-seen fields

## Remaining Production Work

- Persist discovered assets from every scan into the assets table.
- Add asset history and tag update APIs.
- Add saved filters and owner assignment workflows.
