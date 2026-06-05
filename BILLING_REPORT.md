# Billing Report

AdaptiveScan includes a SaaS billing architecture for plans, subscriptions, usage records, invoices, and Stripe abstraction.

## Implemented

- `/api/billing/catalog`
- `/api/billing/subscription`
- `/api/billing/usage`
- `/api/billing/stripe`
- Billing page
- SQLAlchemy models for subscriptions, usage records, and invoices

## Plans

- Starter
- Professional
- Business
- Enterprise

## Metered Usage

- Assets
- Scans
- Monitoring jobs
- Team members
- Storage usage

## Remaining Production Work

- Add Stripe checkout and billing portal session endpoints.
- Consume Stripe webhooks.
- Persist usage records from product events.
