from __future__ import annotations


def stripe_architecture() -> dict[str, object]:
    return {
        "provider": "stripe",
        "mode": "abstraction",
        "objects": ["customers", "subscriptions", "prices", "invoices", "usage_records", "checkout_sessions", "billing_portal_sessions"],
        "webhooks": ["customer.subscription.updated", "invoice.paid", "invoice.payment_failed", "checkout.session.completed"],
        "metered_usage": ["assets", "scans", "monitoring_jobs", "team_members", "storage_usage"],
    }


def billing_usage_summary() -> dict[str, object]:
    return {
        "plans": ["Starter", "Professional", "Business", "Enterprise"],
        "usage_records": [
            {"metric": "assets", "quantity": 128, "limit": 500},
            {"metric": "scans", "quantity": 46, "limit": 250},
            {"metric": "monitoring_jobs", "quantity": 12, "limit": 50},
            {"metric": "team_members", "quantity": 6, "limit": 10},
            {"metric": "storage_usage_gb", "quantity": 4, "limit": 100},
        ],
        "invoices": [
            {"invoice_id": "draft-next", "amount_cents": 39900, "currency": "usd", "status": "draft"},
        ],
        "stripe": stripe_architecture(),
    }
