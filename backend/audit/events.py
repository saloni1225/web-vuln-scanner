from __future__ import annotations


AUDIT_EVENT_TYPES = [
    "organization.created",
    "workspace.created",
    "api_key.created",
    "scan.started",
    "scan.completed",
    "finding.lifecycle.updated",
    "finding.comment.created",
]


def audit_event_catalog() -> dict[str, object]:
    return {
        "event_types": AUDIT_EVENT_TYPES,
        "retention": "365 days default, exportable for enterprise plans",
        "integrity": "append-only database records with actor, target, and JSON details",
    }

