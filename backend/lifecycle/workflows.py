from __future__ import annotations


LIFECYCLE_STATES = [
    {"state": "open", "label": "Open", "sla_hours": 72},
    {"state": "triaged", "label": "Triaged", "sla_hours": 72},
    {"state": "assigned", "label": "Assigned", "sla_hours": 168},
    {"state": "retesting", "label": "Retesting", "sla_hours": 48},
    {"state": "resolved", "label": "Resolved", "sla_hours": 0},
    {"state": "closed", "label": "Closed", "sla_hours": 0},
]


def lifecycle_policy() -> dict[str, object]:
    return {
        "states": LIFECYCLE_STATES,
        "automation": ["auto-open new findings", "auto-retest resolved findings", "SLA breach alerts"],
        "ownership": ["workspace owner", "finding assignee", "CI bot"],
    }

