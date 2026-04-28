from backend.database.db import get_scan
from urllib.parse import urlparse
import re


def compare_roles(left_scan_id: str, right_scan_id: str) -> dict[str, object] | None:
    left = get_scan(left_scan_id)
    right = get_scan(right_scan_id)
    if left is None or right is None:
        return None
    left_endpoints = _endpoint_map(left)
    right_endpoints = _endpoint_map(right)
    shared = sorted(set(left_endpoints) & set(right_endpoints))
    left_only = sorted(set(left_endpoints) - set(right_endpoints))
    right_only = sorted(set(right_endpoints) - set(left_endpoints))
    suspicious_shared = [
        item for item in shared
        if any(token in item.lower() for token in ("/admin", "/settings", "/account", "/user", "/orders", "/profile"))
    ]
    idor_candidates = _build_idor_candidates(left_endpoints, right_endpoints)
    return {
        "left_scan_id": left_scan_id,
        "right_scan_id": right_scan_id,
        "left_role": left.get("role_summary", {}).get("role_name", "default"),
        "right_role": right.get("role_summary", {}).get("role_name", "default"),
        "target_match": left.get("target_url") == right.get("target_url"),
        "shared_endpoint_count": len(shared),
        "left_only_endpoint_count": len(left_only),
        "right_only_endpoint_count": len(right_only),
        "suspicious_shared_privileged_endpoints": suspicious_shared[:25],
        "idor_candidate_count": len(idor_candidates),
        "idor_candidates": idor_candidates[:25],
        "authorization_review": _authorization_review(left_only, right_only, suspicious_shared, idor_candidates),
    }


def _endpoint_map(scan: dict[str, object]) -> dict[str, dict[str, object]]:
    mapped = {}
    for endpoint in scan.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        key = f"{str(endpoint.get('method', 'GET')).upper()} {endpoint.get('url')}"
        mapped[key] = endpoint
    return mapped


def _build_idor_candidates(
    left_endpoints: dict[str, dict[str, object]],
    right_endpoints: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    candidates = []
    right_templates = {_template_endpoint(key): key for key in right_endpoints}
    for left_key in left_endpoints:
        template = _template_endpoint(left_key)
        right_key = right_templates.get(template)
        if not right_key:
            continue
        if left_key == right_key:
            continue
        candidates.append(
            {
                "template": template,
                "left_endpoint": left_key,
                "right_endpoint": right_key,
                "reason": "Both roles expose the same object-addressing pattern with different concrete identifiers.",
                "review_type": "idor-manual-validation",
            }
        )
    return candidates


def _template_endpoint(endpoint_key: str) -> str:
    method, _, url = endpoint_key.partition(" ")
    parsed = urlparse(url)
    path = re.sub(r"/[0-9a-fA-F-]{8,}(?=/|$)", "/{uuid}", parsed.path)
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    query = re.sub(r"([?&][A-Za-z0-9_%-]*(?:id|user|account|order)[A-Za-z0-9_%-]*=)[^&]+", r"\1{id}", parsed.query, flags=re.IGNORECASE)
    return f"{method} {parsed.scheme}://{parsed.netloc}{path}?{query}".rstrip("?")


def _authorization_review(left_only: list[str], right_only: list[str], shared_privileged: list[str], idor_candidates: list[dict[str, object]]) -> list[str]:
    review = []
    if shared_privileged:
        review.append("Both roles can reach privileged-looking endpoints; verify authorization checks manually.")
    if idor_candidates:
        review.append("Object-identifier patterns overlap across roles; perform authorized IDOR validation with paired sessions.")
    if left_only or right_only:
        review.append("Role-specific endpoint differences were observed; review whether the direction matches the intended permission model.")
    if not review:
        review.append("No obvious role-difference authorization signal was observed from endpoint visibility alone.")
    return review
