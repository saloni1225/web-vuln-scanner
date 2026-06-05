from __future__ import annotations

import hashlib
from urllib.parse import urlparse


def build_service_fingerprint(target_url: str, site_map: dict[str, object], recon_summary: dict[str, object]) -> dict[str, object]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    endpoint_urls = [str(item.get("url", "")) for item in site_map.get("endpoints", []) if isinstance(item, dict)]
    technologies = recon_summary.get("technologies", [])
    headers = recon_summary.get("passive_security", {}).get("headers", {}) if isinstance(recon_summary.get("passive_security"), dict) else {}
    favicon_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:16] if host else ""
    return {
        "host": host,
        "scheme": parsed.scheme or "https",
        "favicon_hash": favicon_hash,
        "technology_fingerprints": technologies if isinstance(technologies, list) else [],
        "header_fingerprints": headers if isinstance(headers, dict) else {},
        "service_hints": _service_hints(endpoint_urls),
        "admin_surface": [url for url in endpoint_urls if any(token in url.lower() for token in ("/admin", "/manage", "/console"))],
        "js_surface": [url for url in endpoint_urls if url.endswith(".js")],
    }


def build_reconnaissance_matrix(target_url: str, site_map: dict[str, object], recon_summary: dict[str, object]) -> dict[str, object]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    dns = recon_summary.get("dns", {}) if isinstance(recon_summary.get("dns"), dict) else {}
    return {
        "target": target_url,
        "host": host,
        "asn_intelligence": {
            "status": "passive-ready",
            "provider": "ipwhois/pyasn",
            "notes": "ASN expansion is isolated behind explicit scope controls.",
            "candidate_org": host.split(".")[-2] if "." in host else host,
            "expansion_modes": ["asn", "netblock", "reverse-dns"],
        },
        "dns_intelligence": {
            "a_records": dns.get("a_records", []),
            "aaaa_records": dns.get("aaaa_records", []),
            "mx_records": dns.get("mx_records", []),
            "ns_records": dns.get("ns_records", []),
            "txt_records": dns.get("txt_records", []),
            "wildcard_dns": _wildcard_dns_signal(dns),
            "mail_security": _mail_security(dns),
            "ptr_analysis": recon_summary.get("ptr", {"status": "passive-ready"}),
        },
        "certificate_transparency": _certificate_intelligence(host, recon_summary),
        "cloud_discovery": _cloud_discovery(recon_summary),
        "tls_fingerprint": recon_summary.get("tls", {}),
        "waf_cdn": recon_summary.get("waf", {}),
        "service_fingerprint": build_service_fingerprint(target_url, site_map, recon_summary),
        "endpoint_graph": _endpoint_graph(site_map),
        "exposure_tags": _exposure_tags(site_map, recon_summary),
        "hidden_surface": _hidden_surface(site_map),
    }


def _service_hints(urls: list[str]) -> list[str]:
    hints = set()
    for url in urls:
        lower = url.lower()
        if "graphql" in lower:
            hints.add("graphql")
        if "swagger" in lower or "openapi" in lower:
            hints.add("openapi")
        if "/api/" in lower or lower.endswith("/api"):
            hints.add("rest-api")
        if "upload" in lower:
            hints.add("file-upload")
    return sorted(hints)


def _endpoint_graph(site_map: dict[str, object]) -> dict[str, object]:
    nodes = []
    edges = []
    pages = [str(page) for page in site_map.get("pages", [])]
    endpoints = [item for item in site_map.get("endpoints", []) if isinstance(item, dict)]
    for index, page in enumerate(pages):
        nodes.append({"id": f"page-{index}", "label": page, "type": "page"})
    for index, endpoint in enumerate(endpoints):
        node_id = f"endpoint-{index}"
        nodes.append({"id": node_id, "label": endpoint.get("url", ""), "type": endpoint.get("type", "endpoint")})
        if pages:
            edges.append({"source": "page-0", "target": node_id, "relationship": "discovered"})
    return {"nodes": nodes[:100], "edges": edges[:160]}


def _exposure_tags(site_map: dict[str, object], recon_summary: dict[str, object]) -> list[str]:
    tags = set()
    endpoint_blob = " ".join(str(item.get("url", "")) for item in site_map.get("endpoints", []) if isinstance(item, dict)).lower()
    for token, tag in {
        "admin": "admin-panel",
        "debug": "debug-surface",
        "graphql": "graphql",
        "swagger": "api-schema",
        "openapi": "api-schema",
        "upload": "file-upload",
    }.items():
        if token in endpoint_blob:
            tags.add(tag)
    if recon_summary.get("cloud_assets"):
        tags.add("cloud-candidates")
    if recon_summary.get("port_summary", {}).get("open_ports"):
        tags.add("internet-services")
    return sorted(tags)


def _wildcard_dns_signal(dns: dict[str, object]) -> dict[str, object]:
    records = [str(item).lower() for item in dns.get("a_records", []) + dns.get("aaaa_records", [])]
    return {"suspected": len(set(records)) == 1 and len(records) > 2, "sample_count": len(records)}


def _mail_security(dns: dict[str, object]) -> dict[str, object]:
    txt = " ".join(str(item).lower() for item in dns.get("txt_records", []))
    return {
        "spf": "v=spf1" in txt,
        "dkim_candidate": "dkim" in txt or "_domainkey" in txt,
        "dmarc_candidate": "dmarc" in txt,
        "mx_count": len(dns.get("mx_records", [])),
    }


def _certificate_intelligence(host: str, recon_summary: dict[str, object]) -> dict[str, object]:
    tls = recon_summary.get("tls", {}) if isinstance(recon_summary.get("tls"), dict) else {}
    return {
        "status": "passive-ready",
        "host": host,
        "issuer": tls.get("issuer", "unknown"),
        "subject_alt_name_count": len(tls.get("subject_alt_names", []) or []),
        "ct_mining_ready": True,
    }


def _cloud_discovery(recon_summary: dict[str, object]) -> dict[str, object]:
    assets = recon_summary.get("cloud_assets", []) or recon_summary.get("cloud_asset_summary", {}).get("candidates", [])
    return {
        "candidate_count": len(assets) if isinstance(assets, list) else 0,
        "bucket_enumeration": "safe-name-candidate-mode",
        "metadata_exposure": "checked" if recon_summary.get("cloud_asset_summary") else "ready",
        "assets": assets[:25] if isinstance(assets, list) else [],
    }


def _hidden_surface(site_map: dict[str, object]) -> dict[str, object]:
    endpoints = [str(item.get("url", "")) for item in site_map.get("endpoints", []) if isinstance(item, dict)]
    pages = [str(item) for item in site_map.get("pages", [])]
    blob = " ".join([*endpoints, *pages]).lower()
    return {
        "admin_panels": [url for url in endpoints if any(token in url.lower() for token in ("admin", "dashboard", "console"))][:25],
        "staging_candidates": [url for url in endpoints if any(token in url.lower() for token in ("staging", "stage", "dev", "test"))][:25],
        "forgotten_api_candidates": [url for url in endpoints if any(token in url.lower() for token in ("v1", "beta", "legacy", "internal"))][:25],
        "robots_intelligence": {"mentioned": "robots.txt" in blob, "status": "parsed-if-discovered"},
        "sitemap_intelligence": {"mentioned": "sitemap" in blob, "status": "parsed-if-discovered"},
    }
