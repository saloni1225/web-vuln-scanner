import asyncio
import base64
import hashlib
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

from backend.config.settings import ROOT_DIR, settings


TECH_SIGNATURES = {
    "react": ["react", "__react", "data-reactroot"],
    "vue": ["vue", "__vue__"],
    "angular": ["ng-version", "angular"],
    "next.js": ["__next_data__", "_next/static"],
    "wordpress": ["wp-content", "wp-json"],
    "django": ["csrftoken", "django"],
    "express": ["x-powered-by: express", "express"],
    "cloudflare": ["cf-ray", "cloudflare"],
}

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare"],
    "AWS WAF": ["x-amzn-waf", "awselb", "x-amz-cf"],
    "Akamai": ["akamai", "akamai-ghost"],
    "Imperva": ["incap_ses", "visid_incap"],
    "F5 BIG-IP": ["bigip", "f5"],
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS is missing; add Strict-Transport-Security on HTTPS responses.",
    "content-security-policy": "CSP is missing; add a restrictive Content-Security-Policy.",
    "x-content-type-options": "X-Content-Type-Options is missing; set nosniff.",
    "x-frame-options": "X-Frame-Options is missing; set DENY or SAMEORIGIN.",
    "referrer-policy": "Referrer-Policy is missing; set a privacy-preserving policy.",
}

RISK_KEYWORDS = {
    "critical": ["admin", "debug", "graphql", "swagger", "openapi", "config", "backup"],
    "high": ["login", "auth", "token", "upload", "account", "profile", "settings"],
    "medium": ["api", "rest", "search", "user", "order", "cart"],
}


async def run_recon(
    target_url: str,
    request_handler,
    site_map: dict[str, object],
    scan_id: str,
    scan_options: dict[str, object],
) -> dict[str, object]:
    response = await request_handler.get(target_url)
    headers = {key.lower(): value for key, value in response.headers.items()}
    body = response.text or ""
    directory_results = []

    if scan_options.get("enable_directory_fuzzing", settings.enable_directory_fuzzing):
        directory_results = await _probe_directories(target_url, request_handler)

    return {
        "passive_security": analyze_passive_security(headers),
        "technology_fingerprint": fingerprint_technology(headers, body),
        "waf_detection": detect_waf(headers),
        "dns_analysis": await analyze_dns(target_url) if scan_options.get("enable_dns_analysis", settings.enable_dns_analysis) else {"mode": "disabled"},
        "web_intelligence": await collect_web_intelligence(target_url, request_handler),
        "tls_summary": await inspect_tls(target_url),
        "port_summary": await scan_common_ports(target_url) if scan_options.get("enable_safe_port_scan", settings.enable_safe_port_scan) else {"mode": "disabled", "open_ports": []},
        "subdomain_summary": await enumerate_subdomains(target_url, request_handler, bool(scan_options.get("enable_ct_log_recon", settings.enable_ct_log_recon))) if scan_options.get("enable_subdomain_recon", settings.enable_subdomain_recon) else {"mode": "disabled", "candidates": [], "resolved": []},
        "cloud_asset_summary": await probe_cloud_assets(target_url, request_handler) if scan_options.get("enable_cloud_asset_recon", settings.enable_cloud_asset_recon) else {"mode": "disabled", "candidates": [], "exposed": []},
        "directory_fuzzing": directory_results,
        "screenshot_recon": await capture_screenshot(target_url, scan_id) if scan_options.get("enable_screenshot_recon", settings.enable_screenshot_recon) else {"status": "disabled"},
        "endpoint_risk_ranking": rank_endpoint_risk(site_map, directory_results),
    }


async def analyze_dns(target_url: str) -> dict[str, object]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host or _is_local_host(host):
        return {"mode": "passive-dns", "host": host, "addresses": [], "reverse_dns": [], "reason": "DNS analysis skipped for local targets."}

    def _resolve() -> dict[str, object]:
        records = socket.getaddrinfo(host, None)
        addresses = sorted({item[4][0] for item in records})
        reverse_dns = []
        for address in addresses[:6]:
            try:
                reverse_dns.append({"address": address, "name": socket.gethostbyaddr(address)[0]})
            except Exception:
                reverse_dns.append({"address": address, "name": ""})
        rich_records = _resolve_rich_dns_records(host)
        return {
            "mode": "passive-dns",
            "host": host,
            "addresses": addresses[:12],
            "a_records": [address for address in addresses if ":" not in address][:12],
            "aaaa_records": [address for address in addresses if ":" in address][:12],
            "mx_records": rich_records["mx_records"],
            "ns_records": rich_records["ns_records"],
            "txt_records": rich_records["txt_records"],
            "address_count": len(addresses),
            "reverse_dns": reverse_dns,
            "has_ipv6": any(":" in address for address in addresses),
            "asn_enrichment": _build_asn_enrichment(addresses),
        }

    try:
        return await asyncio.to_thread(_resolve)
    except Exception as exc:
        return {"mode": "passive-dns", "host": host, "addresses": [], "reverse_dns": [], "error": str(exc)}


async def collect_web_intelligence(target_url: str, request_handler) -> dict[str, object]:
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    robots = await _fetch_optional_text(urljoin(base, "/robots.txt"), request_handler)
    sitemap = await _fetch_optional_text(urljoin(base, "/sitemap.xml"), request_handler)
    favicon = await _fetch_optional_binary(urljoin(base, "/favicon.ico"), request_handler)
    source_maps = await _discover_source_maps(target_url, request_handler)
    return {
        "robots": analyze_robots(robots.get("text", ""), robots),
        "sitemap": analyze_sitemap(sitemap.get("text", ""), sitemap),
        "favicon": fingerprint_favicon(favicon.get("content", b""), favicon),
        "source_maps": source_maps,
    }


def analyze_robots(text: str, metadata: dict[str, object] | None = None) -> dict[str, object]:
    disallow = []
    allow = []
    sitemap_urls = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        if key.lower() == "disallow" and value:
            disallow.append(value)
        if key.lower() == "allow" and value:
            allow.append(value)
        if key.lower() == "sitemap" and value:
            sitemap_urls.append(value)
    return {
        "status": metadata.get("status_code") if metadata else None,
        "disallow": disallow[:100],
        "allow": allow[:100],
        "sitemaps": sitemap_urls[:25],
        "sensitive_paths": [path for path in disallow if any(token in path.lower() for token in ("admin", "debug", "backup", "config", "private"))],
    }


def analyze_sitemap(text: str, metadata: dict[str, object] | None = None) -> dict[str, object]:
    urls = re.findall(r"<loc>(.*?)</loc>", text, flags=re.IGNORECASE)
    return {
        "status": metadata.get("status_code") if metadata else None,
        "url_count": len(urls),
        "urls": urls[:100],
        "api_like_urls": [url for url in urls if any(token in url.lower() for token in ("/api", "graphql", "swagger", "openapi"))][:50],
    }


def fingerprint_favicon(content: bytes, metadata: dict[str, object] | None = None) -> dict[str, object]:
    if not content:
        return {"status": metadata.get("status_code") if metadata else None, "available": False, "sha256": "", "mmh3_compatible_b64_length": 0}
    encoded = base64.encodebytes(content)
    return {
        "status": metadata.get("status_code") if metadata else None,
        "available": True,
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha256_short": hashlib.sha256(content).hexdigest()[:16],
        "mmh3_compatible_b64_length": len(encoded),
    }


async def _discover_source_maps(target_url: str, request_handler) -> dict[str, object]:
    try:
        response = await request_handler.get(target_url)
    except Exception as exc:
        return {"status": "failed", "reason": str(exc), "candidates": []}
    script_urls = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", response.text, flags=re.IGNORECASE)
    candidates = []
    for script in script_urls[: settings.max_script_bundles]:
        script_url = urljoin(str(response.url), script)
        map_url = f"{script_url}.map"
        metadata = await _fetch_optional_text(map_url, request_handler)
        if metadata.get("status_code") and int(metadata["status_code"]) < 400:
            candidates.append(
                {
                    "script": script_url,
                    "source_map": map_url,
                    "status_code": metadata["status_code"],
                    "contains_sources": '"sources"' in str(metadata.get("text", ""))[:5000],
                }
            )
    return {"status": "completed", "candidate_count": len(candidates), "candidates": candidates}


async def _fetch_optional_text(url: str, request_handler) -> dict[str, object]:
    try:
        response = await request_handler.get(url)
        if response.status_code >= 500:
            return {"url": url, "status_code": response.status_code, "text": ""}
        return {"url": url, "status_code": response.status_code, "text": response.text or ""}
    except Exception as exc:
        return {"url": url, "status_code": None, "text": "", "error": str(exc)}


async def _fetch_optional_binary(url: str, request_handler) -> dict[str, object]:
    try:
        response = await request_handler.get(url)
        content = response.content if hasattr(response, "content") else (response.text or "").encode("utf-8")
        if response.status_code >= 400:
            content = b""
        return {"url": url, "status_code": response.status_code, "content": content}
    except Exception as exc:
        return {"url": url, "status_code": None, "content": b"", "error": str(exc)}


def _resolve_rich_dns_records(host: str) -> dict[str, list[str]]:
    records = {"mx_records": [], "ns_records": [], "txt_records": []}
    try:
        import dns.resolver
    except Exception:
        return records
    for record_type, key in (("MX", "mx_records"), ("NS", "ns_records"), ("TXT", "txt_records")):
        try:
            answers = dns.resolver.resolve(host, record_type, lifetime=3)
            records[key] = [str(answer).strip('"') for answer in answers][:20]
        except Exception:
            records[key] = []
    return records


def _build_asn_enrichment(addresses: list[str]) -> dict[str, object]:
    public_addresses = [address for address in addresses if ":" not in address][:4]
    if not public_addresses:
        return {"mode": "unavailable", "results": []}
    results = []
    try:
        from ipwhois import IPWhois
    except Exception:
        return {"mode": "library-unavailable", "results": [{"address": address} for address in public_addresses]}
    for address in public_addresses:
        try:
            payload = IPWhois(address).lookup_rdap(depth=0)
            results.append(
                {
                    "address": address,
                    "asn": payload.get("asn", ""),
                    "asn_description": payload.get("asn_description", ""),
                    "network_name": payload.get("network", {}).get("name", "") if isinstance(payload.get("network"), dict) else "",
                }
            )
        except Exception:
            results.append({"address": address, "asn": "", "asn_description": ""})
    return {"mode": "rdap", "results": results}


async def probe_cloud_assets(target_url: str, request_handler) -> dict[str, object]:
    candidates = build_cloud_storage_candidates(target_url)
    exposed = []
    for candidate in candidates:
        try:
            response = await request_handler.get(candidate["url"])
        except Exception:
            continue
        if response.status_code not in {401, 403, 404, 410} and response.status_code < 500:
            exposed.append(
                {
                    **candidate,
                    "status_code": response.status_code,
                    "content_length": len(response.text or ""),
                }
            )
    return {
        "mode": "passive-cloud-candidates",
        "candidates": candidates,
        "candidate_count": len(candidates),
        "exposed": exposed,
        "exposed_count": len(exposed),
    }


def build_cloud_storage_candidates(target_url: str) -> list[dict[str, str]]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host or _is_local_host(host) or "." not in host:
        return []
    root = ".".join(host.split(".")[-2:])
    org = root.split(".")[0].replace("-", "").replace("_", "")
    names = []
    for base in {root.replace(".", "-"), org}:
        for suffix in settings.cloud_bucket_suffixes:
            names.append(f"{base}{suffix}")
    candidates = []
    for name in sorted(set(names)):
        candidates.extend(
            [
                {"provider": "aws-s3", "name": name, "url": f"https://{name}.s3.amazonaws.com/"},
                {"provider": "gcp-storage", "name": name, "url": f"https://storage.googleapis.com/{name}/"},
                {"provider": "azure-blob", "name": name, "url": f"https://{name}.blob.core.windows.net/"},
            ]
        )
    return candidates[:36]


def analyze_passive_security(headers: dict[str, str]) -> dict[str, object]:
    missing = [
        {"header": header, "recommendation": recommendation}
        for header, recommendation in SECURITY_HEADERS.items()
        if header not in headers
    ]
    cookie_flags = []
    for key, value in headers.items():
        if key == "set-cookie":
            lowered = value.lower()
            cookie_flags.append(
                {
                    "secure": "secure" in lowered,
                    "httponly": "httponly" in lowered,
                    "samesite": "samesite" in lowered,
                }
            )
    server_disclosure = headers.get("server") or headers.get("x-powered-by") or ""
    score = max(0, 100 - len(missing) * 12 - (10 if server_disclosure else 0))
    return {
        "score": score,
        "missing_headers": missing,
        "cookie_flags": cookie_flags,
        "server_disclosure": server_disclosure,
    }


def fingerprint_technology(headers: dict[str, str], body: str) -> dict[str, object]:
    haystack = "\n".join([f"{key}: {value}" for key, value in headers.items()]).lower() + "\n" + body.lower()
    matches = [
        {"technology": name, "evidence": signature}
        for name, signatures in TECH_SIGNATURES.items()
        for signature in signatures
        if signature in haystack
    ]
    unique = {}
    for match in matches:
        unique.setdefault(match["technology"], match)
    return {
        "technologies": list(unique.values()),
        "count": len(unique),
    }


def detect_waf(headers: dict[str, str]) -> dict[str, object]:
    haystack = "\n".join([f"{key}: {value}" for key, value in headers.items()]).lower()
    matches = [
        {"name": name, "confidence": "medium", "evidence": signature}
        for name, signatures in WAF_SIGNATURES.items()
        for signature in signatures
        if signature in haystack
    ]
    return {
        "detected": bool(matches),
        "matches": matches,
    }


async def inspect_tls(target_url: str) -> dict[str, object]:
    parsed = urlparse(target_url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"enabled": False, "reason": "Target is not HTTPS."}
    port = parsed.port or 443

    def _inspect() -> dict[str, object]:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                cert = tls.getpeercert()
                return {
                    "enabled": True,
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else "",
                    "certificate_subject": cert.get("subject", []),
                    "certificate_issuer": cert.get("issuer", []),
                    "not_after": cert.get("notAfter", ""),
                }

    try:
        return await asyncio.to_thread(_inspect)
    except Exception as exc:
        return {"enabled": False, "reason": str(exc)}


async def scan_common_ports(target_url: str) -> dict[str, object]:
    parsed = urlparse(target_url)
    if not parsed.hostname:
        return {"mode": "safe-tcp-connect", "open_ports": [], "error": "No hostname parsed."}

    async def _check(port: int) -> dict[str, object] | None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(parsed.hostname, port), timeout=1.2)
            banner = await _grab_banner(reader, writer, parsed.hostname or "", port)
            writer.close()
            await writer.wait_closed()
            return {"port": port, "state": "open", "service_hint": _service_hint(port), "banner": banner}
        except Exception:
            return None

    results = await asyncio.gather(*[_check(port) for port in settings.safe_port_scan_ports])
    return {
        "mode": "safe-tcp-connect",
        "ports_tested": settings.safe_port_scan_ports,
        "open_ports": [item for item in results if item],
    }


async def enumerate_subdomains(target_url: str, request_handler=None, include_ct_logs: bool = False) -> dict[str, object]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host or _is_local_host(host) or host.count(".") < 1:
        return {"mode": "passive-local", "candidates": [], "resolved": [], "reason": "Subdomain recon skipped for local targets."}
    root = ".".join(host.split(".")[-2:])
    candidates = [f"{word}.{root}" for word in settings.subdomain_candidates]
    ct_candidates = await _query_ct_logs(root, request_handler) if include_ct_logs and request_handler else []
    candidates = sorted(set([*candidates, *ct_candidates]))

    async def _resolve(candidate: str) -> dict[str, object] | None:
        try:
            records = await asyncio.to_thread(socket.getaddrinfo, candidate, None)
            addresses = sorted({item[4][0] for item in records})
            return {"host": candidate, "addresses": addresses[:4]}
        except Exception:
            return None

    resolved = await asyncio.gather(*[_resolve(candidate) for candidate in candidates])
    return {
        "mode": "passive-dns-wordlist",
        "candidates": candidates,
        "ct_log_candidate_count": len(ct_candidates),
        "resolved": [item for item in resolved if item],
    }


async def _query_ct_logs(root_domain: str, request_handler) -> list[str]:
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    try:
        response = await request_handler.get(url)
        payload = json.loads(response.text)
    except Exception:
        return []
    candidates: set[str] = set()
    if not isinstance(payload, list):
        return []
    for row in payload[:250]:
        if not isinstance(row, dict):
            continue
        name_value = str(row.get("name_value", ""))
        for host in name_value.splitlines():
            normalized = host.lower().strip("*. ")
            if normalized.endswith(root_domain):
                candidates.add(normalized)
    return sorted(candidates)[:50]


async def capture_screenshot(target_url: str, scan_id: str) -> dict[str, object]:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return {"status": "unavailable", "reason": "Playwright is not installed."}

    screenshot_dir = ROOT_DIR / "backend" / "reports" / "exports" / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = screenshot_dir / f"{scan_id}.png"
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1440, "height": 900})
            await page.goto(target_url, wait_until="networkidle", timeout=settings.playwright_timeout_ms)
            title = await page.title()
            login_hints = await page.locator("input[type='password'], form[action*='login' i]").count()
            await page.screenshot(path=str(screenshot_path), full_page=True)
            await browser.close()
        return {
            "status": "captured",
            "path": str(screenshot_path),
            "url": f"/exports/screenshots/{scan_id}.png",
            "page_title": title,
            "login_surface_detected": login_hints > 0,
        }
    except Exception as exc:
        return {"status": "failed", "reason": str(exc)}


def rank_endpoint_risk(site_map: dict[str, object], directory_results: list[dict[str, object]] | None = None) -> list[dict[str, object]]:
    candidates = []
    for endpoint in site_map.get("endpoints", []):
        if isinstance(endpoint, dict):
            candidates.append({"url": str(endpoint.get("url", "")), "source": str(endpoint.get("source", "crawler")), "method": str(endpoint.get("method", "GET"))})
    for page in site_map.get("pages", []):
        candidates.append({"url": str(page), "source": "page", "method": "GET"})
    for item in directory_results or []:
        candidates.append({"url": str(item.get("url", "")), "source": "directory-fuzzing", "method": "GET"})

    ranked = []
    seen = set()
    for candidate in candidates:
        url = candidate["url"]
        if not url or url in seen:
            continue
        seen.add(url)
        lowered = url.lower()
        score = 10
        reasons = []
        for severity, words in RISK_KEYWORDS.items():
            for word in words:
                if word in lowered:
                    weight = {"critical": 35, "high": 25, "medium": 15}[severity]
                    score += weight
                    reasons.append(f"{word} keyword")
        if "?" in url:
            score += 15
            reasons.append("parameterized")
        if candidate["source"] in {"script", "directory-fuzzing", "openapi"}:
            score += 10
            reasons.append(f"{candidate['source']} source")
        ranked.append({**candidate, "risk_score": min(100, score), "reasons": reasons or ["standard surface"]})
    return sorted(ranked, key=lambda item: item["risk_score"], reverse=True)[:25]


async def _probe_directories(target_url: str, request_handler) -> list[dict[str, object]]:
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    results = []
    for path in settings.directory_fuzz_paths:
        url = urljoin(base, path)
        try:
            response = await request_handler.get(url)
        except Exception:
            continue
        if response.status_code < 500 and response.status_code not in {404, 410}:
            results.append(
                {
                    "url": url,
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": len(response.text or ""),
                }
            )
    return results


def build_replay_plan(finding: dict[str, object]) -> dict[str, object]:
    method = str(finding.get("method") or "GET").upper()
    url = str(finding.get("url") or "")
    parameter = str(finding.get("parameter") or "")
    payload = str(finding.get("payload") or "")
    return {
        "method": method,
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "curl": _curl_preview(method, url, parameter, payload),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "note": "Replay plans are generated for authorized validation only and are not auto-executed by the API.",
    }


def _curl_preview(method: str, url: str, parameter: str, payload: str) -> str:
    if method == "GET" and parameter:
        separator = "&" if "?" in url else "?"
        return f"curl -i '{url}{separator}{parameter}={payload}'"
    if parameter:
        return f"curl -i -X {method} '{url}' --data-urlencode '{parameter}={payload}'"
    return f"curl -i -X {method} '{url}'"


def _service_hint(port: int) -> str:
    return {
        80: "http",
        443: "https",
        8000: "dev-http",
        8080: "proxy-or-dev-http",
        8443: "alt-https",
    }.get(port, "unknown")


async def _grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int) -> str:
    try:
        if port in {80, 8000, 8080}:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore"))
            await writer.drain()
        data = await asyncio.wait_for(reader.read(160), timeout=0.8)
        return data.decode("utf-8", errors="ignore").strip().replace("\r", " ").replace("\n", " ")[:160]
    except Exception:
        return ""


def _is_local_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"} or host.startswith("192.168.") or host.startswith("10.")
