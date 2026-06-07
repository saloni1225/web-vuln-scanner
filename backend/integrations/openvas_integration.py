"""OpenVAS Integration — Orchestrate GVM/OpenVAS scans and merge into findings.

Graceful fallback: Works without OpenVAS; scanner simply skips enrichment.
"""
from __future__ import annotations
import logging
from backend.detection.base_detector import Finding

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Log": "low"}


def is_openvas_available(settings) -> bool:
    """Check if OpenVAS/GVM is configured and reachable."""
    if not getattr(settings, "enable_openvas_integration", False):
        return False
    try:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp
        conn = TLSConnection(
            hostname=getattr(settings, "openvas_host", "127.0.0.1"),
            port=int(getattr(settings, "openvas_port", 9390)),
        )
        with Gmp(connection=conn) as gmp:
            gmp.authenticate(
                getattr(settings, "openvas_username", "admin"),
                getattr(settings, "openvas_password", "admin"),
            )
            return True
    except Exception as exc:
        logger.debug("OpenVAS not available: %s", exc)
        return False


async def run_openvas_scan(target_url: str, settings) -> list[Finding]:
    """Run an OpenVAS scan against the target and return normalized findings.

    Returns an empty list if OpenVAS is not available or not configured.
    """
    if not getattr(settings, "enable_openvas_integration", False):
        return []

    try:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform
        from lxml import etree
        import uuid
    except ImportError:
        logger.info("python-gvm or lxml not installed — skipping OpenVAS integration.")
        return []

    host = getattr(settings, "openvas_host", "127.0.0.1")
    port = int(getattr(settings, "openvas_port", 9390))
    user = getattr(settings, "openvas_username", "admin")
    pw = getattr(settings, "openvas_password", "admin")

    try:
        conn = TLSConnection(hostname=host, port=port)
        transform = EtreeTransform()
        findings: list[Finding] = []

        with Gmp(connection=conn, transform=transform) as gmp:
            gmp.authenticate(user, pw)

            # Create target
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            target_host = parsed.hostname or target_url
            target_name = f"adaptivescan-{uuid.uuid4().hex[:8]}"
            target_resp = gmp.create_target(name=target_name, hosts=[target_host])
            target_id = target_resp.get("id", "")
            if not target_id:
                logger.warning("Failed to create OpenVAS target.")
                return []

            # Get default scan config (Full and fast)
            configs = gmp.get_scan_configs()
            config_id = ""
            for cfg in configs.findall(".//config"):
                name = cfg.findtext("name", "")
                if "full and fast" in name.lower():
                    config_id = cfg.get("id", "")
                    break
            if not config_id:
                config_id = "daba56c8-73ec-11df-a475-002264764cea"  # Default UUID

            # Get default scanner
            scanners = gmp.get_scanners()
            scanner_id = ""
            for s in scanners.findall(".//scanner"):
                if "openvas" in s.findtext("name", "").lower():
                    scanner_id = s.get("id", "")
                    break
            if not scanner_id:
                scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"

            # Create and start task
            task_resp = gmp.create_task(
                name=f"AdaptiveScan-{target_name}",
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            task_id = task_resp.get("id", "")
            if not task_id:
                logger.warning("Failed to create OpenVAS task.")
                return []

            gmp.start_task(task_id)
            logger.info("OpenVAS task %s started for %s", task_id, target_host)

            # Poll for completion (with timeout)
            import asyncio
            for _ in range(60):  # Max 30 minutes
                await asyncio.sleep(30)
                task = gmp.get_task(task_id)
                status = task.findtext(".//status", "")
                if status in ("Done", "Stopped"):
                    break

            # Get results
            report_id = ""
            task = gmp.get_task(task_id)
            for report_el in task.findall(".//report"):
                report_id = report_el.get("id", "")
                break

            if report_id:
                report = gmp.get_report(report_id)
                for result in report.findall(".//result"):
                    name = result.findtext("name", "Unknown")
                    description = result.findtext("description", "")
                    threat = result.findtext("threat", "Low")
                    host_val = result.findtext("host", target_host)
                    port_val = result.findtext("port", "")
                    nvt = result.find("nvt")
                    cve = ""
                    if nvt is not None:
                        refs = nvt.findall(".//ref")
                        for ref in refs:
                            if ref.get("type") == "cve":
                                cve = ref.get("id", "")
                                break

                    findings.append(Finding(
                        detector="openvas",
                        severity=_SEVERITY_MAP.get(threat, "low"),
                        url=f"{target_url} ({host_val}:{port_val})" if port_val else target_url,
                        evidence=f"[OpenVAS] {name}: {description[:300]}",
                        recommendation="Review OpenVAS finding and apply vendor-recommended patches or mitigations.",
                        confidence="medium",
                        category="network-vuln",
                        validation_state="requires-review",
                        reason=f"OpenVAS NVT detection: {name}",
                        cwe_id=cve if cve else None,
                    ))

            # Cleanup
            try:
                gmp.delete_task(task_id)
                gmp.delete_target(target_id)
            except Exception:
                pass

        return findings

    except Exception as exc:
        logger.warning("OpenVAS scan failed: %s", exc)
        return []
