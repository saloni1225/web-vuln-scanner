import asyncio
import json
import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


REPORT_DIR = Path(__file__).resolve().parent
EXPORT_DIR = REPORT_DIR / "exports"
logger = logging.getLogger(__name__)


def generate_html_report(scan: dict[str, object]) -> Path:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(REPORT_DIR / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    html = env.get_template("report_template.html").render(scan=scan)
    output = EXPORT_DIR / f"{scan['scan_id']}.html"
    output.write_text(html, encoding="utf-8")
    return output


def generate_evidence_bundle(scan: dict[str, object]) -> Path:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    output = EXPORT_DIR / f"{scan['scan_id']}.evidence.json"
    bundle = {
        "scan_id": scan.get("scan_id"),
        "target_url": scan.get("target_url"),
        "summary": scan.get("summary", {}),
        "findings": scan.get("findings", []),
        "replay_plans": [finding.get("replay_plan") for finding in scan.get("findings", []) if isinstance(finding, dict) and finding.get("replay_plan")],
        "attack_surface_inventory": scan.get("attack_surface_inventory", {}),
        "api_security_summary": scan.get("api_security_summary", {}),
        "validation_summary": scan.get("validation_summary", {}),
        "compliance_summary": scan.get("compliance_summary", {}),
        "ai_risk_summary": scan.get("ai_risk_summary", {}),
        "telemetry_summary": scan.get("telemetry_summary", {}),
    }
    output.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return output


async def generate_pdf_report(scan: dict[str, object], html_path: Path | None = None) -> Path | None:
    html_path = html_path or generate_html_report(scan)
    pdf_path = EXPORT_DIR / f"{scan['scan_id']}.pdf"
    try:
        return await asyncio.to_thread(_generate_pdf_report_sync, html_path, pdf_path)
    except Exception as exc:
        logger.warning("PDF report generation failed for scan %s: %s", scan.get("scan_id"), exc)
        return None


def _generate_pdf_report_sync(html_path: Path, pdf_path: Path) -> Path:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.goto(html_path.resolve().as_uri(), wait_until="networkidle")
            page.pdf(
                path=str(pdf_path),
                format="A4",
                margin={"top": "14mm", "right": "10mm", "bottom": "14mm", "left": "10mm"},
                print_background=True,
            )
        finally:
            browser.close()
    return pdf_path
