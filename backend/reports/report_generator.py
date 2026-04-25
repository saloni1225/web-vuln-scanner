from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


REPORT_DIR = Path(__file__).resolve().parent
EXPORT_DIR = REPORT_DIR / "exports"


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


async def generate_pdf_report(scan: dict[str, object], html_path: Path | None = None) -> Path | None:
    html_path = html_path or generate_html_report(scan)
    pdf_path = EXPORT_DIR / f"{scan['scan_id']}.pdf"
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(html_path.resolve().as_uri(), wait_until="networkidle")
        await page.pdf(
            path=str(pdf_path),
            format="A4",
            margin={"top": "14mm", "right": "10mm", "bottom": "14mm", "left": "10mm"},
            print_background=True,
        )
        await browser.close()
    return pdf_path
