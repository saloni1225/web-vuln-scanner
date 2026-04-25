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
