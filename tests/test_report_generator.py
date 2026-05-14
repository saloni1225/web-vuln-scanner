import asyncio

from backend.reports import report_generator


def test_generate_pdf_report_returns_none_when_playwright_cannot_start(monkeypatch, tmp_path):
    def fail_to_generate(*args):
        raise NotImplementedError

    monkeypatch.setattr(report_generator, "_generate_pdf_report_sync", fail_to_generate)

    result = asyncio.run(
        report_generator.generate_pdf_report(
            {"scan_id": "scan-with-selector-loop"},
            html_path=tmp_path / "report.html",
        )
    )

    assert result is None
