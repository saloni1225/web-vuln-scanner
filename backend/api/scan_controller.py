from pydantic import BaseModel, HttpUrl

from backend.core.scanner_engine import ScannerEngine
from backend.reports.report_generator import generate_html_report


class ScanRequest(BaseModel):
    target_url: HttpUrl
    auth_headers: dict[str, str] | None = None
    auth_cookies: dict[str, str] | None = None


class ScanController:
    def __init__(self) -> None:
        self.engine = ScannerEngine()

    async def start_scan(
        self,
        request: ScanRequest,
        scan_id: str | None = None,
        progress_callback=None,
    ) -> dict[str, object]:
        auth_context = {
            "headers": request.auth_headers or {},
            "cookies": request.auth_cookies or {},
        }
        return await self.engine.scan(
            str(request.target_url),
            scan_id=scan_id,
            progress_callback=progress_callback,
            auth_context=auth_context,
        )

    def create_report(self, scan: dict[str, object]) -> str:
        return str(generate_html_report(scan))

    def create_report_url(self, scan: dict[str, object]) -> str:
        return f"/exports/{scan['scan_id']}.html"
