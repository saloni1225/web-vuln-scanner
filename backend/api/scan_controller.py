from pydantic import BaseModel, Field, HttpUrl

from backend.core.scanner_engine import ScannerEngine
from backend.reports.report_generator import generate_html_report
from backend.reports.report_generator import generate_pdf_report


class ScanRequest(BaseModel):
    target_url: HttpUrl
    auth_headers: dict[str, str] | None = None
    auth_cookies: dict[str, str] | None = None
    jwt_token: str | None = None
    login_url: HttpUrl | None = None
    login_method: str | None = "post"
    username_field: str | None = "email"
    password_field: str | None = "password"
    username: str | None = None
    password: str | None = None
    login_extra_fields: dict[str, str] | None = None
    rate_limit_per_second: float | None = Field(default=None, ge=0.1, le=20.0)
    retry_attempts: int | None = Field(default=None, ge=0, le=5)
    retry_backoff_ms: int | None = Field(default=None, ge=0, le=5000)
    authorization_confirmed: bool = False
    domain_allowlist: list[str] | None = None
    detector_names: list[str] | None = None
    enable_api_fuzzing: bool = True
    enable_graphql_checks: bool = True
    enable_finding_validator: bool | None = None
    enable_openapi_discovery: bool | None = None


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
            "jwt_token": request.jwt_token or "",
            "login_url": str(request.login_url) if request.login_url else "",
            "login_method": request.login_method or "post",
            "username_field": request.username_field or "email",
            "password_field": request.password_field or "password",
            "username": request.username or "",
            "password": request.password or "",
            "login_extra_fields": request.login_extra_fields or {},
            "rate_limit_per_second": request.rate_limit_per_second,
            "retry_attempts": request.retry_attempts,
            "retry_backoff_ms": request.retry_backoff_ms,
            "authorization_confirmed": request.authorization_confirmed,
            "domain_allowlist": request.domain_allowlist or [],
        }
        scan_options = {
            "detector_names": request.detector_names or [],
            "enable_api_fuzzing": request.enable_api_fuzzing,
            "enable_graphql_checks": request.enable_graphql_checks,
            "enable_finding_validator": request.enable_finding_validator,
            "enable_openapi_discovery": request.enable_openapi_discovery,
        }
        return await self.engine.scan(
            str(request.target_url),
            scan_id=scan_id,
            progress_callback=progress_callback,
            auth_context=auth_context,
            scan_options=scan_options,
        )

    async def create_report_bundle(self, scan: dict[str, object]) -> dict[str, str | None]:
        html_path = generate_html_report(scan)
        pdf_path = await generate_pdf_report(scan, html_path=html_path)
        return {
            "html_path": str(html_path),
            "pdf_path": str(pdf_path) if pdf_path else None,
        }

    def create_report_urls(self, scan: dict[str, object]) -> dict[str, str | None]:
        return {
            "html": f"/exports/{scan['scan_id']}.html",
            "pdf": f"/exports/{scan['scan_id']}.pdf",
        }
