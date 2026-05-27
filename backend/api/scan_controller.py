from pydantic import BaseModel, Field, HttpUrl

from backend.core.risk_gate import evaluate_risk_gate
from backend.core.scanner_engine import ScannerEngine
from backend.integrations.alerts import send_scan_alerts
from backend.reports.report_generator import generate_html_report
from backend.reports.report_generator import generate_pdf_report
from backend.reports.report_generator import generate_evidence_bundle


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
    role_name: str | None = "default"
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
    scan_profile: str | None = "deep"
    enable_directory_fuzzing: bool | None = None
    enable_unsafe_state_changing_fuzz: bool | None = None
    enable_safe_port_scan: bool | None = None
    enable_subdomain_recon: bool | None = None
    enable_dns_analysis: bool | None = None
    enable_cloud_asset_recon: bool | None = None
    enable_screenshot_recon: bool | None = None
    fail_on_high: bool = True
    max_high_severity: int = Field(default=0, ge=0)
    max_medium_severity: int | None = Field(default=None, ge=0)
    max_total_findings: int | None = Field(default=None, ge=0)
    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None


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
            "role_name": request.role_name or "default",
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
            "scan_profile": request.scan_profile or "deep",
            "enable_directory_fuzzing": request.enable_directory_fuzzing,
            "enable_unsafe_state_changing_fuzz": request.enable_unsafe_state_changing_fuzz,
            "enable_safe_port_scan": request.enable_safe_port_scan,
            "enable_subdomain_recon": request.enable_subdomain_recon,
            "enable_dns_analysis": request.enable_dns_analysis,
            "enable_cloud_asset_recon": request.enable_cloud_asset_recon,
            "enable_screenshot_recon": request.enable_screenshot_recon,
        }
        result = await self.engine.scan(
            str(request.target_url),
            scan_id=scan_id,
            progress_callback=progress_callback,
            auth_context=auth_context,
            scan_options=scan_options,
        )
        result["risk_gate"] = evaluate_risk_gate(
            result.get("summary", {}),
            fail_on_high=request.fail_on_high,
            max_high=request.max_high_severity,
            max_medium=request.max_medium_severity,
            max_total=request.max_total_findings,
        )
        result["alert_delivery"] = await send_scan_alerts(
            result,
            slack_webhook_url=request.slack_webhook_url,
            discord_webhook_url=request.discord_webhook_url,
        )
        return result

    async def create_report_bundle(self, scan: dict[str, object]) -> dict[str, str | None]:
        html_path = generate_html_report(scan)
        evidence_path = generate_evidence_bundle(scan)
        pdf_path = await generate_pdf_report(scan, html_path=html_path)
        return {
            "html_path": str(html_path),
            "pdf_path": str(pdf_path) if pdf_path else None,
            "evidence_path": str(evidence_path),
        }

    def create_report_urls(self, scan: dict[str, object]) -> dict[str, str | None]:
        return {
            "html": f"/exports/{scan['scan_id']}.html",
            "pdf": f"/exports/{scan['scan_id']}.pdf",
            "evidence": f"/exports/{scan['scan_id']}.evidence.json",
        }
