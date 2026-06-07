from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "Adaptive Web Vulnerability Scanner"
    request_timeout: float = 8.0
    max_depth: int = 1
    max_pages: int = 25
    max_workers: int = 8
    default_rate_limit_per_second: float = 3.0
    minimum_rate_limit_per_second: float = 0.5
    retry_attempts: int = 2
    retry_backoff_ms: int = 250
    enforce_authorization_for_external: bool = True
    enable_playwright_crawl: bool = True
    enable_api_discovery: bool = True
    enable_graphql_discovery: bool = True
    enable_behavioral_analysis: bool = True
    enable_finding_validator: bool = True
    enable_openapi_discovery: bool = True
    enable_directory_fuzzing: bool = True
    enable_safe_port_scan: bool = True
    enable_subdomain_recon: bool = True
    enable_ct_log_recon: bool = False
    enable_dns_analysis: bool = True
    enable_cloud_asset_recon: bool = True
    enable_screenshot_recon: bool = True
    max_requests: int = 10000
    playwright_timeout_ms: int = 10000
    playwright_render_wait_ms: int = 1200
    max_script_bundles: int = 6
    max_api_candidates: int = 30
    max_schema_fuzz_endpoints: int = 8
    enable_unsafe_state_changing_fuzz: bool = False
    default_max_detector_params: int = 6
    default_max_payloads_per_param: int = 2
    default_enable_login_route_probing: bool = False
    max_crawler_numeric_routes: int = 3
    safe_port_scan_ports: list[int] = [80, 443, 8000, 8080, 8443]
    directory_fuzz_paths: list[str] = [
        "/admin",
        "/debug",
        "/graphql",
        "/swagger",
        "/swagger.json",
        "/openapi.json",
        "/api",
        "/rest",
        "/login",
        "/upload",
    ]
    subdomain_candidates: list[str] = ["www", "api", "dev", "staging", "test", "admin"]
    cloud_bucket_suffixes: list[str] = ["", "-assets", "-static", "-media", "-uploads", "-backup"]
    max_schema_fuzz_cases_per_field: int = 4
    user_agent: str = "AdaptiveWebVulnScanner/0.1"
    database_url: str = f"sqlite:///{ROOT_DIR / 'scanner.db'}"
    redis_url: str = "redis://127.0.0.1:6379/0"
    queue_backend: str = "redis"
    worker_runtime: str = "celery"
    execution_mode: str = "local-dev"
    object_storage_backend: str = "local"
    object_storage_bucket: str = "adaptivescan-artifacts"
    telemetry_retention_days: int = 30
    evidence_retention_days: int = 365
    enable_prometheus_metrics: bool = True
    enable_opentelemetry: bool = False
    default_workspace_id: str = "local-workspace"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    enable_openvas_integration: bool = False
    openvas_host: str = "127.0.0.1"
    openvas_port: int = 9390
    openvas_username: str = "admin"
    openvas_password: str = "admin"
    # ── Security settings ─────────────────────────────────────────────────────
    adaptivescan_jwt_secret: str = ""   # Set ADAPTIVESCAN_JWT_SECRET in .env
    cookie_secure: bool = False          # True when serving over HTTPS
    adaptivescan_expose_docs: bool = True   # False in production
    adaptivescan_hsts: bool = False      # True when serving over HTTPS

    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
