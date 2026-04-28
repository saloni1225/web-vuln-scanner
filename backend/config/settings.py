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
    enable_screenshot_recon: bool = True
    max_requests: int = 10000
    playwright_timeout_ms: int = 10000
    playwright_render_wait_ms: int = 1200
    max_script_bundles: int = 6
    max_api_candidates: int = 30
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
    max_schema_fuzz_cases_per_field: int = 4
    user_agent: str = "AdaptiveWebVulnScanner/0.1"
    database_url: str = f"sqlite:///{ROOT_DIR / 'scanner.db'}"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
