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
    enable_playwright_crawl: bool = True
    playwright_timeout_ms: int = 10000
    playwright_render_wait_ms: int = 1200
    max_script_bundles: int = 6
    user_agent: str = "AdaptiveWebVulnScanner/0.1"
    database_url: str = f"sqlite:///{ROOT_DIR / 'scanner.db'}"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
