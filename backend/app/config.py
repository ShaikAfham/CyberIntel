from __future__ import annotations
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)

    app_name: str = "CyberINTEL-AI API"
    version: str = "1.0.0"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///./cyberintel.db"

    # CORS origins allowed to call the API
    cors_origins: List[str] = [
        "chrome-extension://*",
        "moz-extension://*",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # External API keys (optional — graceful degradation if missing)
    nvd_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None

    # Scan engine limits
    max_concurrent_scans: int = 5
    scan_timeout_seconds: int = 120
    http_request_timeout: int = 10

    # Report storage
    reports_dir: str = "./reports"


@lru_cache
def get_settings() -> Settings:
    return Settings()
