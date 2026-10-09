from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Email Threat Analysis and Malware Detection System"
    app_version: str = "1.0.0"
    app_env: str = "development"
    database_url: str = "sqlite:///./data/etas.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    max_upload_bytes: int = 10 * 1024 * 1024
    persist_raw_content: bool = False
    rate_limit_analyze_per_minute: int = 30
    score_safe_max: int = 29
    score_suspicious_max: int = 59
    virustotal_api_key: str = ""
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    clamav_enabled: bool = False
    clamav_host: str = "127.0.0.1"
    clamav_port: int = 3310
    clamav_timeout_seconds: int = 8
    yara_rules_path: str = "./yara_rules"
    admin_api_token: str = ""
    max_archive_entries: int = 40
    max_archive_depth: int = 1
    max_archive_member_bytes: int = 2 * 1024 * 1024
    max_body_chars: int = 20000

    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
