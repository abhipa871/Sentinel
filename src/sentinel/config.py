from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    database_url: str | None = None
    redis_url: str | None = None
    object_store_endpoint: str | None = None
    object_store_bucket: str = "sentinel-artifacts"
    model_provider: str | None = None
    model_id_supervisor: str | None = None
    model_id_code_analysis: str | None = None
    model_id_review: str | None = None
    default_scan_profile: Literal["fast", "balanced", "deep"] = "balanced"
    sandbox_network_policy: Literal["deny", "allowlisted"] = "deny"
    enable_source_writes: bool = False
    enable_automated_pr: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
