"""Environment-based configuration for all Pentra services."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration loaded from environment variables.

    Every service imports this; keys not relevant to a given service
    are simply ignored (they keep their defaults).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────
    app_name: str = "pentra"
    app_env: str = "development"  # development | staging | production
    debug: bool = True
    api_v1_prefix: str = "/api/v1"
    allowed_origins: list[str] = ["http://localhost:3000"]

    # ── Database (PostgreSQL / asyncpg) ──────────────────────────
    database_url: str = "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra_dev"
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_echo: bool = False

    # ── Redis ────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── JWT ──────────────────────────────────────────────────────
    jwt_secret: str = "CHANGE-ME-IN-PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # ── Google OAuth ─────────────────────────────────────────────
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/auth/google/callback"

    # ── Rate Limiting ────────────────────────────────────────────
    rate_limit_per_minute: int = 60

    # ── Observability ────────────────────────────────────────────
    log_level: str = "INFO"
    otlp_endpoint: str = ""


@lru_cache
def get_settings() -> Settings:
    """Singleton settings instance, cached for the process lifetime."""
    return Settings()
