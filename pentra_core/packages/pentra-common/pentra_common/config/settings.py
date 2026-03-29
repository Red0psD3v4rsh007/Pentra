"""Environment-based configuration for all Pentra services."""

from __future__ import annotations

from functools import lru_cache
import os

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ModuleNotFoundError:  # pragma: no cover - exercised only in minimal test envs
    from pydantic import BaseModel

    def SettingsConfigDict(**kwargs):
        return dict(kwargs)

    class BaseSettings(BaseModel):
        """Lightweight fallback when pydantic-settings is unavailable."""

        model_config = {}

        def __init__(self, **data):
            env_data: dict[str, str] = {}
            for field_name in self.__class__.model_fields:
                env_key = field_name.upper()
                if env_key in os.environ and field_name not in data:
                    env_data[field_name] = os.environ[env_key]
            env_data.update(data)
            super().__init__(**env_data)


def _default_allowed_origins() -> list[str]:
    hosts = ("localhost", "127.0.0.1")
    ports = (3000, 3001, 3002, 3003, 3004, 3005, 3006)
    return [f"http://{host}:{port}" for host in hosts for port in ports]


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
    allowed_origins: list[str] = _default_allowed_origins()
    request_id_header: str = "X-Request-ID"

    # ── Database (PostgreSQL / asyncpg) ──────────────────────────
    database_url: str = "postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev"
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
    frontend_base_url: str = "http://localhost:3006"

    # ── Development Auth Bypass ──────────────────────────────────
    dev_auth_bypass_enabled: bool = True
    dev_auth_user_id: str = "11111111-1111-1111-1111-111111111111"
    dev_auth_tenant_id: str = "22222222-2222-2222-2222-222222222222"
    dev_auth_email: str = "dev@pentra.local"
    dev_auth_roles: str = "owner"
    dev_auth_tier: str = "pro"

    # ── Rate Limiting ────────────────────────────────────────────
    rate_limit_per_minute: int = 60
    allow_local_dev_rate_limit_bypass: bool = True

    # ── Scan Guardrails ──────────────────────────────────────────
    max_scan_depth: int = 4
    max_scan_endpoints: int = 250
    max_scan_subdomains: int = 100
    max_scope_hosts: int = 20
    max_scope_cidrs: int = 8
    max_http_requests_per_minute: int = 300
    max_ffuf_requests_per_minute: int = 120
    max_nuclei_requests_per_minute: int = 60
    max_sqlmap_threads: int = 4
    max_zap_minutes: int = 10
    max_dynamic_nodes_per_scan: int = 12
    max_verifications_per_type: int = 3
    max_stateful_pages: int = 50
    max_stateful_replays: int = 10
    max_ai_strategy_followups: int = 3
    artifact_retention_days: int = 30
    scan_idempotency_window_hours: int = 24
    allow_demo_simulated_scans: bool = False
    allow_external_targets: bool = True
    external_scan_rate_limit: int = 100  # requests/minute per external scan

    # ── Advisory AI Reasoning ────────────────────────────────────
    ai_reasoning_enabled: bool = True
    ai_reasoning_timeout_seconds: float = 20.0
    ai_reasoning_max_retries: int = 2
    ai_reasoning_max_tokens: int = 1400
    ai_reasoning_temperature: float = 0.2
    ai_reasoning_primary_provider: str = "anthropic"
    ai_reasoning_fallback_provider: str = "openai"
    ai_reasoning_additional_providers: str = ""
    ai_provider_priority: str = ""
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"  # legacy alias for default model
    anthropic_default_model: str = "claude-sonnet-4-20250514"
    anthropic_deep_model: str = "claude-opus-4-1-20250805"
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_version: str = "2023-06-01"
    openai_api_key: str = ""
    openai_default_model: str = "gpt-4o-mini"
    openai_deep_model: str = "gpt-4o"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_standard_reasoning_effort: str = "low"
    openai_deep_reasoning_effort: str = "high"
    groq_api_key: str = ""
    groq_default_model: str = ""
    groq_deep_model: str = ""
    groq_base_url: str = "https://api.groq.com/openai/v1"
    ollama_api_key: str = ""
    ollama_default_model: str = ""
    ollama_deep_model: str = ""
    ollama_base_url: str = "http://127.0.0.1:11434/v1"
    gemini_api_key: str = ""
    gemini_default_model: str = ""
    gemini_deep_model: str = ""
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai"

    # ── Observability ────────────────────────────────────────────
    log_level: str = "INFO"
    otlp_endpoint: str = ""


@lru_cache
def get_settings() -> Settings:
    """Singleton settings instance, cached for the process lifetime."""
    return Settings()
