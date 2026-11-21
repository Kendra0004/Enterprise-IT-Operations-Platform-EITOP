"""Application settings loaded from environment variables."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration.

    All values come from environment variables (or an optional ``.env`` file).
    ``SECRET_KEY`` has no default on purpose: the application must fail fast
    when no key is configured instead of silently using an insecure one.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "EITOP"
    app_env: str = Field(default="development")
    debug: bool = False
    log_level: str = "INFO"

    secret_key: str = Field(min_length=16)
    access_token_expire_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    database_url: str = "postgresql+psycopg://eitop:eitop@localhost:5432/eitop"
    redis_url: str = "redis://localhost:6379/0"

    rate_limit_login_per_minute: int = Field(default=10, ge=1)
    rate_limit_refresh_per_minute: int = Field(default=30, ge=1)
    rate_limit_enroll_per_minute: int = Field(default=10, ge=1)

    # --- Endpoint health (Phase 2.5) ---------------------------------------
    # Expected agent heartbeat cadence (informational: health display and
    # the "late" warning band).
    endpoint_heartbeat_interval_seconds: int = Field(default=300, ge=10)
    # An endpoint is marked offline when its last heartbeat is older than
    # this. Must be >= the expected interval so normal jitter never flips
    # an endpoint offline.
    endpoint_offline_threshold_seconds: int = Field(default=900, ge=10)
    # Celery scan cadence for the offline transition (recovery happens
    # synchronously on the next valid heartbeat).
    endpoint_health_scan_seconds: int = Field(default=60, ge=10)

    # --- Inventory snapshot retention (Phase 2.6) ---------------------------
    # Days to keep inventory snapshots. None (default) = keep forever:
    # retention never deletes history unless an operator opts in.
    snapshot_retention_days: int | None = Field(default=None, ge=1)

    # --- Directory integration (Phase 3.1) ----------------------------------
    # Beat tick that scans for due auto-sync connections (per-connection
    # cadence is sync_interval_minutes on the connection row).
    directory_sync_scan_seconds: int = Field(default=300, ge=30)
    # LDAP connect/search budgets. The stale-run reaper threshold must stay
    # above the worst-case (connect + full search) budget.
    directory_connect_timeout_seconds: int = Field(default=10, ge=1, le=120)
    directory_search_timeout_seconds: int = Field(default=30, ge=1, le=600)
    directory_page_size: int = Field(default=500, ge=1, le=5000)
    # Grace period before a never-seen-again object is marked missing.
    directory_missing_grace_days: int = Field(default=7, ge=1, le=90)
    # A 'running' sync row older than this is reaped as failed (crashed
    # worker / lost broker) so retries are never blocked forever.
    directory_stale_run_minutes: int = Field(default=30, ge=5, le=1440)

    @field_validator("app_env")
    @classmethod
    def _known_env(cls, v: str) -> str:
        allowed = {"development", "testing", "production"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {sorted(allowed)}")
        return v

    @field_validator("endpoint_offline_threshold_seconds")
    @classmethod
    def _threshold_ge_interval(cls, v: int, info) -> int:  # type: ignore[no-untyped-def]
        interval = info.data.get("endpoint_heartbeat_interval_seconds", 300)
        if v < interval:
            raise ValueError(
                "endpoint_offline_threshold_seconds must be >= "
                "endpoint_heartbeat_interval_seconds"
            )
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def database_url_sync(self) -> str:
        """Alias kept for readability in alembic/tests."""
        return self.database_url


@lru_cache
def get_settings() -> Settings:
    return Settings()
