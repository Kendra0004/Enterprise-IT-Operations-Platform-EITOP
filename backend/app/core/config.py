"""Application settings loaded from environment variables."""

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
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

    # 32-char floor everywhere (Phase 6 audit A15): production already
    # required ≥32, but a non-prod build with a 16-char HS256 key was
    # silently accepted. One uniform floor, one place to reason about.
    secret_key: str = Field(min_length=32)
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
    # LDAP connect/search budgets (per operation — one bound per probe,
    # bind or page read; the sync run as a whole is bounded by
    # directory_max_sync_minutes below).
    directory_connect_timeout_seconds: int = Field(default=10, ge=1, le=120)
    directory_search_timeout_seconds: int = Field(default=30, ge=1, le=600)
    directory_page_size: int = Field(default=500, ge=1, le=5000)
    # Grace period before a never-seen-again object is marked missing.
    directory_missing_grace_days: int = Field(default=7, ge=1, le=90)
    # --- Sync run lifecycle limits (Phase 3.1.1) ----------------------------
    # Fallback staleness: a run that was NEVER claimed (lost broker
    # delivery, pre-lease rows) is reaped as failed after this long so
    # retries are never blocked. Runs holding a live lease are NOT reaped
    # by this threshold — the executing worker renews its lease.
    directory_stale_run_minutes: int = Field(default=30, ge=5, le=1440)
    # Absolute wall-clock cap for ONE sync run, measured from run creation
    # and enforced by the reaper even while the lease is live. Also sizes
    # the Celery ladder (app/core/celery_app.py): task_soft_time_limit =
    # this value from task start, task_time_limit = +1 min, broker
    # visibility_timeout = +15 min. Keep them in this order.
    directory_max_sync_minutes: int = Field(default=60, ge=5, le=1440)
    # Ownership lease of the executing worker. Renewed by a heartbeat
    # thread every lease/3 and re-checked atomically before each mirror
    # commit and before finalizing run status; an expired lease means the
    # worker must stop without writing. Must be far below the max duration
    # (so several renewals fit) and comfortably above the heartbeat tick.
    directory_sync_lease_seconds: int = Field(default=300, ge=30, le=3600)

    # --- Directory insights (Phase 3.2.1) -----------------------------------
    # Beat cadence of the findings recompute (idempotent, advisory-locked
    # per connection — a tick that collides with another skips cleanly).
    directory_insight_scan_seconds: int = Field(default=600, ge=60)
    # Inactivity thresholds. Both are >= 30 days because AD's replicated
    # lastLogonTimestamp has ~14-day resolution — a shorter window would
    # produce false "inactive" findings inside the replication error band.
    directory_inactive_user_days: int = Field(default=90, ge=30, le=3650)
    directory_stale_computer_days: int = Field(default=90, ge=30, le=3650)
    # Bounded transitive (nested-group) traversal: chain depth from a
    # privileged group. Cycle detection + a node budget bound the walk too.
    directory_nested_group_max_depth: int = Field(default=8, ge=1, le=32)

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

    @field_validator("directory_max_sync_minutes")
    @classmethod
    def _max_sync_ge_stale(cls, v: int, info) -> int:  # type: ignore[no-untyped-def]
        # The absolute cap is the strongest bound; the never-claimed
        # fallback threshold may not exceed it (otherwise it would be dead
        # configuration that no reaper branch could ever fire after).
        stale = info.data.get("directory_stale_run_minutes", 30)
        if v < stale:
            raise ValueError(
                "directory_max_sync_minutes must be >= directory_stale_run_minutes"
            )
        return v

    @model_validator(mode="after")
    def _production_safety(self) -> "Settings":
        """Fail startup when production is configured insecurely.

        Checked on every process that loads settings (API, worker, beat,
        migrations), so a bad deploy dies at boot instead of silently
        running with dev credentials. Development and testing are
        unaffected — the checks only fire under APP_ENV=production.
        """
        if not self.is_production:
            return self

        problems: list[str] = []

        if self.debug:
            problems.append("APP_ENV=production requires DEBUG=false")

        # Secret key: length + no development/placeholder values.
        if len(self.secret_key) < 32:
            problems.append("SECRET_KEY must be at least 32 characters in production")
        lowered = self.secret_key.lower()
        for marker in ("change-me", "changeme", "test-secret", "not-for-production",
                       "insecure", "example"):
            if marker in lowered:
                problems.append(
                    "SECRET_KEY is a known placeholder/development value"
                )
                break

        # Database credentials: reject compose development defaults.
        db_lower = self.database_url.lower()
        if "eitop:eitop@" in db_lower:
            problems.append(
                "DATABASE_URL still uses the development eitop:eitop credentials"
            )
        if "change-me" in db_lower:
            problems.append("DATABASE_URL password is a placeholder")

        # Redis credentials: require a password and reject dev defaults.
        if "change-me-redis-password" in self.redis_url.lower():
            problems.append("redis password is a placeholder")
        if "eitop-dev-redis" in self.redis_url.lower():
            problems.append("redis still uses the development default password")
        # redis://[:password]@host — password segment must exist before @.
        redis_auth = self.redis_url.split("://", 1)[-1] if "://" in self.redis_url else ""
        if "@" not in redis_auth:
            problems.append("redis URL must carry an authentication password")

        # CORS: https origins only, never wildcard.
        for origin in self.cors_origin_list:
            if origin == "*":
                problems.append("CORS wildcard '*' is not allowed in production")
            elif not origin.startswith("https://"):
                problems.append(
                    f"CORS origin must use https in production: {origin}"
                )

        if problems:
            raise ValueError(
                "Insecure production configuration: " + "; ".join(problems)
            )
        return self

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
