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

    @field_validator("app_env")
    @classmethod
    def _known_env(cls, v: str) -> str:
        allowed = {"development", "testing", "production"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {sorted(allowed)}")
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
