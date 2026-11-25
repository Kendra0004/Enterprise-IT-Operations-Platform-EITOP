"""Production configuration fail-fast checks (Phase 4).

A production deployment must die at boot rather than silently run with
development credentials. These tests drive the Settings validators
directly; development/testing behaviour must stay unchanged.
"""

from __future__ import annotations

import pytest
from app.core.config import Settings
from pydantic import ValidationError

PROD_OK = {
    "app_env": "production",
    "debug": False,
    "secret_key": "s" * 64,
    "database_url": "postgresql+psycopg://eitop:some-strong-pw@postgres:5432/eitop",
    "redis_url": "redis://:strong-redis-pw@redis:6379/0",
    "cors_origins": "https://eitop.example.com",
}


def _prod(**overrides: object) -> Settings:
    return Settings(**{**PROD_OK, **overrides})  # type: ignore[arg-type]


class TestProductionValidation:
    def test_secure_production_config_loads(self) -> None:
        s = _prod()
        assert s.is_production
        assert not s.debug

    def test_debug_forbidden_in_production(self) -> None:
        with pytest.raises(ValidationError, match="DEBUG=false"):
            _prod(debug=True)

    @pytest.mark.parametrize(
        "key",
        [
            "change-me-to-a-long-random-string",  # placeholder wording
            "test-secret-key-for-automated-tests-only",
            "dev-insecure-abcdefghijklmnop",  # short AND insecure
            "s" * 31,  # length floor
        ],
    )
    def test_weak_or_placeholder_secret_rejected(self, key: str) -> None:
        with pytest.raises(ValidationError, match="SECRET_KEY"):
            _prod(secret_key=key)

    def test_dev_database_credentials_rejected(self) -> None:
        with pytest.raises(ValidationError, match="eitop:eitop"):
            _prod(database_url="postgresql+psycopg://eitop:eitop@postgres:5432/eitop")

    def test_placeholder_database_password_rejected(self) -> None:
        with pytest.raises(ValidationError, match="DATABASE_URL"):
            _prod(
                database_url=(
                    "postgresql+psycopg://eitop:change-me-db-password"
                    "@postgres:5432/eitop"
                )
            )

    def test_redis_without_password_rejected(self) -> None:
        with pytest.raises(ValidationError, match="authentication password"):
            _prod(redis_url="redis://redis:6379/0")

    def test_redis_dev_password_rejected(self) -> None:
        with pytest.raises(ValidationError, match="development default"):
            _prod(redis_url="redis://:eitop-dev-redis@redis:6379/0")

    def test_redis_placeholder_password_rejected(self) -> None:
        with pytest.raises(ValidationError, match="placeholder"):
            _prod(redis_url="redis://:change-me-redis-password@redis:6379/0")

    def test_cors_wildcard_rejected(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            _prod(cors_origins="*")

    def test_cors_plain_http_rejected(self) -> None:
        with pytest.raises(ValidationError, match="https"):
            _prod(cors_origins="http://eitop.example.com")

    def test_all_problems_reported_together(self) -> None:
        with pytest.raises(ValidationError) as exc:
            _prod(
                debug=True,
                secret_key="change-me-placeholder-1234567890",
                cors_origins="*",
            )
        msg = str(exc.value)
        assert "DEBUG=false" in msg
        assert "SECRET_KEY" in msg
        assert "wildcard" in msg


class TestDevelopmentUntouched:
    """The development workflow must not trip the production checks."""

    def test_development_defaults_still_load(self) -> None:
        s = Settings(
            app_env="development",
            debug=True,
            secret_key="change-me-to-a-long-random-string",
            database_url="postgresql+psycopg://eitop:eitop@localhost:5432/eitop",
            redis_url="redis://localhost:6379/0",
            cors_origins="http://localhost:8080,http://localhost:5173",
        )
        assert not s.is_production
        assert s.debug

    def test_testing_defaults_still_load(self) -> None:
        s = Settings(
            app_env="testing",
            secret_key="test-secret-key-not-for-production-use",
            database_url="postgresql+psycopg://eitop:eitop@postgres:5432/eitop_test",
            redis_url="redis://:eitop-dev-redis@redis:6379/1",
        )
        assert s.app_env == "testing"
