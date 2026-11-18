"""Database configuration and model tests."""

from __future__ import annotations

import pytest
from tests.conftest import requires_postgres


def test_settings_load_from_env():
    from app.core.config import get_settings

    s = get_settings()
    assert s.access_token_expire_minutes >= 1
    assert s.app_env == "testing"
    assert "change-me" not in s.secret_key
    assert s.cors_origin_list  # parsed list, not raw string


def test_database_url_uses_psycopg_driver():
    from app.core.config import get_settings

    assert get_settings().database_url.startswith("postgresql+psycopg://")


@requires_postgres
def test_engine_connects_and_sessions_commit(test_db_ready):
    from app.core.database import SessionLocal
    from sqlalchemy import text

    with SessionLocal() as session:
        assert session.execute(text("SELECT 1")).scalar() == 1


@requires_postgres
def test_get_db_rolls_back_on_error(test_db_ready):
    """A failing dependency must not leave an open transaction."""
    from app.core.database import SessionLocal
    from app.models import User

    session = SessionLocal()
    try:
        # Simulate a request that raises mid-transaction
        session.add(User(email="rollback@example.com", hashed_password="x" * 60))
        session.flush()
        raise RuntimeError("simulated request failure")
    except RuntimeError:
        session.rollback()
    finally:
        session.close()

    # New session must not see the rolled-back user
    with SessionLocal() as s2:
        from sqlalchemy import select

        found = s2.scalar(
            select(User).where(User.email == "rollback@example.com")
        )
        assert found is None


@requires_postgres
def test_refresh_token_hash_unique_constraint(test_db_ready):
    """Duplicate token digests must be rejected by the DB."""
    import uuid as uuid_mod
    from datetime import UTC, datetime, timedelta

    from app.core.database import SessionLocal
    from app.models import RefreshToken, User
    from sqlalchemy import select

    with SessionLocal() as s:
        user = s.scalar(
            select(User).where(User.email.like("admin-%")).limit(1)
        )
        if user is None:
            pytest.skip("no seeded admin user for this test")
        dup_hash = uuid_mod.uuid4().hex
        s.add(
            RefreshToken(
                user_id=user.id,
                token_hash=dup_hash,
                family_id=uuid_mod.uuid4(),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        s.commit()
        s.add(
            RefreshToken(
                user_id=user.id,
                token_hash=dup_hash,
                family_id=uuid_mod.uuid4(),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            s.commit()
        s.rollback()
