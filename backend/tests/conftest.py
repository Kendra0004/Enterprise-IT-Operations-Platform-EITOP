"""Shared pytest fixtures.

Integration tests need PostgreSQL + Redis. When TEST_DATABASE_URL /
TEST_REDIS_URL are set (CI, docker compose), tests run against them;
otherwise DB/Redis-dependent tests are skipped with a clear reason —
we never fake a database with mocks and call it production-ready.
"""

from __future__ import annotations

import os
import uuid

import pytest

# Configure a dedicated test database BEFORE importing the app.
TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://eitop:eitop@localhost:5432/eitop_test",
)
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/1")

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use")
os.environ["DATABASE_URL"] = TEST_DB_URL
os.environ["REDIS_URL"] = TEST_REDIS_URL
os.environ["APP_ENV"] = "testing"
# Rate limits are exercised by dedicated unit tests; keep the per-minute
# ceiling high here so the shared testclient IP does not trip it.
os.environ["RATE_LIMIT_LOGIN_PER_MINUTE"] = "100000"
os.environ["RATE_LIMIT_REFRESH_PER_MINUTE"] = "100000"
os.environ["RATE_LIMIT_ENROLL_PER_MINUTE"] = "100000"



def _postgres_available() -> bool:
    from sqlalchemy import create_engine, text

    try:
        engine = create_engine(TEST_DB_URL, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


def _redis_available() -> bool:
    import redis as redis_lib

    try:
        client = redis_lib.Redis.from_url(TEST_REDIS_URL, socket_connect_timeout=1)
        client.ping()
        client.close()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(
    not _postgres_available(),
    reason=f"PostgreSQL not reachable at {TEST_DB_URL} — start stack first",
)
requires_redis = pytest.mark.skipif(
    not _redis_available(),
    reason=f"Redis not reachable at {TEST_REDIS_URL} — start stack first",
)


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session")
def test_db_ready():
    """Create schema in the test database (once per session)."""
    if not _postgres_available():
        pytest.skip("PostgreSQL not available")
    from alembic import command
    from alembic.config import Config

    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    command.upgrade(cfg, "head")

    from app.db.seed import seed_rbac

    seed_rbac()
    yield


@pytest.fixture()
def db(test_db_ready):
    """Session per test; tables truncated between tests for isolation."""
    from app.core.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="session")
def client(test_db_ready):
    """FastAPI TestClient with the real app (not a mock)."""
    from app.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def admin_user(db):
    """Seeded admin-role user with known credentials."""
    from app.core.security import hash_password
    from app.db.seed import seed_rbac
    from app.models import Role, User
    from sqlalchemy import select

    seed_rbac()
    email = f"admin-{uuid.uuid4().hex[:8]}@example.com"
    admin_role = db.scalar(select(Role).where(Role.name == "admin"))
    user = User(
        email=email,
        full_name="Test Admin",
        hashed_password=hash_password("Str0ng!Passw0rd#2026"),
        is_active=True,
        roles=[admin_role],
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture()
def readonly_user(db):
    from app.core.security import hash_password
    from app.db.seed import seed_rbac
    from app.models import Role, User
    from sqlalchemy import select

    seed_rbac()
    email = f"reader-{uuid.uuid4().hex[:8]}@example.com"
    role = db.scalar(select(Role).where(Role.name == "readonly"))
    user = User(
        email=email,
        full_name="Test Reader",
        hashed_password=hash_password("Str0ng!Passw0rd#2026"),
        is_active=True,
        roles=[role],
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture()
def agent_user(db):
    """Endpoint-collector identity: endpoints:write only."""
    from app.core.security import hash_password
    from app.db.seed import seed_rbac
    from app.models import Role, User
    from sqlalchemy import select

    seed_rbac()
    email = f"agent-{uuid.uuid4().hex[:8]}@example.com"
    role = db.scalar(select(Role).where(Role.name == "agent"))
    user = User(
        email=email,
        full_name="Test Agent",
        hashed_password=hash_password("Str0ng!Passw0rd#2026"),
        is_active=True,
        roles=[role],
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture()
def operator_user(db):
    from app.core.security import hash_password
    from app.db.seed import seed_rbac
    from app.models import Role, User
    from sqlalchemy import select

    seed_rbac()
    email = f"operator-{uuid.uuid4().hex[:8]}@example.com"
    role = db.scalar(select(Role).where(Role.name == "operator"))
    user = User(
        email=email,
        full_name="Test Operator",
        hashed_password=hash_password("Str0ng!Passw0rd#2026"),
        is_active=True,
        roles=[role],
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture()
def auditor_user(db):
    """Security auditor: audit:read but no admin:write."""
    from app.core.security import hash_password
    from app.db.seed import seed_rbac
    from app.models import Role, User
    from sqlalchemy import select

    seed_rbac()
    email = f"auditor-{uuid.uuid4().hex[:8]}@example.com"
    role = db.scalar(select(Role).where(Role.name == "security_auditor"))
    user = User(
        email=email,
        full_name="Test Auditor",
        hashed_password=hash_password("Str0ng!Passw0rd#2026"),
        is_active=True,
        roles=[role],
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture()
def auth_headers(client, admin_user):
    """Login as admin and return Authorization headers (fresh tokens).

    Clears the shared cookie jar first so session state never leaks between
    tests (the TestClient cookie jar is session-scoped).
    """
    client.cookies.clear()
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "Str0ng!Passw0rd#2026"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
