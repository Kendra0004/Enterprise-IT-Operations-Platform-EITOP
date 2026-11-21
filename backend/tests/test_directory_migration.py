"""Alembic migration round-trip for the directory tables (Phase 3.1).

The round-trip runs against an ISOLATED database created for this test —
never against the shared test schema — so ``downgrade``/``upgrade`` cannot
disturb any other test suite. The commands are executed in a subprocess
with an overridden ``DATABASE_URL`` so the application engine and the
Alembic engine are provably separate.

Environment: PostgreSQL is required (to create the scratch database).
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, text
from tests.conftest import requires_postgres

pytestmark = requires_postgres

REPO_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _base_url() -> str:
    url = os.environ["DATABASE_URL"]
    # Split "postgresql+psycopg://user:pass@host:port/db"
    head, _, tail = url.rpartition("/")
    if not head:
        pytest.skip("DATABASE_URL has no database name to derive from")
    return head


def _admin_url(dbname: str) -> str:
    return f"{_base_url()}/{dbname}"


def _run(dbname: str, *args: str) -> subprocess.CompletedProcess:
    """Run alembic with DATABASE_URL pointed at the scratch database."""
    env = dict(os.environ, DATABASE_URL=_admin_url(dbname))
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_BACKEND,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.fixture()
def scratch_db():
    """A scratch database that is created for this test and dropped after."""
    dbname = f"eitop_mig_{os.getpid()}_{abs(hash(sys.argv[0])) % 10000}"
    admin = create_engine(_admin_url("postgres"), future=True, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": dbname}
            ).scalar()
            if not exists:
                try:
                    conn.execute(text(f'CREATE DATABASE "{dbname}"'))
                except Exception as exc:  # pragma: no cover - permission denied
                    pytest.skip(f"cannot create scratch database: {exc.__class__.__name__}")
    finally:
        admin.dispose()
    yield dbname
    admin = create_engine(_admin_url("postgres"), future=True, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :n AND pid <> pg_backend_pid()"
                ),
                {"n": dbname},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{dbname}"'))
    except Exception:  # pragma: no cover - best-effort cleanup
        pass
    finally:
        admin.dispose()


def _table_names(dbname: str) -> set[str]:
    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public' AND tablename LIKE 'directory_%'"
                )
            )
            return {r[0] for r in rows}
    finally:
        engine.dispose()


def _column(dbname: str, table: str, column: str) -> dict:
    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT data_type, is_nullable FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = :t AND column_name = :c"
                ),
                {"t": table, "c": column},
            ).first()
            assert row is not None, f"{table}.{column} missing"
            return {"data_type": row[0], "is_nullable": row[1]}
    finally:
        engine.dispose()


def _check_constraints(dbname: str, table: str) -> list[str]:
    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = CAST(:t AS regclass) AND contype = 'c'"
                ),
                {"t": table},
            )
            return [r[0] for r in rows]
    finally:
        engine.dispose()


def test_migration_round_trip_on_isolated_database(scratch_db):
    """downgrade 0004 → upgrade head, verified against a scratch database."""
    # 1. Upgrade to head on the isolated database.
    up = _run(scratch_db, "upgrade", "head")
    assert up.returncode == 0, up.stderr[-3000:]

    tables = _table_names(scratch_db)
    assert "directory_connections" in tables
    assert "directory_sync_runs" in tables
    assert "directory_users" in tables
    assert "directory_group_memberships" in tables
    assert "directory_reconciliations" in tables
    assert "directory_computers" in tables
    assert "directory_groups" in tables
    assert "directory_ous" in tables
    assert "directory_domains" in tables

    # The Phase 3.1 column fixes are present.
    assert _column(scratch_db, "directory_group_memberships", "member_object_guid")[
        "is_nullable"
    ] == "YES"
    assert "canonical_path" not in {
        r[0]
        for r in _columns(scratch_db, "directory_ous")
    }
    checks = " ".join(_check_constraints(scratch_db, "directory_group_memberships"))
    assert "unknown" in checks

    # 2. Downgrade past the directory migration.
    down = _run(scratch_db, "downgrade", "0004")
    assert down.returncode == 0, down.stderr[-3000:]
    assert _table_names(scratch_db) == set()

    # 3. Re-upgrade: the schema is reproducible from scratch.
    again = _run(scratch_db, "upgrade", "head")
    assert again.returncode == 0, again.stderr[-3000:]
    assert "directory_connections" in _table_names(scratch_db)
    assert _column(scratch_db, "directory_group_memberships", "member_object_guid")[
        "is_nullable"
    ] == "YES"
    checks = " ".join(_check_constraints(scratch_db, "directory_group_memberships"))
    assert "unknown" in checks


def _columns(dbname: str, table: str) -> list[tuple]:
    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = :t"
                ),
                {"t": table},
            )
            return [(r[0],) for r in rows]
    finally:
        engine.dispose()


def test_downgrade_does_not_touch_other_schemas(scratch_db):
    """Sanity: the isolated round-trip really used its own database."""
    up = _run(scratch_db, "upgrade", "head")
    assert up.returncode == 0, up.stderr[-3000:]
    # The shared test database (DATABASE_URL without override) still has
    # its own directory tables: we never dropped anything shared.
    shared = _shared_tables()
    assert "directory_connections" in shared


def _shared_tables() -> set[str]:
    engine = create_engine(os.environ["DATABASE_URL"], future=True)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public' AND tablename LIKE 'directory_%'"
                )
            )
            return {r[0] for r in rows}
    finally:
        engine.dispose()
