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
import uuid
from datetime import UTC, datetime

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

    # Phase 3.1.1 ownership columns (execution token + lease) are present.
    assert _column(scratch_db, "directory_sync_runs", "execution_token") == {
        "data_type": "character varying",
        "is_nullable": "YES",
    }
    assert _column(scratch_db, "directory_sync_runs", "lease_expires_at") == {
        "data_type": "timestamp with time zone",
        "is_nullable": "YES",
    }

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
    assert _column(scratch_db, "directory_sync_runs", "execution_token")[
        "data_type"
    ] == "character varying"


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


# --- Phase 3.2.1: directory_findings (0007) ----------------------------------


def _insert_connection(dbname: str) -> str:
    """Raw connection row (all NOT NULL columns supplied explicitly)."""
    cid = str(uuid.uuid4())
    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO directory_connections ("
                    "id, name, domain_dns, host, port, tls_mode, search_base, "
                    "bind_username, bind_password_encrypted, connect_timeout_seconds, "
                    "search_timeout_seconds, page_size, enabled, auto_sync, "
                    "sync_interval_minutes, created_at, updated_at"
                    ") VALUES ("
                    ":id, 'insights-mig', 'eitop.test', 'dc01.eitop.test', 636, "
                    "'ldaps', 'DC=eitop,DC=test', 'CN=svc,CN=Users,DC=eitop,DC=test', "
                    "'placeholder', 10, 30, 500, TRUE, TRUE, 60, :ts, :ts"
                    ")"
                ),
                {"id": cid, "ts": datetime(2026, 11, 23, 12, 0, tzinfo=UTC)},
            )
    finally:
        engine.dispose()
    return cid


_FINDING_INSERT = """
    INSERT INTO directory_findings (
        id, connection_id, fingerprint, rule_key, severity, status,
        subject_type, access, subject_guid, subject_dn, subject_name,
        title, first_seen_at, last_seen_at, created_at, updated_at
    ) VALUES (
        :id, :cid, :fp, :rule, :severity, :status,
        :subject_type, :access, :guid, :dn, :name,
        'title', :ts, :ts, :ts, :ts
    )
"""


def _finding_params(cid: str, **overrides) -> dict:
    params = {
        "id": str(uuid.uuid4()),
        "cid": cid,
        "fp": f"privileged.direct_member|m=g:guid-{uuid.uuid4().hex[:8]}|p=n:abc",
        "rule": "privileged.direct_member",
        "severity": "high",
        "status": "open",
        "subject_type": "user",
        "access": "direct",
        "guid": "bbbbbbbb-0000-0000-0000-000000000001",
        "dn": "CN=alice,CN=Users,DC=eitop,DC=test",
        "name": "alice",
        "ts": datetime(2026, 11, 23, 12, 0, tzinfo=UTC),
    }
    params.update(overrides)
    return params


def _try_insert(dbname: str, params: dict) -> str | None:
    """Run the finding insert; return the DB error code (or None on success)."""
    from sqlalchemy.exc import IntegrityError

    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.begin() as conn:
            conn.execute(text(_FINDING_INSERT), params)
        return None
    except IntegrityError as exc:
        return getattr(exc.orig, "sqlstate", None) or str(exc.orig)
    finally:
        engine.dispose()


def _unique_constraints(dbname: str, table: str) -> set[str]:
    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid = CAST(:t AS regclass) AND contype = 'u'"
                ),
                {"t": table},
            )
            return {r[0] for r in rows}
    finally:
        engine.dispose()


def _index_names(dbname: str, table: str) -> set[str]:
    engine = create_engine(_admin_url(dbname), future=True)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE tablename = :t AND schemaname = 'public'"
                ),
                {"t": table},
            )
            return {r[0] for r in rows}
    finally:
        engine.dispose()


def test_findings_table_0007(scratch_db):
    """0007: directory_findings DDL, CHECK constraints, round-trip."""
    up = _run(scratch_db, "upgrade", "head")
    assert up.returncode == 0, up.stderr[-3000:]

    tables = _table_names(scratch_db)
    assert "directory_findings" in tables

    # Core columns: fingerprint/status NOT NULL, subject_dn nullable
    # (connection findings), reopen_count present.
    assert _column(scratch_db, "directory_findings", "fingerprint") == {
        "data_type": "character varying",
        "is_nullable": "NO",
    }
    assert _column(scratch_db, "directory_findings", "subject_dn")["is_nullable"] == "YES"
    assert _column(scratch_db, "directory_findings", "reopen_count") == {
        "data_type": "integer",
        "is_nullable": "NO",
    }
    assert _column(scratch_db, "directory_findings", "resolved_at")["is_nullable"] == "YES"
    assert _column(scratch_db, "directory_findings", "acknowledged_by")[
        "is_nullable"
    ] == "YES"

    checks = " ".join(_check_constraints(scratch_db, "directory_findings"))
    # subject identity CHECK: connection ⇔ subject_dn IS NULL.
    assert "subject_dn IS NULL" in checks
    assert "subject_dn IS NOT NULL" in checks
    assert "severity" in checks and "status" in checks

    # Unique (connection_id, fingerprint) + the four read indexes.
    assert "uq_directory_findings_conn_fp" in _unique_constraints(
        scratch_db, "directory_findings"
    )
    indexes = _index_names(scratch_db, "directory_findings")
    for name in (
        "ix_directory_findings_conn_status",
        "ix_directory_findings_conn_severity",
        "ix_directory_findings_rule",
        "ix_directory_findings_subject",
    ):
        assert name in indexes, name

    # --- CHECK enforcement via raw SQL ------------------------------------
    cid = _insert_connection(scratch_db)

    # Valid object-level finding (subject_dn present).
    assert _try_insert(scratch_db, _finding_params(cid)) is None
    # Valid connection-level finding (subject_dn/subject_guid NULL).
    assert (
        _try_insert(
            scratch_db,
            _finding_params(
                cid,
                fp="connection.inventory_empty|c=" + cid,
                rule="connection.inventory_empty",
                subject_type="connection",
                access=None,
                guid=None,
                dn=None,
                name=None,
            ),
        )
        is None
    )
    # Violation: connection finding carrying a subject_dn.
    assert (
        _try_insert(
            scratch_db,
            _finding_params(
                cid,
                subject_type="connection",
                dn="CN=should-not-exist,DC=eitop,DC=test",
            ),
        )
        is not None
    )
    # Violation: object finding with NULL subject_dn.
    assert _try_insert(scratch_db, _finding_params(cid, dn=None)) is not None
    # Violation: bad severity.
    assert _try_insert(scratch_db, _finding_params(cid, severity="urgent")) is not None
    # Violation: bad status.
    assert _try_insert(scratch_db, _finding_params(cid, status="archived")) is not None
    # Violation: bad access value.
    assert _try_insert(scratch_db, _finding_params(cid, access="indirect")) is not None
    # Violation: bad subject_type.
    assert _try_insert(scratch_db, _finding_params(cid, subject_type="group2")) is not None
    # Violation: duplicate (connection_id, fingerprint).
    dup = _finding_params(cid)
    dup["id"] = str(uuid.uuid4())
    assert _try_insert(scratch_db, dup) is None  # fresh fingerprint OK
    dup_again = dict(dup)
    dup_again["id"] = str(uuid.uuid4())
    assert _try_insert(scratch_db, dup_again) is not None

    # --- Round-trip: downgrade drops it, upgrade restores it ---------------
    down = _run(scratch_db, "downgrade", "0006_directory_sync_ownership")
    assert down.returncode == 0, down.stderr[-3000:]
    assert "directory_findings" not in _table_names(scratch_db)

    again = _run(scratch_db, "upgrade", "head")
    assert again.returncode == 0, again.stderr[-3000:]
    assert "directory_findings" in _table_names(scratch_db)
    assert "uq_directory_findings_conn_fp" in _unique_constraints(
        scratch_db, "directory_findings"
    )
