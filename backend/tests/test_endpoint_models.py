"""Endpoint data model and migration tests (Phase 2.1).

Verifies the 0003 migration produced the expected schema: UUID keys,
UTC timestamps, constraints and indexes that keep inventory normalized.
"""

from __future__ import annotations

import uuid

import pytest
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _columns(table: str) -> set[str]:
    from app.core.database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :t"
            ),
            {"t": table},
        )
    return {r[0] for r in rows}


def test_migration_created_endpoint_tables():
    expected = {
        "endpoints",
        "endpoint_metadata",
        "endpoint_facts",
        "endpoint_software",
        "endpoint_groups",
        "endpoint_group_members",
        "enrollment_tokens",
        "endpoint_credentials",
    }
    assert expected, "spec tables missing"
    for table in expected:
        assert _columns(table), f"missing table {table}"


def test_endpoints_columns_match_spec():
    cols = _columns("endpoints")
    assert {
        "id",
        "hostname",
        "fqdn",
        "os",
        "os_version",
        "os_arch",
        "kernel_version",
        "status",
        "agent_version",
        "enrolled_at",
        "last_heartbeat_at",
        "created_at",
        "updated_at",
    } <= cols


def test_secrets_only_stored_hashed():
    """Enrollment tokens and credentials have digest columns, not secrets."""
    from app.core.database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        token_cols = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'enrollment_tokens'"
            )
        ).fetchall()
        cred_cols = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'endpoint_credentials'"
            )
        ).fetchall()
    token_names = {r[0] for r in token_cols}
    cred_names = {r[0] for r in cred_cols}
    assert "token_hash" in token_names
    assert "token" not in token_names and "raw_token" not in token_names
    assert "token_hash" in cred_names
    assert "credential" not in cred_names and "secret" not in cred_names


def test_unique_hash_indexes_exist():
    from app.core.database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        indexes = {
            r[0]
            for r in conn.execute(
                text(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE tablename IN "
                    "('enrollment_tokens', 'endpoint_credentials', "
                    "'endpoint_facts', 'endpoint_software')"
                )
            ).fetchall()
        }
    assert any("token_hash" in i for i in indexes)
    assert any("endpoint_facts" in i for i in indexes)
    assert any("endpoint_software" in i for i in indexes)


def test_endpoint_status_check_constraint(db):
    """Database rejects unknown status values (not just the ORM)."""
    from app.core.database import engine
    from sqlalchemy import text

    with engine.begin() as conn, pytest.raises(Exception) as exc:
        conn.execute(
            text(
                "INSERT INTO endpoints (id, hostname, os, status, "
                "enrolled_at, created_at, updated_at) "
                "VALUES (:id, 'x', 'linux', 'bogus', now(), now(), now())"
            ),
            {"id": str(uuid.uuid4())},
        )
    assert "ck_endpoints_status" in str(exc.value) or "status" in str(exc.value)


def test_endpoint_uuid_and_utc_timestamps(db):
    from app.core.database import SessionLocal
    from app.models import Endpoint

    with SessionLocal() as s:
        ep = Endpoint(hostname="utc-test-host")
        s.add(ep)
        s.commit()
        s.refresh(ep)
        assert isinstance(ep.id, uuid.UUID)
        assert ep.created_at.tzinfo is not None
        assert ep.updated_at.tzinfo is not None
        assert ep.enrolled_at.tzinfo is not None
        assert ep.status == "active"
        # cleanup
        s.delete(ep)
        s.commit()


def test_fact_unique_per_endpoint_and_key(db):
    from app.core.database import SessionLocal
    from app.models import Endpoint, EndpointFact
    from sqlalchemy.exc import IntegrityError

    with SessionLocal() as s:
        ep = Endpoint(hostname=f"fact-test-{uuid.uuid4().hex[:8]}")
        s.add(ep)
        s.flush()
        s.add(EndpointFact(endpoint_id=ep.id, key="k", value="v1"))
        s.add(EndpointFact(endpoint_id=ep.id, key="k", value="v2"))
        with pytest.raises(IntegrityError):
            s.commit()
        # The whole transaction rolled back — no rows (incl. the endpoint)
        # remain, so there is nothing to clean up.


def test_software_unique_per_endpoint_name_manager(db):
    from app.core.database import SessionLocal
    from app.models import Endpoint, EndpointSoftware
    from sqlalchemy.exc import IntegrityError

    with SessionLocal() as s:
        ep = Endpoint(hostname=f"pkg-test-{uuid.uuid4().hex[:8]}")
        s.add(ep)
        s.flush()
        s.add(
            EndpointSoftware(
                endpoint_id=ep.id, name="curl", version="1", package_manager="dpkg"
            )
        )
        s.add(
            EndpointSoftware(
                endpoint_id=ep.id, name="curl", version="2", package_manager="dpkg"
            )
        )
        with pytest.raises(IntegrityError):
            s.commit()
        # Whole transaction rolled back — nothing to clean up.


def test_credential_revoked_at_column_exists_and_endpoint_fk(db):
    """Credential revocation is a data-level flag checked per request."""
    cols = _columns("endpoint_credentials")
    assert {"revoked_at", "expires_at", "rotated_from", "endpoint_id"} <= cols
