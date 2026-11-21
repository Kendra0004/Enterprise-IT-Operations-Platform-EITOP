"""Sync engine tests (Phase 3.1): pipeline, safety gates, reconciliation.

Environment labels (honest):
- Directory data comes from **ldap3.mock** (protocol behavior, not a real
  Active Directory). TLS handshake behavior is covered separately in
  ``test_directory_client.py`` against a local TLS listener.
- PostgreSQL is real (the shared test database).

Invariants exercised here:
- one data transaction: a failed run rolls back completely;
- missing-object marking only after ALL required categories succeed;
- unparseable entries fail their category instead of silently dropping;
- keyed upserts + unique edges: re-runs never duplicate rows;
- category_results/errors carry sanitized labels only (no exception text,
  no credentials, no directory attribute payloads);
- stale-run reaping, concurrent-trigger 409, enqueue-failure finalization.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.models import (
    SYNC_FAILED,
    SYNC_RUNNING,
    SYNC_SUCCESS,
    AuditLog,
    DirectoryComputer,
    DirectoryConnection,
    DirectoryDomain,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectoryOrganizationalUnit,
    DirectoryReconciliation,
    DirectorySyncRun,
    DirectoryUser,
    Endpoint,
)
from app.services.directory import connection_service
from app.services.directory import factory as factory_module
from app.services.directory.connection_service import create_sync_run, trigger_sync
from app.services.directory.ldap_client import DirectoryLdapClient
from app.services.directory.sync_engine import execute_sync, initial_category_results
from ldap3 import MOCK_SYNC, NONE, Connection, Server
from sqlalchemy import delete, select, update
from tests.conftest import requires_postgres

pytestmark = requires_postgres

SEARCH_BASE = "OU=HQ,DC=eitop,DC=test"
BIND_DN = "CN=svc-eitop,DC=eitop,DC=test"
BIND_PASSWORD = "Sentinel-Bind-Pa55word!"
DC_DN = "DC=eitop,DC=test"

# Ids of runs created by this test module (cleared between tests).
_LAST_RUN_IDS: list[uuid.UUID] = []

# Endpoint identities used by the reconciliation tests (cleaned per test).
_TEST_FQDNS = ("ws01.eitop.test", "ws02.eitop.test", "ws02.other-domain.test")
_TEST_HOSTNAMES = ("ws01", "ws01-dup", "ws02")

OU_HQ = str(uuid.uuid4())
OU_IT = str(uuid.uuid4())
OU_SALES = str(uuid.uuid4())
GRP_ALL = str(uuid.uuid4())
GRP_EMPTY = str(uuid.uuid4())
USER_ALICE = str(uuid.uuid4())
USER_BOB = str(uuid.uuid4())
COMP_WS01 = str(uuid.uuid4())
COMP_WS02 = str(uuid.uuid4())

ALICE_DN = "CN=alice,OU=IT,OU=HQ,DC=eitop,DC=test"
BOB_DN = "CN=bob,OU=Sales,OU=HQ,DC=eitop,DC=test"
FOREIGN_DN = "CN=Foreign-Principal,CN=Foreign,DC=other,DC=test"
WS01_DN = "CN=WS01,OU=IT,OU=HQ,DC=eitop,DC=test"
WS02_DN = "CN=WS02,OU=Sales,OU=HQ,DC=eitop,DC=test"

# S-1-5-21-1234567890 (16 bytes, well-formed AD objectSid)
ALICE_SID = bytes(
    [1, 2, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0, 0xD2, 0x02, 0x96, 0x49]
)
ALICE_SID_STR = "S-1-5-21-1234567890"


def _bind_entry() -> dict:
    return {
        "dn": BIND_DN,
        "attributes": {
            "objectClass": ["top", "person"],
            "cn": "svc-eitop",
            "userPassword": BIND_PASSWORD,
        },
    }


def _base_entries() -> list[dict]:
    """A small but complete directory: 3 OUs, 2 users, 2 groups, 2 computers."""
    return [
        _bind_entry(),
        {
            "dn": SEARCH_BASE,
            "attributes": {
                "objectClass": ["top", "organizationalUnit"],
                "ou": "HQ",
                "objectGUID": OU_HQ,
            },
        },
        {
            "dn": "OU=IT," + SEARCH_BASE,
            "attributes": {
                "objectClass": ["top", "organizationalUnit"],
                "ou": "IT",
                "objectGUID": OU_IT,
            },
        },
        {
            "dn": "OU=Sales," + SEARCH_BASE,
            "attributes": {
                "objectClass": ["top", "organizationalUnit"],
                "ou": "Sales",
                "objectGUID": OU_SALES,
            },
        },
        {
            "dn": ALICE_DN,
            "attributes": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "objectCategory": "person",
                "objectGUID": USER_ALICE,
                "objectSid": ALICE_SID,
                "sAMAccountName": "alice",
                "userPrincipalName": "alice@eitop.test",
                "displayName": "Alice Example",
                "mail": "alice@eitop.test",
                "userAccountControl": "512",
                "department": "IT",
                "title": "Engineer",
            },
        },
        {
            "dn": BOB_DN,
            "attributes": {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "objectCategory": "person",
                "objectGUID": USER_BOB,
                "sAMAccountName": "bob",
                "displayName": "Bob Example",
                "userAccountControl": "514",  # ACCOUNTDISABLE -> enabled False
            },
        },
        {
            "dn": "CN=Team-All,OU=IT," + SEARCH_BASE,
            "attributes": {
                "objectClass": ["top", "group"],
                "objectGUID": GRP_ALL,
                "cn": "Team-All",
                "description": "Everyone",
                # global + security (0x80000002 as signed 32-bit)
                "groupType": "-2147483646",
                "member": [ALICE_DN, BOB_DN, FOREIGN_DN],
            },
        },
        {
            "dn": "CN=Team-Empty,OU=Sales," + SEARCH_BASE,
            "attributes": {
                "objectClass": ["top", "group"],
                "objectGUID": GRP_EMPTY,
                "cn": "Team-Empty",
                # domain local + security (0x80000004)
                "groupType": "-2147483644",
            },
        },
        {
            "dn": WS01_DN,
            "attributes": {
                "objectClass": ["top", "person", "user", "computer"],
                "objectGUID": COMP_WS01,
                "objectSid": ALICE_SID,
                "name": "WS01",
                "dNSHostName": "ws01.eitop.test",
                "operatingSystem": "Windows 11 Pro",
                "operatingSystemVersion": "10.0.22631",
                "userAccountControl": "4096",
            },
        },
        {
            "dn": WS02_DN,
            "attributes": {
                "objectClass": ["top", "person", "user", "computer"],
                "objectGUID": COMP_WS02,
                "name": "WS02",
                "dNSHostName": "ws02.eitop.test",
                "operatingSystem": "Windows 10 Enterprise",
                "userAccountControl": "4096",
            },
        },
    ]


class _MockDirectoryClient(DirectoryLdapClient):
    """Mock-backed client that can fail specific categories on demand."""

    def __init__(self, *args: Any, fail_filters: dict[str, Exception] | None = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._fail_filters = fail_filters or {}

    def paged_search(self, **kwargs: Any):
        for needle, exc in self._fail_filters.items():
            if needle in kwargs.get("search_filter", ""):
                raise exc
        yield from super().paged_search(**kwargs)


def _make_client(entries: list[dict], fail_filters: dict[str, Exception] | None = None):
    def server_factory(ep: Any) -> Any:
        return Server(ep.host, port=ep.port, use_ssl=True, get_info=NONE)

    def connection_factory(server: Any, dn: str, pw: str, ep: Any) -> Any:
        conn = Connection(
            server,
            user=dn,
            password=pw,
            client_strategy=MOCK_SYNC,
            raise_exceptions=True,
        )
        for entry in entries:
            conn.strategy.add_entry(entry["dn"], entry["attributes"])
        return conn

    def builder(row: DirectoryConnection) -> DirectoryLdapClient:
        return _MockDirectoryClient(
            endpoint=factory_module.endpoint_from_connection(row),
            bind_dn=row.bind_username,
            bind_password=BIND_PASSWORD,
            server_factory=server_factory,
            connection_factory=connection_factory,
            probe_on_connect=False,  # mock: no network, no TLS handshake
            fail_filters=fail_filters,
        )

    return builder


@pytest.fixture(autouse=True)
def clean_directory_tables(db):
    """Wipe directory rows + this module's endpoints (shared test DB)."""
    _LAST_RUN_IDS.clear()
    # Endpoints are not owned by this module, but reconciliation tests
    # depend on FQDN uniqueness — leftovers from earlier runs of these
    # very tests would silently break that.
    db.execute(
        delete(Endpoint).where(
            Endpoint.fqdn.in_(_TEST_FQDNS),
        )
    )
    db.execute(
        delete(Endpoint).where(
            Endpoint.hostname.in_(_TEST_HOSTNAMES),
        )
    )
    for model in (
        DirectoryReconciliation,
        DirectorySyncRun,
        DirectoryGroupMembership,
        DirectoryComputer,
        DirectoryGroup,
        DirectoryUser,
        DirectoryOrganizationalUnit,
        DirectoryDomain,
        DirectoryConnection,
    ):
        db.execute(delete(model))
    db.commit()
    yield
    db.rollback()
    for model in (
        DirectoryReconciliation,
        DirectorySyncRun,
        DirectoryGroupMembership,
        DirectoryComputer,
        DirectoryGroup,
        DirectoryUser,
        DirectoryOrganizationalUnit,
        DirectoryDomain,
        DirectoryConnection,
    ):
        db.execute(delete(model))
    db.commit()


@pytest.fixture()
def connection(db) -> DirectoryConnection:
    row = DirectoryConnection(
        name=f"ad-{uuid.uuid4().hex[:8]}",
        domain_dns="eitop.test",
        host="dc01.eitop.test",
        port=636,
        tls_mode="ldaps",
        tls_ca_pem="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        search_base=SEARCH_BASE,
        bind_username=BIND_DN,
        bind_password_encrypted="placeholder-never-valid",
        connect_timeout_seconds=5,
        search_timeout_seconds=5,
        page_size=2,  # small page -> the 3-OU category really paginates
        enabled=True,
        auto_sync=True,
        sync_interval_minutes=60,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _patch_client(monkeypatch, entries: list[dict], fail_filters=None) -> None:
    monkeypatch.setattr(
        factory_module, "build_client", _make_client(entries, fail_filters)
    )


def _start_run(db, connection_row, *, trigger: str = "manual") -> DirectorySyncRun:
    run = DirectorySyncRun(
        connection_id=connection_row.id,
        trigger=trigger,
        status=SYNC_RUNNING,
        category_results=initial_category_results(),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    _LAST_RUN_IDS.append(run.id)
    return run


def _run_sync(db, connection_row, **kwargs) -> str:
    """Start a run and execute it to completion in one step."""
    _start_run(db, connection_row, **kwargs)
    status = execute_sync(_LAST_RUN_IDS[-1])
    db.expire_all()
    return status


def _last_run(db) -> DirectorySyncRun:
    """The run created by the most recent ``_start_run``/``_run_sync``."""
    db.expire_all()
    run = db.get(DirectorySyncRun, _LAST_RUN_IDS[-1])
    assert run is not None, "run row disappeared (cascade?)"
    return run


def _age_all_rows(db, connection_row, days: int) -> None:
    cutoff = datetime.now(UTC) - timedelta(days=days)
    for model in (
        DirectoryOrganizationalUnit,
        DirectoryUser,
        DirectoryGroup,
        DirectoryComputer,
    ):
        db.execute(
            update(model)
            .where(model.connection_id == connection_row.id)
            .values(last_seen_at=cutoff)
        )
    db.commit()


def _count(db, model, connection_row) -> int:
    from sqlalchemy import func

    return int(
        db.scalar(
            select(func.count())
            .select_from(model)
            .where(model.connection_id == connection_row.id)
        )
        or 0
    )


# ---------------------------------------------------------------------------
# Happy path + idempotency
# ---------------------------------------------------------------------------


def test_full_sync_succeeds_and_populates_mirror(db, connection, monkeypatch):
    _patch_client(monkeypatch, _base_entries())
    status = _run_sync(db, connection)

    assert status == SYNC_SUCCESS, {
        k: v
        for k, v in _last_run(db).category_results.items()
        if v.get("status") != "success"
    }
    run = _last_run(db)

    assert run.status == SYNC_SUCCESS
    assert run.finished_at is not None
    assert run.duration_ms is not None and run.duration_ms >= 0

    # Every category succeeded, including the explicit missing gate.
    for category, result in run.category_results.items():
        assert result["status"] == "success", (category, result)
    assert run.errors is None

    assert _count(db, DirectoryDomain, connection) == 1
    assert _count(db, DirectoryOrganizationalUnit, connection) == 3
    assert _count(db, DirectoryUser, connection) == 2
    assert _count(db, DirectoryGroup, connection) == 2
    assert _count(db, DirectoryComputer, connection) == 2

    alice = db.scalar(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection.id,
            DirectoryUser.sam_account_name == "alice",
        )
    )
    assert alice is not None
    assert alice.sid == ALICE_SID_STR
    assert alice.enabled is True
    assert alice.email == "alice@eitop.test"
    assert alice.missing_since is None

    bob = db.scalar(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection.id,
            DirectoryUser.sam_account_name == "bob",
        )
    )
    assert bob is not None
    assert bob.enabled is False  # ACCOUNTDISABLE flag honored

    team_all = db.scalar(
        select(DirectoryGroup).where(
            DirectoryGroup.connection_id == connection.id,
            DirectoryGroup.name == "Team-All",
        )
    )
    assert team_all is not None
    assert team_all.scope == "global"
    assert team_all.category == "security"

    ws01 = db.scalar(
        select(DirectoryComputer).where(
            DirectoryComputer.connection_id == connection.id,
            DirectoryComputer.name == "WS01",
        )
    )
    assert ws01 is not None
    assert ws01.dns_hostname == "ws01.eitop.test"
    assert ws01.os == "Windows 11 Pro"

    # Memberships: resolved locally, foreign principal honestly "unknown".
    members = db.scalars(
        select(DirectoryGroupMembership).where(
            DirectoryGroupMembership.group_id == team_all.id
        )
    ).all()
    assert len(members) == 3
    by_dn = {m.member_dn: m for m in members}
    assert by_dn[ALICE_DN].member_type == "user"
    assert by_dn[ALICE_DN].member_object_guid == USER_ALICE
    assert by_dn[BOB_DN].member_type == "user"
    assert by_dn[FOREIGN_DN].member_type == "unknown"
    assert by_dn[FOREIGN_DN].member_object_guid is None

    empty = db.scalar(
        select(DirectoryGroup).where(
            DirectoryGroup.connection_id == connection.id,
            DirectoryGroup.name == "Team-Empty",
        )
    )
    assert empty is not None
    assert (
        _count_members(db, empty.id) == 0
    )

    # Sanitized audit event exists.
    audit = db.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "directory.sync.succeeded",
            AuditLog.target == str(run.id),
        )
    ).first()
    assert audit is not None
    assert audit.outcome == "success"
    assert BIND_PASSWORD not in (audit.detail or "")
    assert "Traceback" not in (audit.detail or "")


def _count_members(db, group_id) -> int:
    from sqlalchemy import func

    return int(
        db.scalar(
            select(func.count())
            .select_from(DirectoryGroupMembership)
            .where(DirectoryGroupMembership.group_id == group_id)
        )
        or 0
    )


def test_repeated_syncs_never_duplicate_rows(db, connection, monkeypatch):
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS
    first_counts = {
        "ous": _count(db, DirectoryOrganizationalUnit, connection),
        "users": _count(db, DirectoryUser, connection),
        "groups": _count(db, DirectoryGroup, connection),
        "computers": _count(db, DirectoryComputer, connection),
    }
    assert first_counts == {"ous": 3, "users": 2, "groups": 2, "computers": 2}

    # Two more full runs: same directory -> same rows, no duplicates.
    assert _run_sync(db, connection) == SYNC_SUCCESS
    assert _run_sync(db, connection) == SYNC_SUCCESS

    assert {
        "ous": _count(db, DirectoryOrganizationalUnit, connection),
        "users": _count(db, DirectoryUser, connection),
        "groups": _count(db, DirectoryGroup, connection),
        "computers": _count(db, DirectoryComputer, connection),
    } == first_counts

    runs = db.scalars(
        select(DirectorySyncRun).where(
            DirectorySyncRun.connection_id == connection.id,
            DirectorySyncRun.status == SYNC_SUCCESS,
        )
    ).all()
    assert len(runs) == 3
    # Runs 2 and 3 update existing rows instead of creating them.
    assert runs[1].objects_created == 0
    assert runs[1].objects_updated > 0
    assert runs[2].objects_created == 0

    # Exactly one membership edge set: the rebuild replaced, not appended.
    from sqlalchemy import func

    total_members = db.scalar(
        select(func.count())
        .select_from(DirectoryGroupMembership)
        .where(DirectoryGroupMembership.connection_id == connection.id)
    )
    assert int(total_members or 0) == 3


# ---------------------------------------------------------------------------
# Failure handling: rollback, category failure, missing-object gate
# ---------------------------------------------------------------------------


def test_unparseable_entry_fails_category_and_preserves_prior_data(
    db, connection, monkeypatch
):
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS
    assert _count(db, DirectoryUser, connection) == 2

    # Second directory: bob's entry lost its objectGUID (unreadable).
    broken = _base_entries()
    for entry in broken:
        if entry["dn"] == BOB_DN:
            entry["attributes"] = dict(entry["attributes"])
            entry["attributes"].pop("objectGUID", None)
    _patch_client(monkeypatch, broken)

    status = _run_sync(db, connection)
    assert status == SYNC_FAILED

    run = _last_run(db)
    assert run.status == SYNC_FAILED

    results = run.category_results
    assert results["connect"]["status"] == "success"
    assert results["domains"]["status"] == "success"
    assert results["ous"]["status"] == "success"
    assert results["users"]["status"] == "failed"
    assert results["users"]["label"] == "protocol_error"
    assert results["users"]["error_type"] == "UnparseableEntryError"
    # Fail-fast: nothing after users ran, and the gate stayed closed.
    assert results["groups"]["status"] == "skipped"
    assert results["computers"]["status"] == "skipped"
    assert results["memberships"]["status"] == "skipped"
    assert results["missing_scan"]["status"] == "skipped"
    assert results["reconcile"]["status"] == "skipped"

    # Sanitized errors: label + class name only, no entry content.
    assert run.errors and len(run.errors) == 1
    entry = run.errors[0]
    assert entry["category"] == "users"
    assert entry["label"] == "protocol_error"
    assert "alice" not in str(entry)
    assert "bob" not in str(entry)

    # Rollback: the previous mirror is untouched.
    assert _count(db, DirectoryUser, connection) == 2
    assert _count(db, DirectoryOrganizationalUnit, connection) == 3
    bob = db.scalar(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection.id,
            DirectoryUser.sam_account_name == "bob",
        )
    )
    assert bob is not None
    assert bob.missing_since is None


def test_failed_run_never_marks_objects_missing(db, connection, monkeypatch):
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    # Everything is far past the 7-day grace period...
    _age_all_rows(db, connection, days=30)
    assert _count(db, DirectoryUser, connection) == 2

    # ...but the groups category fails, so the gate must stay closed.
    failing = _base_entries()
    _patch_client(
        monkeypatch,
        failing,
        fail_filters={"objectClass=group": TimeoutError("read timed out")},
    )
    status = _run_sync(db, connection)
    assert status == SYNC_FAILED

    run = _last_run(db)
    results = run.category_results
    assert results["users"]["status"] == "success"
    assert results["groups"]["status"] == "failed"
    assert results["groups"]["label"] == "timeout"
    assert results["missing_scan"]["status"] == "skipped"
    assert run.objects_marked_missing == 0
    # Nothing marked missing anywhere — the gate is absolute.
    for model in (
        DirectoryOrganizationalUnit,
        DirectoryUser,
        DirectoryGroup,
        DirectoryComputer,
    ):
        marked = db.scalar(
            select(model.id).where(
                model.connection_id == connection.id,
                model.missing_since.is_not(None),
            )
        )
        assert marked is None, model.__name__


def test_full_success_marks_missing_after_grace_period(db, connection, monkeypatch):
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    _age_all_rows(db, connection, days=30)

    # Alice disappears from the directory; everyone else is still present.
    remaining = [e for e in _base_entries() if e["dn"] != ALICE_DN]
    _patch_client(monkeypatch, remaining)
    status = _run_sync(db, connection)
    assert status == SYNC_SUCCESS

    alice = db.scalar(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection.id,
            DirectoryUser.sam_account_name == "alice",
        )
    )
    assert alice is not None
    assert alice.missing_since is not None  # soft delete, never removed

    bob = db.scalar(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection.id,
            DirectoryUser.sam_account_name == "bob",
        )
    )
    assert bob is not None
    assert bob.missing_since is None  # seen again -> revived / never marked

    run = _last_run(db)
    assert run.category_results["missing_scan"]["status"] == "success"
    assert run.objects_marked_missing >= 1

    # Reappearing objects are revived on a later run.
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS
    db.expire_all()
    alice = db.scalar(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection.id,
            DirectoryUser.sam_account_name == "alice",
        )
    )
    assert alice is not None
    assert alice.missing_since is None


def test_objects_within_grace_period_are_not_marked_missing(
    db, connection, monkeypatch
):
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    _age_all_rows(db, connection, days=2)  # grace period is 7 days

    remaining = [e for e in _base_entries() if e["dn"] != ALICE_DN]
    _patch_client(monkeypatch, remaining)
    assert _run_sync(db, connection) == SYNC_SUCCESS

    alice = db.scalar(
        select(DirectoryUser).where(
            DirectoryUser.connection_id == connection.id,
            DirectoryUser.sam_account_name == "alice",
        )
    )
    assert alice is not None
    assert alice.missing_since is None


def test_missing_search_base_fails_the_domains_stage(db, connection, monkeypatch):
    # Remove the search-base entry entirely -> noSuchObject -> gate closes.
    entries = [e for e in _base_entries() if e["dn"] != SEARCH_BASE]
    _patch_client(monkeypatch, entries)

    status = _run_sync(db, connection)
    assert status == SYNC_FAILED
    run = _last_run(db)
    results = run.category_results
    assert results["domains"]["status"] == "failed"
    assert results["domains"]["label"] == "search_base_not_found"
    assert results["missing_scan"]["status"] == "skipped"
    assert _count(db, DirectoryUser, connection) == 0


def test_undecryptable_credential_fails_with_sanitized_label(db, connection):
    # Real factory (deliberately NOT patched): the stored token is garbage,
    # as if SECRET_KEY had been rotated without re-entering the password.
    status = _run_sync(db, connection)
    assert status == SYNC_FAILED
    run = _last_run(db)
    results = run.category_results
    assert results["connect"]["status"] == "failed"
    assert results["connect"]["label"] == "credential_undecryptable"
    assert "placeholder" not in str(results)


# ---------------------------------------------------------------------------
# Reconciliation (never guesses, never overwrites manual decisions)
# ---------------------------------------------------------------------------


def _endpoint(db, hostname: str, fqdn: str | None) -> Endpoint:
    row = Endpoint(hostname=hostname, fqdn=fqdn, status="active")
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _recon_for(db, connection_row, computer_name: str) -> DirectoryReconciliation:
    return db.scalar(
        select(DirectoryReconciliation)
        .join(DirectoryComputer)
        .where(
            DirectoryReconciliation.connection_id == connection_row.id,
            DirectoryComputer.name == computer_name,
        )
    )


def test_unique_fqdn_match_is_auto_confirmed(db, connection, monkeypatch):
    ep = _endpoint(db, "ws01", "ws01.eitop.test")
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    recon = _recon_for(db, connection, "WS01")
    assert recon is not None
    assert recon.method == "exact_fqdn"
    assert recon.confidence == "high"
    assert recon.status == "matched"
    assert recon.endpoint_id == ep.id
    assert recon.candidates in (None, [])


def test_ambiguous_fqdn_needs_review_never_auto_matches(db, connection, monkeypatch):
    _endpoint(db, "ws01", "ws01.eitop.test")
    _endpoint(db, "ws01-dup", "ws01.eitop.test")  # same FQDN on two endpoints
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    recon = _recon_for(db, connection, "WS01")
    assert recon is not None
    assert recon.status == "needs_review"
    assert recon.endpoint_id is None
    assert recon.candidates is not None and len(recon.candidates) == 2


def test_short_name_match_is_never_auto_confirmed(db, connection, monkeypatch):
    # Endpoint hostname matches the computer's short name, but its FQDN
    # is different -> candidate only.
    ep = _endpoint(db, "ws02", "ws02.other-domain.test")
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    recon = _recon_for(db, connection, "WS02")
    assert recon is not None
    assert recon.method == "short_name"
    assert recon.status == "needs_review"
    assert recon.confidence in ("medium", "low")
    assert recon.endpoint_id is None
    assert recon.candidates == [str(ep.id)]


def test_revoked_endpoints_are_excluded_from_matching(db, connection, monkeypatch):
    ep = _endpoint(db, "ws01", "ws01.eitop.test")
    ep.status = "revoked"
    db.commit()

    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    recon = _recon_for(db, connection, "WS01")
    assert recon is not None
    assert recon.endpoint_id is None
    assert recon.status != "matched"


def test_manual_reconciliation_decisions_are_never_overwritten(
    db, connection, monkeypatch
):
    _endpoint(db, "ws01", "ws01.eitop.test")
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS

    recon = _recon_for(db, connection, "WS01")
    assert recon is not None
    recon.method = "manual"
    recon.status = "rejected"
    recon.endpoint_id = None
    recon.confidence = "low"
    db.commit()

    # A later (successful) sync must leave the operator decision alone.
    assert _run_sync(db, connection) == SYNC_SUCCESS
    db.expire_all()
    recon = _recon_for(db, connection, "WS01")
    assert recon is not None
    assert recon.method == "manual"
    assert recon.status == "rejected"
    assert recon.endpoint_id is None


def test_reconcile_is_recorded_as_successful_category(db, connection, monkeypatch):
    _patch_client(monkeypatch, _base_entries())
    assert _run_sync(db, connection) == SYNC_SUCCESS
    run = _last_run(db)
    assert run.category_results["reconcile"]["status"] == "success"


# ---------------------------------------------------------------------------
# Run lifecycle: 409, stale reaping, enqueue failure, beat tick
# ---------------------------------------------------------------------------


def test_second_concurrent_run_is_rejected_with_409(db, connection):
    first = _start_run(db, connection)
    assert first.status == SYNC_RUNNING

    with pytest.raises(Exception) as excinfo:
        create_sync_run(db, connection, trigger="manual")
    err = excinfo.value
    assert getattr(err, "status", None) == 409
    assert "already in progress" in str(err)

    # Only one running row exists (partial unique index held).
    running = db.scalars(
        select(DirectorySyncRun).where(
            DirectorySyncRun.connection_id == connection.id,
            DirectorySyncRun.status == SYNC_RUNNING,
        )
    ).all()
    assert len(running) == 1
    assert running[0].id == first.id


def test_stale_running_row_is_reaped_so_retries_work(db, connection):
    stale_started = datetime.now(UTC) - timedelta(hours=2)
    stale = DirectorySyncRun(
        connection_id=connection.id,
        trigger="manual",
        status=SYNC_RUNNING,
        category_results=initial_category_results(),
    )
    stale.started_at = stale_started
    db.add(stale)
    db.commit()

    new_run = create_sync_run(db, connection, trigger="manual")
    db.commit()

    db.expire_all()
    stale_row = db.get(DirectorySyncRun, stale.id)
    assert stale_row is not None
    assert stale_row.status == SYNC_FAILED
    assert stale_row.finished_at is not None
    assert stale_row.errors == [
        {
            "category": "connect",
            "label": "stale_run_reaped",
            "error_count": 1,
        }
    ]

    assert new_run.status == SYNC_RUNNING
    running = db.scalars(
        select(DirectorySyncRun).where(
            DirectorySyncRun.connection_id == connection.id,
            DirectorySyncRun.status == SYNC_RUNNING,
        )
    ).all()
    assert [r.id for r in running] == [new_run.id]


def test_enqueue_failure_marks_run_failed_and_allows_retry(db, connection, monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("broker unavailable")

    monkeypatch.setattr(connection_service.celery_app, "send_task", boom)

    with pytest.raises(Exception) as excinfo:
        trigger_sync(db, connection, trigger="manual")
    err = excinfo.value
    assert getattr(err, "status", None) == 503

    # The failed submission is persisted BEFORE the error propagated.
    db.expire_all()
    runs = db.scalars(
        select(DirectorySyncRun).where(
            DirectorySyncRun.connection_id == connection.id
        )
    ).all()
    assert len(runs) == 1
    assert runs[0].status == SYNC_FAILED
    assert runs[0].errors == [
        {
            "category": "connect",
            "label": "task_submission_failed",
            "error_count": 1,
        }
    ]
    assert runs[0].category_results["missing_scan"]["status"] == "skipped"
    assert runs[0].finished_at is not None

    audit = db.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "directory.sync.failed",
            AuditLog.target == str(runs[0].id),
        )
    ).first()
    assert audit is not None
    assert audit.outcome == "failure"
    assert "task_submission_failed" in (audit.detail or "")

    # Retrying is possible: no lingering 'running' row blocks the next try.
    submitted: list[list[str]] = []

    def capture(task_name, args=None, **_kwargs):
        submitted.append([task_name, *(args or [])])

    monkeypatch.setattr(connection_service.celery_app, "send_task", capture)
    run = trigger_sync(db, connection, trigger="manual")
    db.commit()
    assert run.status == SYNC_RUNNING
    assert submitted and submitted[0][0] == "eitop.sync_directory"
    assert submitted[0][1] == str(run.id)


def test_trigger_sync_success_writes_audit_without_secrets(db, connection, monkeypatch):
    submitted: list[str] = []
    monkeypatch.setattr(
        connection_service.celery_app,
        "send_task",
        lambda name, args=None, **kw: submitted.append(name),
    )
    actor = _actor(db)
    run = trigger_sync(db, connection, trigger="manual", actor=actor)
    db.commit()
    assert submitted == ["eitop.sync_directory"]

    audit = db.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "directory.sync.triggered",
            AuditLog.target == str(run.id),
        )
    ).first()
    assert audit is not None
    assert audit.actor_user_id == actor.id
    assert BIND_PASSWORD not in (audit.detail or "")
    assert "placeholder" not in (audit.detail or "")


def _actor(db):
    """Minimal authenticated user for audit attribution in these tests."""
    from app.core.security import hash_password
    from app.models import User

    user = User(
        email=f"dir-actor-{uuid.uuid4().hex[:8]}@example.com",
        full_name="Directory Tester",
        hashed_password=hash_password("Str0ng!Passw0rd#2026"),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_enqueue_due_syncs_respects_interval_and_disables(db, connection, monkeypatch):
    submitted: list[str] = []
    monkeypatch.setattr(
        connection_service.celery_app,
        "send_task",
        lambda name, args=None, **kw: submitted.append(name),
    )

    # No prior run -> due now.
    assert connection_service.enqueue_due_syncs() == 1
    assert len(submitted) == 1

    # The run we just created is recent -> not due again.
    assert connection_service.enqueue_due_syncs() == 0
    assert len(submitted) == 1

    # Disabled connections are never enqueued.
    connection.enabled = False
    db.commit()
    assert connection_service.enqueue_due_syncs() == 0


def test_stale_task_delivery_after_completion_is_skipped(db, connection, monkeypatch):
    _patch_client(monkeypatch, _base_entries())
    run = _start_run(db, connection)
    assert execute_sync(run.id) == SYNC_SUCCESS
    # Duplicate delivery of the same task: the run is already terminal.
    assert execute_sync(run.id) == "skipped"


def test_run_for_deleted_connection_is_skipped(db, connection, monkeypatch):
    run = _start_run(db, connection)
    db.delete(connection)
    db.commit()
    assert execute_sync(run.id) == "skipped"
