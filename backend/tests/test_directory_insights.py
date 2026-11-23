"""Directory findings engine tests (Phase 3.2.1).

Covers the three plan fixes and the lifecycle/concurrency contract:
- Fix 1: privileged SID identification (5-token BUILTIN, exact 8-token
  domain boundary, DN/CN fallback flagged ``dn_fallback``);
- Fix 2: inventory completeness from the NEWEST run (an older success
  never backstops a newer failure);
- Fix 3: distribution-group nesting is an anomaly only — it never
  downgrades privilege visibility;
- lifecycle: create/refresh/auto-resolve/reopen, suppressed immunity,
  audit rows with ``actor_email="system"``;
- concurrency: advisory-lock collision skips with ZERO writes;
- fingerprints: deterministic, path-independent, bounded;
- absence rules gated on complete inventory; missing/stale split;
- static guarantee: insights never imports the LDAP client.

PostgreSQL is real (shared test database); no LDAP server is involved —
all directory data is seeded mirror rows.
"""

from __future__ import annotations

import ast
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core.config import Settings
from app.core.database import SessionLocal
from app.models import (
    AuditLog,
    DirectoryComputer,
    DirectoryConnection,
    DirectoryDomain,
    DirectoryFinding,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectoryOrganizationalUnit,
    DirectoryReconciliation,
    DirectorySyncRun,
    DirectoryUser,
    Endpoint,
    User,
)
from app.services.directory import insights
from app.services.directory.insights import (
    INVENTORY_CATEGORIES,
    RULE_COMPUTER_STALE,
    RULE_DIRECT,
    RULE_DISABLED_MEMBER,
    RULE_DISABLED_PERSIST,
    RULE_DIST_ANOMALY,
    RULE_INVENTORY_EMPTY,
    RULE_MISSING_GRACE,
    RULE_NO_LOGON,
    RULE_SYNC_FRESHNESS,
    RULE_TRANSITIVE,
    RULE_UNKNOWN_MEMBER,
    RULE_USER_INACTIVE,
    builtin_privileged_rid,
    connection_fingerprint,
    domain_privileged_rid,
    identify_privileged_groups,
    inventory_complete,
    member_fingerprint,
    newest_sync_run,
    object_fingerprint,
    object_key,
    recompute_connection,
)
from pydantic import ValidationError
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session
from tests.conftest import requires_postgres

pytestmark = requires_postgres

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)

DS = "S-1-5-21-111-222-333"
BASE = "DC=eitop,DC=test"

DA_DN = f"CN=Domain Admins,CN=Users,{BASE}"
NESTED_DN = f"CN=Ops Nested,CN=Users,{BASE}"
PARTY_DN = f"CN=Party,CN=Users,{BASE}"
MYSTERY_DN = f"CN=Mystery,CN=Users,{BASE}"
GHOST_DN = f"CN=Ghost,CN=Users,{BASE}"
FSP_DN = f"CN={DS}-1105,CN=ForeignSecurityPrincipals,{BASE}"

ALICE_DN = f"CN=alice,CN=Users,{BASE}"
BOB_DN = f"CN=bob,CN=Users,{BASE}"
CAROL_DN = f"CN=carol,CN=Users,{BASE}"
DAVE_DN = f"CN=dave,CN=Users,{BASE}"

G_DA = "aaaaaaaa-0000-0000-0000-000000000001"
G_NESTED = "aaaaaaaa-0000-0000-0000-000000000002"
G_PARTY = "aaaaaaaa-0000-0000-0000-000000000003"
G_MYSTERY = "aaaaaaaa-0000-0000-0000-000000000004"
G_ALICE = "bbbbbbbb-0000-0000-0000-000000000001"
G_BOB = "bbbbbbbb-0000-0000-0000-000000000002"
G_CAROL = "bbbbbbbb-0000-0000-0000-000000000003"
G_DAVE = "bbbbbbbb-0000-0000-0000-000000000004"

_TEST_FQDNS = ("ws05.eitop.test", "ws06.eitop.test", "ws07.eitop.test")


def _complete_results() -> dict:
    return {category: {"status": "success"} for category in INVENTORY_CATEGORIES}


def _wipe(db: Session) -> None:
    db.execute(delete(DirectoryFinding))
    # NOTE: audit_logs is append-only (DB trigger blocks DELETE) — audit
    # rows are never cleaned here; every assertion scopes them to the
    # test's own connection_id (unique per test).
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
    db.execute(delete(Endpoint).where(Endpoint.fqdn.in_(_TEST_FQDNS)))
    db.commit()


@pytest.fixture(autouse=True)
def clean_insight_tables(db):
    _wipe(db)
    yield
    db.rollback()
    _wipe(db)


def _group(db, conn, *, guid, dn, name, sid, category, scope="global"):
    row = DirectoryGroup(
        connection_id=conn.id,
        object_guid=guid,
        distinguished_name=dn,
        sid=sid,
        name=name,
        scope=scope,
        category=category,
    )
    db.add(row)
    return row


def _user(db, conn, *, guid, dn, sam, enabled, logon_days_ago, no_logon=False):
    row = DirectoryUser(
        connection_id=conn.id,
        object_guid=guid,
        distinguished_name=dn,
        sid=f"{DS}-{1000 + int(guid[-1])}",
        sam_account_name=sam,
        enabled=enabled,
        last_logon_at=None if no_logon else NOW - timedelta(days=logon_days_ago),
    )
    db.add(row)
    return row


def _computer(db, conn, *, guid, name, enabled=True, logon_days_ago=10, missing_days=None):
    row = DirectoryComputer(
        connection_id=conn.id,
        object_guid=guid,
        distinguished_name=f"CN={name},CN=Computers,{BASE}",
        sid=f"{DS}-{2000 + int(guid[-1])}",
        name=name,
        dns_hostname=f"{name.lower()}.eitop.test",
        enabled=enabled,
        last_logon_at=NOW - timedelta(days=logon_days_ago),
        missing_since=(
            NOW - timedelta(days=missing_days) if missing_days is not None else None
        ),
    )
    db.add(row)
    return row


def _edge(db, conn, group_id, member_type, member_dn, member_guid=None):
    db.add(
        DirectoryGroupMembership(
            connection_id=conn.id,
            group_id=group_id,
            member_type=member_type,
            member_dn=member_dn,
            member_object_guid=member_guid,
        )
    )


def _add_run(db, conn, *, status="success", results=None, started_at=NOW - timedelta(minutes=5)):
    run = DirectorySyncRun(
        connection_id=conn.id,
        started_at=started_at,
        finished_at=started_at + timedelta(minutes=1),
        status=status,
        trigger="scheduled",
        category_results=_complete_results() if results is None else results,
    )
    db.add(run)
    db.commit()
    return run


@pytest.fixture()
def connection(db) -> DirectoryConnection:
    """Base scenario: complete inventory, clean graph (=> full visibility).

    Domain Admins (SID-proven) directly holds alice; nested security
    group "Ops Nested" holds disabled bob (transitive); distribution
    group "Party" is a direct member (anomaly only).
    """
    conn = DirectoryConnection(
        name=f"ad-{uuid.uuid4().hex[:8]}",
        domain_dns="eitop.test",
        host="dc01.eitop.test",
        port=636,
        tls_mode="ldaps",
        search_base=BASE,
        bind_username="CN=svc,CN=Users," + BASE,
        bind_password_encrypted="placeholder-never-valid",
        enabled=True,
        auto_sync=True,
        sync_interval_minutes=60,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)

    db.add(
        DirectoryDomain(
            connection_id=conn.id,
            domain_dns="eitop.test",
            distinguished_name=BASE,
            sid=DS,
        )
    )
    da = _group(
        db, conn, guid=G_DA, dn=DA_DN, name="Domain Admins", sid=f"{DS}-512",
        category="security",
    )
    nested = _group(
        db, conn, guid=G_NESTED, dn=NESTED_DN, name="Ops Nested", sid=f"{DS}-1001",
        category="security",
    )
    _group(
        db, conn, guid=G_PARTY, dn=PARTY_DN, name="Party", sid=f"{DS}-1002",
        category="distribution", scope=None,
    )
    db.commit()

    alice = _user(
        db, conn, guid=G_ALICE, dn=ALICE_DN, sam="alice", enabled=True,
        logon_days_ago=10,
    )
    bob = _user(
        db, conn, guid=G_BOB, dn=BOB_DN, sam="bob", enabled=False,
        logon_days_ago=10,
    )
    carol = _user(
        db, conn, guid=G_CAROL, dn=CAROL_DN, sam="carol", enabled=True,
        logon_days_ago=200,
    )
    dave = _user(
        db, conn, guid=G_DAVE, dn=DAVE_DN, sam="dave", enabled=True,
        logon_days_ago=0, no_logon=True,
    )
    ws01 = _computer(db, conn, guid="cccccccc-0000-0000-0000-000000000001", name="WS01")
    ws02 = _computer(
        db, conn, guid="cccccccc-0000-0000-0000-000000000002", name="WS02",
        enabled=False,
    )
    ws03 = _computer(
        db, conn, guid="cccccccc-0000-0000-0000-000000000003", name="WS03",
        logon_days_ago=200,
    )
    ws04 = _computer(
        db, conn, guid="cccccccc-0000-0000-0000-000000000004", name="WS04",
        missing_days=30,
    )
    ws05 = _computer(
        db, conn, guid="cccccccc-0000-0000-0000-000000000005", name="WS05",
        missing_days=30,
    )
    db.commit()

    _edge(db, conn, da.id, "user", ALICE_DN, G_ALICE)
    _edge(db, conn, da.id, "group", NESTED_DN, G_NESTED)
    _edge(db, conn, nested.id, "user", BOB_DN, G_BOB)
    _edge(db, conn, da.id, "group", PARTY_DN, G_PARTY)

    endpoint = Endpoint(hostname="ws05", fqdn="ws05.eitop.test", status="active")
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    db.add(
        DirectoryReconciliation(
            connection_id=conn.id,
            computer_id=ws05.id,
            endpoint_id=endpoint.id,
            method="exact_fqdn",
            confidence="high",
            status="matched",
        )
    )
    db.commit()
    _add_run(db, conn)
    # Silence unused warnings for seed rows used only for absence rules.
    assert alice and bob and carol and dave and ws01 and ws02 and ws03 and ws04
    return conn


def _recompute(db, conn, **kwargs) -> dict:
    kwargs.setdefault("now", NOW)
    return recompute_connection(db, conn.id, **kwargs)


def _rows(db, conn, rule: str | None = None, dn: str | None = None) -> list[DirectoryFinding]:
    stmt = select(DirectoryFinding).where(DirectoryFinding.connection_id == conn.id)
    if rule is not None:
        stmt = stmt.where(DirectoryFinding.rule_key == rule)
    if dn is not None:
        stmt = stmt.where(DirectoryFinding.subject_dn == dn)
    return list(db.scalars(stmt).all())


def _one(db, conn, rule: str, dn: str) -> DirectoryFinding:
    rows = _rows(db, conn, rule, dn)
    assert len(rows) == 1, f"expected 1 {rule} row for {dn}, got {len(rows)}"
    return rows[0]


def _audit_events(
    db: Session, event_type: str, conn: DirectoryConnection
) -> list[AuditLog]:
    """Audit rows of one event type, scoped to this test's connection.

    The audit trail is append-only (never cleaned up), and every system
    event detail carries the connection_id — that is the isolation key.
    """
    return list(
        db.scalars(
            select(AuditLog).where(
                AuditLog.event_type == event_type,
                AuditLog.detail.like(f"%{conn.id}%"),
            )
        ).all()
    )


# --- Fix 1: privileged SID identification ------------------------------------


def test_builtin_sid_exact_five_tokens():
    assert builtin_privileged_rid("S-1-5-32-544") == 544
    assert builtin_privileged_rid("S-1-5-32-548") == 548
    assert builtin_privileged_rid("S-1-5-32-552") == 552


def test_builtin_sid_rejects_wrong_shapes():
    # Wrong token count (six tokens) — the classic long-SID mistake.
    assert builtin_privileged_rid("S-1-5-32-544-1") is None
    # Domain SID pretending to be builtin.
    assert builtin_privileged_rid(f"{DS}-544") is None
    # Leading zero RID.
    assert builtin_privileged_rid("S-1-5-32-0544") is None
    # Non-numeric RID.
    assert builtin_privileged_rid("S-1-5-32-5x4") is None
    # Opt-off RIDs: 547 (Power Users) and 511 are not privileged.
    assert builtin_privileged_rid("S-1-5-32-547") is None
    assert builtin_privileged_rid("S-1-5-32-511") is None
    assert builtin_privileged_rid(None) is None
    assert builtin_privileged_rid("") is None


def test_domain_sid_exact_boundary_accepts_privileged_rids():
    assert domain_privileged_rid(f"{DS}-512", DS) == 512
    assert domain_privileged_rid(f"{DS}-518", DS) == 518
    assert domain_privileged_rid(f"{DS}-519", DS) == 519
    assert domain_privileged_rid(f"{DS}-520", DS) == 520


def test_domain_sid_rejects_non_privileged_and_opt_off_rids():
    assert domain_privileged_rid(f"{DS}-517", DS) is None  # opt-off
    assert domain_privileged_rid(f"{DS}-511", DS) is None  # never privileged
    assert domain_privileged_rid(f"{DS}-513", DS) is None  # plain Domain Users


def test_domain_sid_rejects_string_prefix_collisions():
    # startswith("S-1-5-21-111-222-333") is TRUE for this SID, but the
    # token boundary differs (3330 vs 333) — must never match.
    evil = "S-1-5-21-111-222-3330-512"
    assert evil.startswith(DS)
    assert domain_privileged_rid(evil, DS) is None
    # Wrong domain entirely.
    assert domain_privileged_rid("S-1-5-21-9-9-9-512", DS) is None


def test_domain_sid_rejects_malformed_tokens():
    assert domain_privileged_rid(f"{DS}-0512", DS) is None  # leading zero
    assert domain_privileged_rid("S-1-5-21-111-222-512", DS) is None  # 7 tokens
    assert domain_privileged_rid(f"{DS}-512", "S-1-5-21-1-2") is None  # bad domain
    assert domain_privileged_rid(None, DS) is None
    assert domain_privileged_rid(f"{DS}-512", None) is None


def test_identify_privileged_groups_sid_and_dn_fallback(db, connection):
    conn = connection
    # SID-proven group (already seeded: Domain Admins).
    # CN fallback candidates: only rows with sid IS NULL qualify.
    db.add(
        DirectoryGroup(
            connection_id=conn.id,
            object_guid="dddddddd-0000-0000-0000-000000000001",
            distinguished_name=f"CN=Enterprise Admins,CN=Users,{BASE}",
            sid=None,
            name="Enterprise Admins",
            scope="global",
            category="security",
        )
    )
    db.add(
        DirectoryGroup(
            connection_id=conn.id,
            object_guid="dddddddd-0000-0000-0000-000000000002",
            distinguished_name=f"CN=Power Users,CN=Users,{BASE}",
            sid=None,
            name="Power Users",
            scope=None,
            category=None,
        )
    )
    # Name matches but a NON-privileged SID is present → no fallback.
    db.add(
        DirectoryGroup(
            connection_id=conn.id,
            object_guid="dddddddd-0000-0000-0000-000000000003",
            distinguished_name=f"CN=Fake Admins,CN=Users,{BASE}",
            sid=f"{DS}-1105",
            name="Domain Admins",
            scope="global",
            category="security",
        )
    )
    db.commit()

    found = identify_privileged_groups(db, conn.id)
    by_name = {g.name: g for g in found}
    assert set(by_name) == {"Domain Admins", "Enterprise Admins"}
    assert by_name["Domain Admins"].detection == "sid"
    assert by_name["Domain Admins"].rid == 512
    assert by_name["Enterprise Admins"].detection == "dn_fallback"
    assert by_name["Enterprise Admins"].rid == 519
    assert "Power Users" not in by_name


# --- Fix 2: inventory completeness from the NEWEST run -----------------------


def test_inventory_complete_success_run(db, connection):
    assert inventory_complete(db, connection.id) is True


def test_inventory_complete_ignores_older_success(db, connection):
    # Older success exists, but the NEWEST run failed → never fall back.
    _add_run(
        db, connection, status="failed", started_at=NOW + timedelta(minutes=5),
        results={c: {"status": "failed"} for c in INVENTORY_CATEGORIES},
    )
    run = newest_sync_run(db, connection.id)
    assert run is not None and run.status == "failed"
    assert inventory_complete(db, connection.id) is False


def test_inventory_complete_orders_both_ways(db, connection):
    # Failed run BEFORE the success does not matter: newest wins.
    _add_run(
        db, connection, status="failed", started_at=NOW - timedelta(minutes=30),
        results={c: {"status": "failed"} for c in INVENTORY_CATEGORIES},
    )
    assert inventory_complete(db, connection.id) is True


def test_inventory_complete_newest_running(db, connection):
    _add_run(db, connection, status="running", started_at=NOW + timedelta(minutes=1))
    assert inventory_complete(db, connection.id) is False


def test_inventory_complete_missing_category_key(db, connection):
    results = _complete_results()
    del results["reconcile"]
    run = newest_sync_run(db, connection.id)
    run.category_results = results
    db.commit()
    assert inventory_complete(db, connection.id) is False


def test_inventory_complete_category_not_success(db, connection):
    results = _complete_results()
    results["memberships"] = {"status": "failed", "error_count": 1}
    run = newest_sync_run(db, connection.id)
    run.category_results = results
    db.commit()
    assert inventory_complete(db, connection.id) is False


def test_inventory_complete_empty_results(db, connection):
    run = newest_sync_run(db, connection.id)
    run.category_results = {}
    db.commit()
    assert inventory_complete(db, connection.id) is False


def test_inventory_complete_no_run(db, connection):
    db.execute(delete(DirectorySyncRun).where(DirectorySyncRun.connection_id == connection.id))
    db.commit()
    assert inventory_complete(db, connection.id) is False
    assert newest_sync_run(db, connection.id) is None


def test_pipeline_matches_sync_engine():
    # Local duplicate stays honest: identical to the engine's PIPELINE.
    from app.services.directory.sync_engine import PIPELINE

    assert INVENTORY_CATEGORIES == PIPELINE
    assert len(INVENTORY_CATEGORIES) == 9


# --- Findings generation: privileged graph -----------------------------------


def test_direct_member_finding_full_visibility(db, connection):
    result = _recompute(db, connection)
    assert result["skipped"] is False
    assert result["privilege_visibility"] == "full"
    assert result["visibility_reasons"] == []
    assert result["inventory_complete"] is True

    row = _one(db, connection, RULE_DIRECT, ALICE_DN)
    assert row.severity == "high"
    assert row.status == "open"
    assert row.access == "direct"
    assert row.subject_type == "user"
    assert row.subject_guid == G_ALICE
    assert row.subject_name == "alice"
    assert row.first_seen_at == NOW
    assert row.last_seen_at == NOW
    assert row.detail["hops"] == 1
    assert row.detail["confirmed_security"] is True
    assert row.detail["privilege_visibility"] == "full"
    assert row.detail["path"][0] == DA_DN


def test_transitive_member_nested_group(db, connection):
    _recompute(db, connection)
    row = _one(db, connection, RULE_TRANSITIVE, BOB_DN)
    assert row.severity == "high"
    assert row.access == "transitive"
    assert row.detail["hops"] == 2
    assert row.detail["path"] == [DA_DN, NESTED_DN, BOB_DN]


def test_nested_group_itself_is_direct_member(db, connection):
    _recompute(db, connection)
    row = _one(db, connection, RULE_DIRECT, NESTED_DN)
    assert row.subject_type == "group"
    assert row.severity == "high"


def test_disabled_member_of_privileged_group(db, connection):
    _recompute(db, connection)
    row = _one(db, connection, RULE_DISABLED_MEMBER, BOB_DN)
    assert row.severity == "high"
    assert row.subject_type == "user"
    assert row.detail["hops"] == 2


def test_distribution_group_is_anomaly_only_never_partial(db, connection):
    # Fix 3: distribution branch under a privileged group must NOT
    # downgrade visibility — anomaly finding only.
    result = _recompute(db, connection)
    assert result["privilege_visibility"] == "full"
    assert result["visibility_reasons"] == []

    row = _one(db, connection, RULE_DIST_ANOMALY, PARTY_DN)
    assert row.severity == "low"
    assert row.subject_type == "group"
    assert row.access is None
    assert row.detail["category"] == "distribution"
    # No membership finding exists for the distribution group.
    assert _rows(db, connection, RULE_DIRECT, PARTY_DN) == []
    assert _rows(db, connection, RULE_TRANSITIVE, PARTY_DN) == []


def test_unknown_fsp_member_is_unknown_finding(db, connection):
    conn = connection
    da = db.scalar(select(DirectoryGroup).where(DirectoryGroup.distinguished_name == DA_DN))
    _edge(db, conn, da.id, "unknown", FSP_DN, None)
    db.commit()

    result = _recompute(db, conn)
    assert result["privilege_visibility"] == "partial"
    assert "unresolved_member" in result["visibility_reasons"]

    row = _one(db, conn, RULE_UNKNOWN_MEMBER, FSP_DN)
    assert row.severity == "medium"
    assert row.subject_type == "unknown"
    assert row.subject_guid is None
    assert row.access == "direct"
    assert row.detail["privilege_visibility"] == "partial"


def test_typed_member_without_mirror_row_is_unknown(db, connection):
    conn = connection
    da = db.scalar(select(DirectoryGroup).where(DirectoryGroup.distinguished_name == DA_DN))
    _edge(db, conn, da.id, "user", f"CN=ghost-user,CN=Users,{BASE}", G_ALICE)
    db.commit()
    result = _recompute(db, conn)
    assert "unresolved_member" in result["visibility_reasons"]
    rows = _rows(db, conn, RULE_UNKNOWN_MEMBER, f"CN=ghost-user,CN=Users,{BASE}")
    assert len(rows) == 1
    assert rows[0].subject_guid is None


def test_missing_group_branch_marks_partial(db, connection):
    conn = connection
    da = db.scalar(select(DirectoryGroup).where(DirectoryGroup.distinguished_name == DA_DN))
    _edge(db, conn, da.id, "group", GHOST_DN, None)
    db.commit()
    result = _recompute(db, conn)
    assert result["privilege_visibility"] == "partial"
    assert "missing_group" in result["visibility_reasons"]
    row = _one(db, conn, RULE_UNKNOWN_MEMBER, GHOST_DN)
    assert row.subject_type == "unknown"


def test_untyped_intermediate_downgrades_and_marks_partial(db, connection):
    conn = connection
    da = db.scalar(select(DirectoryGroup).where(DirectoryGroup.distinguished_name == DA_DN))
    mystery = _group(
        db, conn, guid=G_MYSTERY, dn=MYSTERY_DN, name="Mystery", sid=f"{DS}-1003",
        category=None, scope=None,
    )
    db.commit()
    _edge(db, conn, da.id, "group", MYSTERY_DN, G_MYSTERY)
    _edge(db, conn, mystery.id, "user", CAROL_DN, G_CAROL)
    db.commit()

    result = _recompute(db, conn)
    assert result["privilege_visibility"] == "partial"
    assert "untyped_group" in result["visibility_reasons"]

    row = _one(db, conn, RULE_TRANSITIVE, CAROL_DN)
    assert row.severity == "medium"  # unconfirmed → downgrade
    assert row.detail["confirmed_security"] is False
    # Distribution branch (if any) still does not cause this: visibility
    # was full before this test added the untyped group.
    assert "distribution" not in " ".join(result["visibility_reasons"])


def test_cycle_detection_marks_partial(db, connection):
    conn = connection
    nested = db.scalar(
        select(DirectoryGroup).where(DirectoryGroup.distinguished_name == NESTED_DN)
    )
    _edge(db, conn, nested.id, "group", DA_DN, G_DA)  # cycle back to DA
    db.commit()

    result = _recompute(db, conn)
    assert result["privilege_visibility"] == "partial"
    assert "cycle" in result["visibility_reasons"]
    # Traversal still terminated and produced the direct findings.
    assert _rows(db, conn, RULE_DIRECT, ALICE_DN)


def test_depth_cap_truncates_and_marks_partial(db, connection):
    # max_depth=1: only direct members of the privileged group.
    result = _recompute(
        db, connection, settings=Settings(directory_nested_group_max_depth=1)
    )
    assert result["privilege_visibility"] == "partial"
    assert "truncated_depth" in result["visibility_reasons"]
    assert _rows(db, connection, RULE_TRANSITIVE, BOB_DN) == []
    assert _rows(db, connection, RULE_DIRECT, ALICE_DN)


def test_path_independence_and_alternate_paths(db, connection):
    conn = connection
    nested = db.scalar(
        select(DirectoryGroup).where(DirectoryGroup.distinguished_name == NESTED_DN)
    )
    # Second route to alice: DA → nested → alice.
    _edge(db, conn, nested.id, "user", ALICE_DN, G_ALICE)
    db.commit()

    result = _recompute(db, conn)
    rows = _rows(db, conn, RULE_DIRECT, ALICE_DN)
    assert len(rows) == 1  # both routes collapse into ONE row
    assert rows[0].detail["hops"] == 1  # shortest path wins
    assert rows[0].detail["path"] == [DA_DN, ALICE_DN]
    assert len(rows[0].detail["alternate_paths"]) == 1
    assert len(rows[0].detail["alternate_paths"]) <= 3
    assert result["privilege_visibility"] in ("full", "partial")


# --- Fingerprints -------------------------------------------------------------


def test_fingerprint_formats_are_deterministic():
    assert member_fingerprint("r", "g:abc", "n:def") == "r|m=g:abc|p=n:def"
    assert object_fingerprint("r", "n:abc") == "r|o=n:abc"
    conn_id = uuid.uuid4()
    assert connection_fingerprint("r", conn_id) == f"r|c={conn_id}"


def test_fingerprint_guid_keyed_survives_rename():
    dn_before = f"CN=alice,CN=Users,{BASE}"
    dn_after = f"CN=alice,OU=Moved,{BASE}"
    assert object_key(G_ALICE, dn_before) == object_key(G_ALICE, dn_after)


def test_fingerprint_dn_hash_is_case_insensitive_and_bounded():
    assert object_key(None, "CN=A,DC=X") == object_key(None, "cn=a,dc=x")
    key = object_key(None, "CN=" + "x" * 900 + f",{BASE}")
    assert key.startswith("n:") and len(key) == 2 + 24


def test_fingerprint_rejects_oversized_and_invalid():
    with pytest.raises(ValueError):
        object_fingerprint("x" * 200, "o:k")
    with pytest.raises(ValueError):
        object_fingerprint("rule with spaces", "o:k")
    with pytest.raises(ValueError):
        object_key(None, None)


def test_fingerprint_row_length_within_column(db, connection):
    _recompute(db, connection)
    rows = _rows(db, connection)
    assert rows
    assert all(len(r.fingerprint) <= 160 for r in rows)
    assert len({r.fingerprint for r in rows}) == len(rows)  # unique per connection


def test_fingerprint_stable_across_dn_rename(db, connection):
    conn = connection
    _recompute(db, conn)
    before = _one(db, conn, RULE_DIRECT, ALICE_DN)
    fp = before.fingerprint

    # Rename alice (mirror row + edge DN); GUID is unchanged.
    alice = db.scalar(select(DirectoryUser).where(DirectoryUser.sam_account_name == "alice"))
    new_dn = f"CN=alice,OU=People,{BASE}"
    alice.distinguished_name = new_dn
    edge = db.scalar(
        select(DirectoryGroupMembership).where(
            DirectoryGroupMembership.member_dn == ALICE_DN
        )
    )
    edge.member_dn = new_dn
    db.commit()

    _recompute(db, conn)
    rows = _rows(db, conn, RULE_DIRECT, new_dn)
    assert len(rows) == 1
    assert rows[0].id == before.id  # same row, refreshed — not recreated
    assert rows[0].fingerprint == fp


# --- Lifecycle ----------------------------------------------------------------


def test_create_then_refresh_preserves_first_seen(db, connection):
    first = _recompute(db, connection)
    assert first["created"] > 0
    assert first["reopened"] == 0

    row = _one(db, connection, RULE_DIRECT, ALICE_DN)
    created_audit = _audit_events(db, "directory.finding.created", connection)
    assert len(created_audit) == first["created"]
    assert all(a.actor_email == "system" for a in created_audit)

    second = _recompute(db, connection, now=LATER)
    assert second["created"] == 0
    assert second["refreshed"] >= 1
    refetched = _one(db, connection, RULE_DIRECT, ALICE_DN)
    assert refetched.id == row.id
    assert refetched.first_seen_at == NOW  # immutable
    assert refetched.last_seen_at == LATER  # advanced
    assert refetched.status == "open"
    # Refresh is not a transition: no extra audit rows.
    assert (
        len(_audit_events(db, "directory.finding.created", connection))
        == first["created"]
    )


def test_auto_resolve_when_condition_vanishes(db, connection):
    conn = connection
    _recompute(db, conn)
    nested = db.scalar(
        select(DirectoryGroup).where(DirectoryGroup.distinguished_name == NESTED_DN)
    )
    db.execute(
        delete(DirectoryGroupMembership).where(
            DirectoryGroupMembership.group_id == nested.id,
            DirectoryGroupMembership.member_dn == BOB_DN,
        )
    )
    db.commit()

    result = _recompute(db, conn, now=LATER)
    assert result["inventory_complete"] is True
    assert result["resolved"] >= 2  # transitive + disabled rows

    for rule in (RULE_TRANSITIVE, RULE_DISABLED_MEMBER):
        row = _one(db, conn, rule, BOB_DN)
        assert row.status == "resolved"
        assert row.resolved_at == LATER

    resolved_audit = _audit_events(db, "directory.finding.resolved", conn)
    assert resolved_audit
    assert all(a.actor_email == "system" for a in resolved_audit)
    targets = {a.target for a in resolved_audit}
    assert any(t and t.startswith(RULE_TRANSITIVE) for t in targets)


def test_no_auto_resolve_without_complete_inventory(db, connection):
    conn = connection
    _recompute(db, conn)
    nested = db.scalar(
        select(DirectoryGroup).where(DirectoryGroup.distinguished_name == NESTED_DN)
    )
    db.execute(
        delete(DirectoryGroupMembership).where(
            DirectoryGroupMembership.group_id == nested.id,
            DirectoryGroupMembership.member_dn == BOB_DN,
        )
    )
    # Newest run now failed → inventory incomplete → NO auto-resolve.
    _add_run(
        db, conn, status="failed", started_at=NOW + timedelta(minutes=5),
        results={c: {"status": "failed"} for c in INVENTORY_CATEGORIES},
    )

    result = _recompute(db, conn, now=LATER)
    assert result["inventory_complete"] is False
    assert result["privilege_visibility"] == "insufficient"
    assert "inventory_incomplete" in result["visibility_reasons"]
    assert result["resolved"] == 0

    for rule in (RULE_TRANSITIVE, RULE_DISABLED_MEMBER):
        row = _one(db, conn, rule, BOB_DN)
        assert row.status == "open"
    # Absence rules also pause: the inactive-user row stays open untouched.
    assert _one(db, conn, RULE_USER_INACTIVE, CAROL_DN).status == "open"
    # Connection findings reflect the bad newest run.
    assert _rows(db, conn, RULE_SYNC_FRESHNESS)
    assert _rows(db, conn, RULE_INVENTORY_EMPTY)


def test_resolved_finding_reopens_on_recurrence(db, connection):
    from app.core.security import hash_password

    conn = connection
    _recompute(db, conn)
    row = _one(db, conn, RULE_TRANSITIVE, BOB_DN)
    first_seen = row.first_seen_at

    # Resolve: condition vanishes with a complete inventory.
    nested = db.scalar(
        select(DirectoryGroup).where(DirectoryGroup.distinguished_name == NESTED_DN)
    )
    db.execute(
        delete(DirectoryGroupMembership).where(
            DirectoryGroupMembership.group_id == nested.id,
            DirectoryGroupMembership.member_dn == BOB_DN,
        )
    )
    db.commit()
    _recompute(db, conn, now=LATER)
    row = _one(db, conn, RULE_TRANSITIVE, BOB_DN)
    assert row.status == "resolved"

    # An operator had acknowledged it before it resolved.
    ack_user = User(
        email=f"ack-{uuid.uuid4().hex[:8]}@example.com",
        full_name="Ack User",
        hashed_password=hash_password("Str0ng!Passw0rd#2026"),
    )
    db.add(ack_user)
    db.commit()
    row.acknowledged_by = ack_user.id
    row.acknowledged_at = LATER
    db.commit()

    # Recurrence: the membership edge comes back.
    _edge(db, conn, nested.id, "user", BOB_DN, G_BOB)
    db.commit()
    later2 = LATER + timedelta(hours=2)
    result = _recompute(db, conn, now=later2)
    assert result["reopened"] >= 1

    row = _one(db, conn, RULE_TRANSITIVE, BOB_DN)
    assert row.status == "open"
    assert row.resolved_at is None
    assert row.first_seen_at == first_seen  # preserved
    assert row.last_seen_at == later2
    assert row.reopen_count == 1
    assert row.acknowledged_by is None  # cleared
    assert row.acknowledged_at is None

    reopen_audit = _audit_events(db, "directory.finding.reopened", conn)
    assert reopen_audit
    assert all(a.actor_email == "system" for a in reopen_audit)
    assert any(a.target == row.fingerprint for a in reopen_audit)


def test_suppressed_finding_is_completely_untouched(db, connection):
    conn = connection
    _recompute(db, conn)
    row = _one(db, conn, RULE_DIRECT, ALICE_DN)
    row.status = "suppressed"
    row.suppressed_at = NOW
    db.commit()
    original_last_seen = row.last_seen_at

    # 1) Condition still holds → not refreshed (last_seen frozen).
    _recompute(db, conn, now=LATER)
    row = _one(db, conn, RULE_DIRECT, ALICE_DN)
    assert row.status == "suppressed"
    assert row.last_seen_at == original_last_seen

    # 2) Condition vanishes with complete inventory → NOT resolved.
    #    The only vanished condition is alice's own → suppressed rows are
    #    skipped, so NOTHING resolves in this pass.
    db.execute(
        delete(DirectoryGroupMembership).where(
            DirectoryGroupMembership.member_dn == ALICE_DN
        )
    )
    db.commit()
    result = _recompute(db, conn, now=LATER)
    assert result["resolved"] == 0
    row = _one(db, conn, RULE_DIRECT, ALICE_DN)
    assert row.status == "suppressed"
    assert row.resolved_at is None

    # 3) Recurrence → NOT reopened (and nothing else recurred here).
    da = db.scalar(select(DirectoryGroup).where(DirectoryGroup.distinguished_name == DA_DN))
    _edge(db, conn, da.id, "user", ALICE_DN, G_ALICE)
    db.commit()
    result = _recompute(db, conn, now=LATER)
    assert result["reopened"] == 0
    row = _one(db, conn, RULE_DIRECT, ALICE_DN)
    assert row.status == "suppressed"
    assert row.reopen_count == 0
    assert row.last_seen_at == original_last_seen


# --- Concurrency: advisory lock ----------------------------------------------


def test_lock_contention_skips_with_zero_writes(db, connection):
    conn = connection
    _recompute(db, conn)
    findings_before = db.scalar(
        select(func.count()).select_from(DirectoryFinding)
    )
    audit_scope = AuditLog.detail.like(f"%{conn.id}%")
    audit_before = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.event_type.like("directory.finding%"), audit_scope)
    )

    other = SessionLocal()
    try:
        got = other.execute(
            text("SELECT pg_try_advisory_xact_lock(:ns, hashtext(:cid))"),
            {"ns": insights.INSIGHTS_LOCK_NS, "cid": str(conn.id)},
        ).scalar()
        assert got is True  # the other writer holds the lock now

        result = _recompute(db, conn, now=LATER)
        assert result == {"skipped": True, "reason": "lock_held"}

        findings_after = db.scalar(select(func.count()).select_from(DirectoryFinding))
        audit_after = db.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.event_type.like("directory.finding%"), audit_scope)
        )
        assert findings_after == findings_before
        assert audit_after == audit_before
    finally:
        other.rollback()
        other.close()

    # Lock released → recomputation proceeds again.
    result = _recompute(db, conn, now=LATER)
    assert result["skipped"] is False


# --- Absence rules + connection findings --------------------------------------


def test_inactive_user_gated_on_complete_inventory(db, connection):
    conn = connection
    result = _recompute(db, conn)
    assert result["inventory_complete"] is True
    row = _one(db, conn, RULE_USER_INACTIVE, CAROL_DN)
    assert row.severity == "medium"
    assert row.detail["threshold_days"] == 90

    # Newest run fails → absence rules pause (row stays, no new eval).
    _add_run(
        db, conn, status="failed", started_at=NOW + timedelta(minutes=5),
        results={c: {"status": "failed"} for c in INVENTORY_CATEGORIES},
    )
    db.execute(
        delete(DirectoryFinding).where(
            DirectoryFinding.rule_key == RULE_USER_INACTIVE
        )
    )
    db.commit()
    result = _recompute(db, conn, now=LATER)
    assert result["inventory_complete"] is False
    assert _rows(db, conn, RULE_USER_INACTIVE) == []


def test_no_logon_data_is_info(db, connection):
    _recompute(db, connection)
    row = _one(db, connection, RULE_NO_LOGON, DAVE_DN)
    assert row.severity == "info"


def test_stale_excludes_missing_computers(db, connection):
    _recompute(db, connection)
    # ws03: present, no logon in 200 days → stale.
    stale = _rows(db, connection, RULE_COMPUTER_STALE)
    assert [r.subject_name for r in stale] == ["WS03"]
    # ws04 is missing → missing_after_grace only, never stale.
    assert all(r.subject_dn.find("WS04") < 0 for r in stale)
    grace = _rows(db, connection, RULE_MISSING_GRACE)
    assert {r.subject_name for r in grace} == {"WS04", "WS05"}


def test_disabled_computer_persist_rule(db, connection):
    _recompute(db, connection)
    rows = _rows(db, connection, RULE_DISABLED_PERSIST)
    assert [r.subject_name for r in rows] == ["WS02"]
    assert rows[0].severity == "medium"


def test_missing_after_grace_boundary_and_live_endpoint(db, connection):
    conn = connection
    _recompute(db, conn)
    by_name = {r.subject_name: r for r in _rows(db, conn, RULE_MISSING_GRACE)}
    # ws04: missing 30 days > grace 7 → medium, no endpoint.
    assert by_name["WS04"].severity == "medium"
    assert by_name["WS04"].detail["live_endpoint"] is False
    assert by_name["WS04"].detail["grace_days"] == 7
    # ws05: missing 30 days AND matched to an ACTIVE endpoint → high.
    assert by_name["WS05"].severity == "high"
    assert by_name["WS05"].detail["live_endpoint"] is True

    # Inside the grace window → no finding.
    ws06 = _computer(
        db, conn, guid="cccccccc-0000-0000-0000-000000000006", name="WS06",
        missing_days=2,
    )
    db.commit()
    assert ws06
    _recompute(db, conn, now=LATER)
    names = {r.subject_name for r in _rows(db, conn, RULE_MISSING_GRACE)}
    assert "WS06" not in names


def test_sync_freshness_and_inventory_empty_on_failed_newest(db, connection):
    conn = connection
    _add_run(
        db, conn, status="failed", started_at=NOW + timedelta(minutes=5),
        results={c: {"status": "failed"} for c in INVENTORY_CATEGORIES},
    )
    result = _recompute(db, conn)
    assert result["inventory_complete"] is False

    freshness = _rows(db, conn, RULE_SYNC_FRESHNESS)
    assert len(freshness) == 1
    assert freshness[0].severity == "medium"
    assert freshness[0].subject_type == "connection"
    assert freshness[0].subject_dn is None  # CHECK: connection findings
    assert freshness[0].detail["status"] == "failed"

    empty = _rows(db, conn, RULE_INVENTORY_EMPTY)
    assert len(empty) == 1
    assert empty[0].subject_type == "connection"
    assert empty[0].subject_dn is None
    assert set(empty[0].detail["missing_categories"]) == set(INVENTORY_CATEGORIES)


def test_inventory_empty_resolves_when_inventory_recovers(db, connection):
    conn = connection
    db.execute(delete(DirectorySyncRun).where(DirectorySyncRun.connection_id == conn.id))
    db.commit()
    result = _recompute(db, conn)
    assert result["inventory_complete"] is False
    assert _rows(db, conn, RULE_INVENTORY_EMPTY)

    _add_run(db, conn)  # complete success run
    result = _recompute(db, conn, now=LATER)
    assert result["inventory_complete"] is True
    assert result["resolved"] >= 1
    row = _rows(db, conn, RULE_INVENTORY_EMPTY)[0]
    assert row.status == "resolved"
    assert row.resolved_at == LATER


# --- Config -------------------------------------------------------------------


def test_config_validators_enforce_floors():
    with pytest.raises(ValidationError):
        Settings(directory_insight_scan_seconds=30)  # must be >= 60
    with pytest.raises(ValidationError):
        Settings(directory_inactive_user_days=14)  # >= 30 (14-day AD resolution)
    with pytest.raises(ValidationError):
        Settings(directory_stale_computer_days=14)  # >= 30
    with pytest.raises(ValidationError):
        Settings(directory_nested_group_max_depth=0)  # >= 1

    defaults = Settings()
    assert defaults.directory_insight_scan_seconds == 600
    assert defaults.directory_inactive_user_days == 90
    assert defaults.directory_stale_computer_days == 90
    assert defaults.directory_nested_group_max_depth == 8


# --- Static security guarantee ------------------------------------------------


def test_insights_never_imports_ldap_or_sync_engine():
    """AST-enforced: insights stays free of the LDAP client import chain."""
    module_file = Path(insights.__file__)
    tree = ast.parse(module_file.read_text())
    forbidden_exact = {
        "ldap",
        "ldap3",
        "app.services.directory.ldap_client",
        "app.services.directory.sync_engine",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert alias.name not in forbidden_exact, alias.name
                assert root not in ("ldap", "ldap3"), alias.name
        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            assert mod_name not in forbidden_exact, mod_name
            assert mod_name.split(".")[0] not in ("ldap", "ldap3"), mod_name
