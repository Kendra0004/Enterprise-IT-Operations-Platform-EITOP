"""Directory findings/health/correlation API tests (Phase 3.2.2).

Acceptance-audit coverage for the Phase 3.2.1 findings engine exposed
through the API:

- lifecycle: every manual transition (ack/suppress/reopen), idempotent
  no-ops, illegal transitions -> RFC 9457 400 with ZERO writes and
  ZERO audit rows (validation happens before mutation), actor
  attribution, ack-field clearing, reopen_count rules, cross-
  connection 404;
- findings list/summary/detail: enum filters derived from the model
  constants, sort allowlist + stable id tiebreak, pagination,
  cross-connection isolation, 404/422 contract;
- health: newest run regardless of status (an older success never
  backfills a newer failure), all nine PIPELINE categories, visibility
  via the engine helper (never a second implementation), distribution
  anomaly never downgrades visibility, sync freshness;
- correlation gaps: never_reconciled/unmatched/ambiguous classified,
  matched + rejected excluded, gap_type filter, pagination, isolation;
- RBAC: all five roles on every new endpoint (admin writes; readonly /
  auditor / operator read-only; agent 403; anonymous 401);
- no secrets in responses, logs or audit detail.

PostgreSQL is real (shared test database); no LDAP server is involved
— all directory data is seeded mirror rows.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models import (
    AuditLog,
    DirectoryComputer,
    DirectoryConnection,
    DirectoryFinding,
    DirectoryReconciliation,
)
from app.services.directory import insights
from app.services.directory.insights import (
    INVENTORY_CATEGORIES,
    RULE_COMPUTER_STALE,
    RULE_DIRECT,
    RULE_DIST_ANOMALY,
    RULE_SYNC_FRESHNESS,
)
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from tests.conftest import requires_postgres, requires_redis
from tests.test_directory_insights import (
    _add_run,
    _audit_events,
    _recompute,
    _wipe,
    connection,  # noqa: F401 — pytest fixture re-export
)

pytestmark = [requires_postgres, requires_redis]

API = "/api/v1/directory"
PASSWORD = "Str0ng!Passw0rd#2026"

BASE = "DC=eitop,DC=test"
DS = "S-1-5-21-111-222-333"
TS = datetime(2026, 11, 23, 8, 0, tzinfo=UTC)

ALL_GAPS = ("never_reconciled", "unmatched", "ambiguous")
READ_ROLES = ("readonly_user", "auditor_user", "operator_user")


# --- Helpers -----------------------------------------------------------------


def _login(client, email, password=PASSWORD):
    resp = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _new_conn(db: Session) -> DirectoryConnection:
    row = DirectoryConnection(
        name=f"ad-{uuid.uuid4().hex[:8]}",
        domain_dns="eitop.test",
        host="dc01.eitop.test",
        port=636,
        tls_mode="ldaps",
        search_base=BASE,
        bind_username="CN=svc,CN=Users," + BASE,
        bind_password_encrypted="placeholder-never-valid",
        enabled=True,
        auto_sync=False,
        sync_interval_minutes=60,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _seed_finding(
    db: Session,
    conn: DirectoryConnection,
    *,
    dn: str | None = f"CN=seed,CN=Users,{BASE}",
    status: str = "open",
    severity: str = "high",
    rule_key: str = RULE_DIRECT,
    subject_type: str = "user",
    access: str | None = "direct",
    subject_name: str | None = "seed",
) -> DirectoryFinding:
    """Insert one API-valid finding row (DB CHECKs satisfied)."""
    row = DirectoryFinding(
        connection_id=conn.id,
        fingerprint=f"fp-{uuid.uuid4().hex}",
        rule_key=rule_key,
        severity=severity,
        status=status,
        subject_type=subject_type,
        access=access,
        subject_guid=str(uuid.uuid4()) if dn is not None else None,
        subject_dn=dn,
        subject_name=subject_name,
        title="seeded finding",
        detail={"note": "seeded"},
        first_seen_at=TS,
        last_seen_at=TS,
        resolved_at=TS if status == "resolved" else None,
        suppressed_at=TS if status == "suppressed" else None,
        acknowledged_at=TS if status == "acknowledged" else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _seed_computer(db: Session, conn: DirectoryConnection, name: str) -> DirectoryComputer:
    row = DirectoryComputer(
        connection_id=conn.id,
        object_guid=str(uuid.uuid4()),
        distinguished_name=f"CN={name},CN=Computers,{BASE}",
        sid=f"{DS}-{2500 + len(name)}",
        name=name,
        dns_hostname=f"{name.lower()}.eitop.test",
        enabled=True,
        last_logon_at=TS,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _seed_recon(
    db: Session,
    conn: DirectoryConnection,
    computer: DirectoryComputer,
    *,
    status: str,
    method: str = "short_name",
    confidence: str = "low",
    candidates: list | None = None,
    reviewed_at: datetime | None = None,
) -> DirectoryReconciliation:
    row = DirectoryReconciliation(
        connection_id=conn.id,
        computer_id=computer.id,
        method=method,
        confidence=confidence,
        status=status,
        candidates=candidates,
        reviewed_at=reviewed_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _audit_rows(db: Session, conn: DirectoryConnection) -> list[AuditLog]:
    """Every audit row whose detail carries this connection (isolation key)."""
    return list(
        db.scalars(
            select(AuditLog).where(AuditLog.detail.like(f"%{conn.id}%"))
        ).all()
    )


def _post(client, headers, conn, finding_id, action) -> object:
    return client.post(
        f"{API}/findings/{finding_id}/{action}",
        params={"connection_id": str(conn.id)},
        headers=headers,
    )


def _get(client, headers, conn, path: str, **params):
    return client.get(
        f"{API}{path}",
        params={"connection_id": str(conn.id), **params},
        headers=headers,
    )


def _ids(body: dict) -> set[str]:
    return {item["id"] for item in body["items"]}


@pytest.fixture(autouse=True)
def clean_directory_tables(db):
    _wipe(db)
    yield
    db.rollback()
    _wipe(db)


@pytest.fixture()
def conn(db) -> DirectoryConnection:
    """Bare connection — no mirror graph, no sync runs."""
    return _new_conn(db)


# --- Lifecycle: ack ----------------------------------------------------------


def test_ack_open_finding_sets_fields_and_audits_actor(
    db, client, auth_headers, admin_user, conn
):
    row = _seed_finding(db, conn)
    resp = _post(client, auth_headers, conn, row.id, "ack")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "acknowledged"
    assert body["acknowledged_by"] == str(admin_user.id)
    assert body["acknowledged_at"] is not None
    assert body["suppressed_at"] is None

    db.expire_all()
    fresh = db.get(DirectoryFinding, row.id)
    assert fresh.status == "acknowledged"
    assert fresh.acknowledged_by == admin_user.id

    events = _audit_events(db, "directory.finding.acknowledged", conn)
    assert len(events) == 1
    event = events[0]
    assert event.actor_email == admin_user.email
    assert event.actor_user_id == admin_user.id
    assert event.outcome == "success"
    detail = json.loads(event.detail)
    assert detail["from_status"] == "open"
    assert detail["to_status"] == "acknowledged"
    assert detail["finding_id"] == str(row.id)


def test_ack_is_idempotent_without_duplicate_audit(
    db, client, auth_headers, conn
):
    row = _seed_finding(db, conn)
    first = _post(client, auth_headers, conn, row.id, "ack")
    second = _post(client, auth_headers, conn, row.id, "ack")
    assert first.status_code == 200
    assert second.status_code == 200, second.text
    assert second.json()["acknowledged_at"] == first.json()["acknowledged_at"]
    assert len(_audit_events(db, "directory.finding.acknowledged", conn)) == 1


def test_ack_from_suppressed_is_400_with_zero_writes(
    db, client, auth_headers, conn
):
    row = _seed_finding(db, conn, status="suppressed")
    before = len(_audit_rows(db, conn))

    resp = _post(client, auth_headers, conn, row.id, "ack")
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("application/problem+json")
    problem = resp.json()
    assert problem["status"] == 400
    assert problem["title"] == "Invalid transition"
    assert "suppressed" in problem["detail"]

    db.expire_all()
    fresh = db.get(DirectoryFinding, row.id)
    assert fresh.status == "suppressed"
    assert fresh.acknowledged_at is None
    assert fresh.acknowledged_by is None
    assert len(_audit_rows(db, conn)) == before
    assert not _audit_events(db, "directory.finding.acknowledged", conn)


def test_ack_from_resolved_is_400_with_zero_audit(db, client, auth_headers, conn):
    row = _seed_finding(db, conn, status="resolved")
    resp = _post(client, auth_headers, conn, row.id, "ack")
    assert resp.status_code == 400
    assert "resolved" in resp.json()["detail"]
    assert not _audit_events(db, "directory.finding.acknowledged", conn)
    db.expire_all()
    assert db.get(DirectoryFinding, row.id).status == "resolved"


# --- Lifecycle: suppress -----------------------------------------------------


def test_suppress_from_open(db, client, auth_headers, admin_user, conn):
    row = _seed_finding(db, conn)
    resp = _post(client, auth_headers, conn, row.id, "suppress")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "suppressed"
    assert body["suppressed_at"] is not None
    assert body["acknowledged_at"] is None

    events = _audit_events(db, "directory.finding.suppressed", conn)
    assert len(events) == 1
    assert events[0].actor_email == admin_user.email
    detail = json.loads(events[0].detail)
    assert detail["from_status"] == "open"
    assert detail["to_status"] == "suppressed"


def test_suppress_from_acknowledged_keeps_ack_history(
    db, client, auth_headers, conn
):
    row = _seed_finding(db, conn)
    assert _post(client, auth_headers, conn, row.id, "ack").status_code == 200
    resp = _post(client, auth_headers, conn, row.id, "suppress")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "suppressed"
    assert body["suppressed_at"] is not None
    # Prior ack columns are history, not cleared by suppression.
    assert body["acknowledged_at"] is not None
    assert body["acknowledged_by"] is not None
    assert len(_audit_events(db, "directory.finding.suppressed", conn)) == 1


def test_suppress_from_resolved_is_400_no_audit(db, client, auth_headers, conn):
    row = _seed_finding(db, conn, status="resolved")
    resp = _post(client, auth_headers, conn, row.id, "suppress")
    assert resp.status_code == 400
    assert "resolved" in resp.json()["detail"]
    assert not _audit_events(db, "directory.finding.suppressed", conn)
    db.expire_all()
    assert db.get(DirectoryFinding, row.id).status == "resolved"


def test_suppress_is_idempotent_without_duplicate_audit(
    db, client, auth_headers, conn
):
    row = _seed_finding(db, conn)
    first = _post(client, auth_headers, conn, row.id, "suppress")
    second = _post(client, auth_headers, conn, row.id, "suppress")
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["suppressed_at"] == first.json()["suppressed_at"]
    assert len(_audit_events(db, "directory.finding.suppressed", conn)) == 1


# --- Lifecycle: reopen -------------------------------------------------------


def test_reopen_from_resolved_bumps_counter_and_clears_fields(
    db, client, auth_headers, admin_user, conn
):
    row = _seed_finding(db, conn, status="resolved")
    resp = _post(client, auth_headers, conn, row.id, "reopen")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "open"
    assert body["resolved_at"] is None
    assert body["suppressed_at"] is None
    assert body["acknowledged_at"] is None
    assert body["acknowledged_by"] is None
    assert body["reopen_count"] == 1

    db.expire_all()
    fresh = db.get(DirectoryFinding, row.id)
    assert fresh.first_seen_at == TS  # never touched

    events = _audit_events(db, "directory.finding.reopened", conn)
    assert len(events) == 1
    assert events[0].actor_email == admin_user.email
    detail = json.loads(events[0].detail)
    assert detail["from_status"] == "resolved"
    assert detail["to_status"] == "open"
    assert detail["reopen_count"] == 1


def test_reopen_from_suppressed_bumps_counter(db, client, auth_headers, conn):
    row = _seed_finding(db, conn, status="suppressed")
    resp = _post(client, auth_headers, conn, row.id, "reopen")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "open"
    assert body["suppressed_at"] is None
    assert body["reopen_count"] == 1
    assert len(_audit_events(db, "directory.finding.reopened", conn)) == 1


def test_reopen_from_acknowledged_clears_ack_without_counter_bump(
    db, client, auth_headers, conn
):
    row = _seed_finding(db, conn)
    assert _post(client, auth_headers, conn, row.id, "ack").status_code == 200
    resp = _post(client, auth_headers, conn, row.id, "reopen")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "open"
    assert body["acknowledged_at"] is None
    assert body["acknowledged_by"] is None
    # Un-acknowledge: the finding never closed, so no reopen credit.
    assert body["reopen_count"] == 0
    events = _audit_events(db, "directory.finding.reopened", conn)
    assert len(events) == 1
    assert json.loads(events[0].detail)["from_status"] == "acknowledged"


def test_reopen_from_open_is_idempotent_without_audit(
    db, client, auth_headers, conn
):
    row = _seed_finding(db, conn)
    resp = _post(client, auth_headers, conn, row.id, "reopen")
    assert resp.status_code == 200
    assert resp.json()["status"] == "open"
    assert resp.json()["reopen_count"] == 0
    assert not _audit_events(db, "directory.finding.reopened", conn)


# --- Lifecycle: scope / contract ---------------------------------------------


def test_transition_across_connections_is_404_without_writes(
    db, client, auth_headers, conn
):
    other = _new_conn(db)
    row = _seed_finding(db, other)  # finding belongs to `other`
    before = len(_audit_rows(db, conn))

    resp = _post(client, auth_headers, conn, row.id, "ack")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")

    db.expire_all()
    assert db.get(DirectoryFinding, row.id).status == "open"
    assert len(_audit_rows(db, conn)) == before
    assert not _audit_events(db, "directory.finding.acknowledged", other)


def test_transition_requires_connection_id(client, auth_headers, db):
    conn_row = _new_conn(db)
    row = _seed_finding(db, conn_row)
    resp = client.post(f"{API}/findings/{row.id}/ack", headers=auth_headers)
    assert resp.status_code == 422
    assert "connection_id" in resp.text


def test_transition_on_unknown_finding_is_404(client, auth_headers, conn):
    resp = _post(client, auth_headers, conn, uuid.uuid4(), "ack")
    assert resp.status_code == 404


# --- Findings list -----------------------------------------------------------


@pytest.fixture()
def four_findings(db, conn) -> dict:
    """Four findings covering every filterable dimension."""
    f1 = _seed_finding(
        db, conn, dn="CN=u1,CN=Users," + BASE, rule_key=RULE_DIRECT,
        subject_type="user", access="direct", severity="high", status="open",
    )
    f2 = _seed_finding(
        db, conn, dn="CN=g1,CN=Users," + BASE, rule_key=RULE_DIST_ANOMALY,
        subject_type="group", access="transitive", severity="medium",
        status="acknowledged", subject_name="g1",
    )
    f3 = _seed_finding(
        db, conn, dn=None, rule_key=RULE_SYNC_FRESHNESS,
        subject_type="connection", access=None, severity="info",
        status="suppressed", subject_name=None,
    )
    f4 = _seed_finding(
        db, conn, dn="CN=c1,CN=Computers," + BASE, rule_key=RULE_COMPUTER_STALE,
        subject_type="computer", access="direct", severity="critical",
        status="open", subject_name="c1",
    )
    return {"user": f1, "group": f2, "connection": f3, "computer": f4}


def test_findings_require_connection_id(client, auth_headers):
    resp = client.get(f"{API}/findings", headers=auth_headers)
    assert resp.status_code == 422
    assert "connection_id" in resp.text


def test_findings_unknown_connection_is_404(client, auth_headers):
    resp = client.get(
        f"{API}/findings", headers=auth_headers,
        params={"connection_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_findings_enum_filters(db, client, auth_headers, conn, four_findings):
    cases = [
        ({"subject_type": "user"}, {"user"}),
        ({"access": "direct"}, {"user", "computer"}),
        ({"status": "acknowledged"}, {"group"}),
        ({"severity": "critical"}, {"computer"}),
        ({"rule_key": RULE_DIST_ANOMALY}, {"group"}),
        ({"subject_type": "user", "severity": "high"}, {"user"}),
        ({"status": "open", "severity": "info"}, set()),
    ]
    for params, expected_keys in cases:
        resp = _get(client, auth_headers, conn, "/findings", page_size=100, **params)
        assert resp.status_code == 200, (params, resp.text)
        expected = {str(four_findings[k].id) for k in expected_keys}
        assert _ids(resp.json()) == expected, params
        assert resp.json()["total"] == len(expected)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("subject_type", "bogus"),
        ("access", "bogus"),
        ("status", "bogus"),
        ("severity", "bogus"),
        ("rule_key", "bogus.rule"),
    ],
)
def test_findings_invalid_enum_filter_is_422(
    db, client, auth_headers, conn, key, value
):
    resp = _get(client, auth_headers, conn, "/findings", **{key: value})
    assert resp.status_code == 422, resp.text


def test_findings_sort_allowlist(db, client, auth_headers, conn, four_findings):
    # Allowlisted column with natural lexicographic order, both directions.
    asc = _get(
        client, auth_headers, conn, "/findings",
        sort="rule_key", order="asc", page_size=100,
    )
    assert asc.status_code == 200, asc.text
    rules = [item["rule_key"] for item in asc.json()["items"]]
    assert rules == sorted(rules)

    desc = _get(
        client, auth_headers, conn, "/findings",
        sort="rule_key", order="desc", page_size=100,
    )
    assert [item["rule_key"] for item in desc.json()["items"]] == list(reversed(rules))

    # severity is a plain column: accepted and deterministic across calls
    # (the API contract is allowlist + stable tiebreak, not rank ordering).
    sev1 = _get(
        client, auth_headers, conn, "/findings",
        sort="severity", order="desc", page_size=100,
    )
    sev2 = _get(
        client, auth_headers, conn, "/findings",
        sort="severity", order="desc", page_size=100,
    )
    assert sev1.status_code == 200, sev1.text
    assert [i["id"] for i in sev1.json()["items"]] == [
        i["id"] for i in sev2.json()["items"]
    ]

    bad = _get(client, auth_headers, conn, "/findings", sort="fingerprint")
    assert bad.status_code == 400
    assert bad.json()["title"] == "Invalid sort field"

    bad_order = _get(client, auth_headers, conn, "/findings", order="sideways")
    assert bad_order.status_code == 422


def test_findings_stable_id_tiebreak(db, client, auth_headers, conn, four_findings):
    db.execute(
        update(DirectoryFinding)
        .where(DirectoryFinding.connection_id == conn.id)
        .values(updated_at=TS)
    )
    db.commit()

    first = _get(
        client, auth_headers, conn, "/findings",
        sort="updated_at", order="desc", page_size=100,
    )
    second = _get(
        client, auth_headers, conn, "/findings",
        sort="updated_at", order="desc", page_size=100,
    )
    ids_first = [item["id"] for item in first.json()["items"]]
    ids_second = [item["id"] for item in second.json()["items"]]
    assert ids_first == ids_second
    # Deterministic: identical primary sort falls back to id ascending.
    assert ids_first == sorted(ids_first)


def test_findings_pagination(db, client, auth_headers, conn, four_findings):
    page1 = _get(client, auth_headers, conn, "/findings", page=1, page_size=2)
    page2 = _get(client, auth_headers, conn, "/findings", page=2, page_size=2)
    page3 = _get(client, auth_headers, conn, "/findings", page=3, page_size=2)
    assert page1.json()["total"] == 4
    assert len(page1.json()["items"]) == 2
    assert len(page2.json()["items"]) == 2
    assert not (_ids(page1.json()) & _ids(page2.json()))
    assert page3.json()["items"] == []


def test_findings_never_bleed_across_connections(
    db, client, auth_headers, conn, four_findings
):
    other = _new_conn(db)
    foreign = _seed_finding(db, other, dn="CN=foreign,CN=Users," + BASE)

    resp = _get(client, auth_headers, conn, "/findings", page_size=100)
    assert resp.status_code == 200
    assert str(foreign.id) not in _ids(resp.json())
    assert resp.json()["total"] == 4

    other_resp = _get(client, auth_headers, other, "/findings", page_size=100)
    assert _ids(other_resp.json()) == {str(foreign.id)}


# --- Findings detail ---------------------------------------------------------


def test_finding_detail_lifecycle_fields_and_isolation(
    db, client, auth_headers, conn
):
    row = _seed_finding(db, conn)
    resp = _get(client, auth_headers, conn, f"/findings/{row.id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    for field in (
        "acknowledged_by", "acknowledged_at", "suppressed_at",
        "reopen_count", "resolved_at", "first_seen_at", "detail",
        "subject_dn", "rule_key", "severity", "status",
    ):
        assert field in body, field
    assert body["acknowledged_by"] is None
    assert body["suppressed_at"] is None
    assert body["detail"] == {"note": "seeded"}

    # After a transition the detail view reflects the lifecycle fields.
    assert _post(client, auth_headers, conn, row.id, "ack").status_code == 200
    detail = _get(client, auth_headers, conn, f"/findings/{row.id}").json()
    assert detail["acknowledged_by"] is not None
    assert detail["status"] == "acknowledged"

    # Cross-connection and unknown ids are 404, never a leak.
    other = _new_conn(db)
    foreign = _seed_finding(db, other)
    assert _get(client, auth_headers, conn, f"/findings/{foreign.id}").status_code == 404
    assert _get(client, auth_headers, other, f"/findings/{row.id}").status_code == 404
    assert (
        _get(client, auth_headers, conn, f"/findings/{uuid.uuid4()}").status_code
        == 404
    )


# --- Findings summary --------------------------------------------------------


def test_summary_counts_by_every_dimension(
    db, client, auth_headers, conn, four_findings
):
    resp = _get(client, auth_headers, conn, "/findings/summary")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 4
    assert body["open"] == 2
    assert body["acknowledged"] == 1
    assert body["suppressed"] == 1
    assert body["resolved"] == 0
    assert sum(body["by_severity"].values()) == 4
    assert sum(body["by_rule"].values()) == 4
    assert sum(body["by_subject_type"].values()) == 4
    assert body["by_subject_type"] == {
        "user": 1, "group": 1, "connection": 1, "computer": 1,
    }
    # Bare connection: no sync run proves completeness.
    assert body["privilege_visibility"] == "insufficient"
    assert body["inventory_complete"] is False


def test_summary_reflects_transitions(db, client, auth_headers, conn):
    row = _seed_finding(db, conn)
    before = _get(client, auth_headers, conn, "/findings/summary").json()
    assert before["open"] == 1

    assert _post(client, auth_headers, conn, row.id, "ack").status_code == 200
    after_ack = _get(client, auth_headers, conn, "/findings/summary").json()
    assert after_ack["open"] == 0
    assert after_ack["acknowledged"] == 1

    assert _post(client, auth_headers, conn, row.id, "suppress").status_code == 200
    after_suppress = _get(client, auth_headers, conn, "/findings/summary").json()
    assert after_suppress["acknowledged"] == 0
    assert after_suppress["suppressed"] == 1
    assert after_suppress["total"] == 1


def test_summary_requires_and_scopes_connection(
    db, client, auth_headers, conn, four_findings
):
    missing = client.get(f"{API}/findings/summary", headers=auth_headers)
    assert missing.status_code == 422

    unknown = client.get(
        f"{API}/findings/summary", headers=auth_headers,
        params={"connection_id": str(uuid.uuid4())},
    )
    assert unknown.status_code == 404

    other = _new_conn(db)
    _seed_finding(db, other, dn="CN=only,CN=Users," + BASE)
    foreign_summary = _get(client, auth_headers, other, "/findings/summary").json()
    assert foreign_summary["total"] == 1
    own = _get(client, auth_headers, conn, "/findings/summary").json()
    assert own["total"] == 4


# --- Directory health --------------------------------------------------------


def _failed_results() -> dict:
    return {category: {"status": "failed"} for category in INVENTORY_CATEGORIES}


def test_health_without_run_lists_all_nine_categories(db, client, auth_headers, conn):
    resp = _get(client, auth_headers, conn, "/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["newest_run"] is None
    assert body["inventory_complete"] is False
    assert body["missing_categories"] == list(INVENTORY_CATEGORIES)
    assert len(body["missing_categories"]) == 9
    assert body["privilege_visibility"] == "insufficient"
    assert body["sync_freshness"]["last_success_at"] is None
    assert body["sync_freshness"]["sync_overdue"] is True
    assert body["connection_id"] == str(conn.id)


def test_health_newest_failed_run_never_falls_back_to_older_success(
    db, client, auth_headers, conn
):
    now = datetime.now(UTC)
    older_success = _add_run(
        db, conn, status="success", started_at=now - timedelta(hours=2)
    )
    newest_failure = _add_run(
        db, conn, status="failed",
        started_at=now - timedelta(minutes=10),
        results=_failed_results(),
    )

    resp = _get(client, auth_headers, conn, "/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    newest = body["newest_run"]
    assert newest["id"] == str(newest_failure.id)
    assert newest["status"] == "failed"
    assert newest["id"] != str(older_success.id)
    # Raw error labels are never exposed by the health view.
    assert "errors" not in newest

    assert body["inventory_complete"] is False
    assert body["missing_categories"] == list(INVENTORY_CATEGORIES)
    assert body["privilege_visibility"] == "insufficient"
    assert "inventory_incomplete" in body["visibility_reasons"]


def test_health_visibility_uses_engine_helper_and_ignores_distribution(
    db, client, auth_headers, connection  # noqa: F811 — fixture param
):
    conn_row = connection
    _recompute(db, conn_row)

    resp = _get(client, auth_headers, conn_row, "/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Same helper the engine uses — never a second implementation.
    expected = insights.privilege_visibility(db, conn_row.id)
    assert body["privilege_visibility"] == expected["privilege_visibility"]
    assert body["visibility_reasons"] == expected["visibility_reasons"]
    assert body["inventory_complete"] == expected["inventory_complete"]
    assert body["privilege_visibility"] == "full"
    assert body["visibility_reasons"] == []

    # The distribution anomaly IS reported — it just never downgrades.
    assert body["findings"]["by_rule"].get(RULE_DIST_ANOMALY, 0) >= 1
    assert body["missing_categories"] == []
    assert body["newest_run"]["status"] == "success"


def test_health_sync_freshness(db, client, auth_headers):
    now = datetime.now(UTC)
    stale = _new_conn(db)
    _add_run(db, stale, status="success", started_at=now - timedelta(hours=3))
    fresh = _new_conn(db)
    _add_run(db, fresh, status="success", started_at=now - timedelta(minutes=5))

    stale_body = _get(client, auth_headers, stale, "/health").json()
    assert stale_body["sync_freshness"]["sync_overdue"] is True
    assert stale_body["sync_freshness"]["last_success_at"] is not None
    assert stale_body["sync_freshness"]["newest_run_started_at"] is not None
    assert stale_body["sync_freshness"]["sync_interval_minutes"] == 60

    fresh_body = _get(client, auth_headers, fresh, "/health").json()
    assert fresh_body["sync_freshness"]["sync_overdue"] is False
    assert fresh_body["sync_freshness"]["last_success_at"] is not None


def test_health_requires_and_scopes_connection(client, auth_headers):
    missing = client.get(f"{API}/health", headers=auth_headers)
    assert missing.status_code == 422
    unknown = client.get(
        f"{API}/health", headers=auth_headers,
        params={"connection_id": str(uuid.uuid4())},
    )
    assert unknown.status_code == 404


# --- Correlation gaps --------------------------------------------------------


@pytest.fixture()
def gap_scenario(db, connection) -> dict:  # noqa: F811 — fixture param
    """Graph connection with one computer per reconciliation state."""
    conn_row = connection
    computers = {
        c.name: c
        for c in db.scalars(
            select(DirectoryComputer).where(
                DirectoryComputer.connection_id == conn_row.id
            )
        ).all()
    }
    _seed_recon(db, conn_row, computers["WS01"], status="unmatched")
    _seed_recon(
        db, conn_row, computers["WS02"],
        status="needs_review", method="exact_fqdn", confidence="medium",
        candidates=[str(uuid.uuid4())],
    )
    _seed_recon(
        db, conn_row, computers["WS03"],
        status="rejected", method="manual", confidence="medium",
        reviewed_at=datetime.now(UTC),
    )
    # WS04: never reconciled (no row). WS05: matched (fixture).
    return {"conn": conn_row, "computers": computers}


def test_gap_classifications_exclude_matched_and_rejected(
    db, client, auth_headers, gap_scenario
):
    conn_row = gap_scenario["conn"]
    resp = _get(client, auth_headers, conn_row, "/correlation/gaps", page_size=100)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    by_name = {item["computer_name"]: item for item in body["items"]}
    assert body["total"] == 3
    assert set(by_name) == {"WS01", "WS02", "WS04"}

    assert by_name["WS01"]["gap_type"] == "unmatched"
    assert by_name["WS01"]["recon_status"] == "unmatched"
    assert by_name["WS01"]["recon_method"] == "short_name"
    assert by_name["WS01"]["recon_confidence"] == "low"

    assert by_name["WS02"]["gap_type"] == "ambiguous"
    assert by_name["WS02"]["recon_status"] == "needs_review"
    assert by_name["WS02"]["recon_method"] == "exact_fqdn"
    assert by_name["WS02"]["recon_confidence"] == "medium"
    assert len(by_name["WS02"]["candidates"]) == 1
    assert by_name["WS02"]["reviewed_at"] is None

    assert by_name["WS04"]["gap_type"] == "never_reconciled"
    assert by_name["WS04"]["recon_status"] is None
    assert by_name["WS04"]["candidates"] == []

    # Deliberate decisions are NOT gaps.
    assert "WS03" not in by_name  # rejected
    assert "WS05" not in by_name  # matched


@pytest.mark.parametrize("gap_type", ALL_GAPS)
def test_gap_type_filter(db, client, auth_headers, gap_scenario, gap_type):
    conn_row = gap_scenario["conn"]
    resp = _get(
        client, auth_headers, conn_row, "/correlation/gaps",
        gap_type=gap_type, page_size=100,
    )
    assert resp.status_code == 200, resp.text
    names = {item["computer_name"] for item in resp.json()["items"]}
    expected = {
        "never_reconciled": {"WS04"},
        "unmatched": {"WS01"},
        "ambiguous": {"WS02"},
    }[gap_type]
    assert names == expected
    assert all(item["gap_type"] == gap_type for item in resp.json()["items"])


def test_gap_type_invalid_value_is_422(db, client, auth_headers, gap_scenario):
    conn_row = gap_scenario["conn"]
    resp = _get(client, auth_headers, conn_row, "/correlation/gaps", gap_type="matched")
    assert resp.status_code == 422


def test_gaps_pagination_and_sort(db, client, auth_headers, gap_scenario):
    conn_row = gap_scenario["conn"]
    page1 = _get(client, auth_headers, conn_row, "/correlation/gaps",
                 page=1, page_size=2)
    page2 = _get(client, auth_headers, conn_row, "/correlation/gaps",
                 page=2, page_size=2)
    assert page1.json()["total"] == 3
    names1 = [i["computer_name"] for i in page1.json()["items"]]
    names2 = [i["computer_name"] for i in page2.json()["items"]]
    # Default sort: name ascending.
    assert names1 == ["WS01", "WS02"]
    assert names2 == ["WS04"]
    assert not set(names1) & set(names2)

    bad_sort = _get(client, auth_headers, conn_row, "/correlation/gaps",
                    sort="dns_hostname")
    assert bad_sort.status_code == 400
    assert bad_sort.json()["title"] == "Invalid sort field"


def test_gaps_are_connection_scoped(db, client, auth_headers, conn):
    computer = _seed_computer(db, conn, "WSA")
    other = _new_conn(db)
    _seed_computer(db, other, "WSB")

    own = _get(client, auth_headers, conn, "/correlation/gaps", page_size=100)
    assert own.status_code == 200
    assert own.json()["total"] == 1
    assert own.json()["items"][0]["computer_name"] == "WSA"
    assert own.json()["items"][0]["computer_id"] == str(computer.id)

    foreign = _get(client, auth_headers, other, "/correlation/gaps", page_size=100)
    assert {i["computer_name"] for i in foreign.json()["items"]} == {"WSB"}


def test_gaps_require_and_scope_connection(client, auth_headers):
    missing = client.get(f"{API}/correlation/gaps", headers=auth_headers)
    assert missing.status_code == 422
    unknown = client.get(
        f"{API}/correlation/gaps", headers=auth_headers,
        params={"connection_id": str(uuid.uuid4())},
    )
    assert unknown.status_code == 404


# --- RBAC --------------------------------------------------------------------

READ_PATHS = (
    "/findings",
    "/findings/summary",
    "/health",
    "/correlation/gaps",
)


@pytest.mark.parametrize("role", READ_ROLES)
def test_read_roles_can_read_every_new_endpoint(
    db, client, role, request
):
    user = request.getfixturevalue(role)
    headers = _login(client, user.email)
    conn_row = _new_conn(db)
    finding = _seed_finding(db, conn_row)
    paths = READ_PATHS + (f"/findings/{finding.id}",)
    for path in paths:
        resp = client.get(
            f"{API}{path}", headers=headers,
            params={"connection_id": str(conn_row.id)},
        )
        assert resp.status_code == 200, (role, path, resp.text)


@pytest.mark.parametrize("role", READ_ROLES + ("agent_user",))
def test_non_admin_cannot_transition(db, client, role, request):
    user = request.getfixturevalue(role)
    headers = _login(client, user.email)
    conn_row = _new_conn(db)
    finding = _seed_finding(db, conn_row)
    resp = client.post(
        f"{API}/findings/{finding.id}/ack",
        params={"connection_id": str(conn_row.id)},
        headers=headers,
    )
    assert resp.status_code == 403, resp.text
    assert "directory:write" in resp.json()["detail"]
    # The rejected attempt changed nothing.
    db.expire_all()
    assert db.get(DirectoryFinding, finding.id).status == "open"
    assert not _audit_events(db, "directory.finding.acknowledged", conn_row)


def test_agent_cannot_read_directory_endpoints(db, client, agent_user):
    headers = _login(client, agent_user.email)
    conn_row = _new_conn(db)
    for path in READ_PATHS:
        resp = client.get(
            f"{API}{path}", headers=headers,
            params={"connection_id": str(conn_row.id)},
        )
        assert resp.status_code == 403, (path, resp.text)
        assert "directory:read" in resp.json()["detail"]


def test_anonymous_denied_on_every_new_endpoint(db, client, conn):
    finding = _seed_finding(db, conn)
    for path in READ_PATHS + (f"/findings/{finding.id}",):
        resp = client.get(
            f"{API}{path}", params={"connection_id": str(conn.id)}
        )
        assert resp.status_code == 401, path
        assert resp.headers["content-type"].startswith("application/problem+json")

    resp = client.post(
        f"{API}/findings/{finding.id}/ack",
        params={"connection_id": str(conn.id)},
    )
    assert resp.status_code == 401
    db.expire_all()
    assert db.get(DirectoryFinding, finding.id).status == "open"


# --- No secrets --------------------------------------------------------------


def test_no_secrets_in_responses_logs_or_audit(db, client, auth_headers, conn, caplog):
    caplog.set_level(logging.DEBUG)
    row = _seed_finding(db, conn)
    _add_run(
        db, conn, status="failed", started_at=datetime.now(UTC),
        results=_failed_results(),
    )

    texts: list[str] = []
    for path in READ_PATHS + (f"/findings/{row.id}",):
        resp = _get(client, auth_headers, conn, path)
        assert resp.status_code == 200, (path, resp.text)
        texts.append(resp.text)
    texts.append(_post(client, auth_headers, conn, row.id, "ack").text)

    blob = "\n".join(texts)
    for needle in (
        "placeholder-never-valid",  # bind_password_encrypted value
        "bind_password",
        "encrypted",
        PASSWORD,
    ):
        assert needle not in blob, needle

    health = _get(client, auth_headers, conn, "/health").json()
    assert "errors" not in health["newest_run"]  # raw error labels stay hidden

    # The bind password never reaches the logs either.
    assert "placeholder-never-valid" not in caplog.text

    # Audit detail for this connection is metadata only.
    rows = _audit_rows(db, conn)
    assert rows  # the ack above was audited
    for event in rows:
        detail = (event.detail or "").lower()
        assert "password" not in detail
        assert "placeholder" not in detail
