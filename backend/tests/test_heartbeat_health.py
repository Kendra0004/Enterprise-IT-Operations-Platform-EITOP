"""Heartbeat & health tests (Phase 2.5): updates, offline detection,
online recovery, revoked immutability, duplicate-transition prevention,
periodic task behavior, health endpoint, list filters and audit rules."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]


def _login(client, email, password="Str0ng!Passw0rd#2026"):
    client.cookies.clear()
    resp = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _enroll(client, headers, hostname: str, **extra) -> tuple[str, str]:
    token_resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=headers,
        json={"expires_in_minutes": 60},
    )
    assert token_resp.status_code == 201, token_resp.text
    payload = {"token": token_resp.json()["token"], "hostname": hostname}
    payload.update(extra)
    resp = client.post("/api/v1/agent/enroll", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["endpoint_id"], body["credential"]


def _hb(client, credential: str, version: str | None = "0.2.0"):
    return client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer {credential}"},
        json={"agent_version": version} if version else {},
    )


def _set_heartbeat_age(db, endpoint_id: str, seconds: int) -> None:
    from app.models import Endpoint

    ep = db.get(Endpoint, uuid.UUID(endpoint_id))
    ep.last_heartbeat_at = datetime.now(UTC) - timedelta(seconds=seconds)
    db.commit()


def _set_enrollment_age(db, endpoint_id: str, seconds: int) -> None:
    from app.models import Endpoint

    ep = db.get(Endpoint, uuid.UUID(endpoint_id))
    ep.enrolled_at = datetime.now(UTC) - timedelta(seconds=seconds)
    db.commit()


def _audit_events(db, endpoint_id: str, event_type: str) -> list:
    from app.models import AuditLog
    from sqlalchemy import select

    return list(
        db.scalars(
            select(AuditLog).where(
                AuditLog.target == endpoint_id,
                AuditLog.event_type == event_type,
            )
        ).all()
    )


# --- Heartbeat basics -------------------------------------------------------


def test_heartbeat_updates_last_seen_and_version(client, auth_headers, db):
    endpoint_id, cred = _enroll(client, auth_headers, "hb-host")
    resp = _hb(client, cred, version="9.9.9")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["endpoint_id"] == endpoint_id
    assert body["status"] == "active"

    health = client.get(
        f"/api/v1/endpoints/{endpoint_id}/health", headers=auth_headers
    ).json()
    assert health["last_heartbeat_at"] is not None
    age = datetime.now(UTC) - datetime.fromisoformat(health["last_heartbeat_at"])
    assert age.total_seconds() < 60
    assert health["agent_version"] == "9.9.9"
    assert health["collector_status"] == "healthy"
    assert health["seconds_since_heartbeat"] < 60
    assert health["heartbeat_interval_seconds"] == 300
    assert health["offline_threshold_seconds"] == 900


def test_routine_heartbeats_are_not_audited(client, auth_headers, db):
    """Only lifecycle events are audited — never per-heartbeat noise."""
    endpoint_id, cred = _enroll(client, auth_headers, "quiet-host")
    for _ in range(3):
        assert _hb(client, cred).status_code == 200
    assert len(_audit_events(db, endpoint_id, "endpoint.enrolled")) == 1
    # no heartbeat/offline/online events for a healthy chatty agent
    assert _audit_events(db, endpoint_id, "endpoint.online") == []
    assert _audit_events(db, endpoint_id, "endpoint.offline") == []
    from app.models import AuditLog
    from sqlalchemy import select

    heartbeat_noise = db.scalars(
        select(AuditLog).where(
            AuditLog.target == endpoint_id,
            AuditLog.event_type.like("%heartbeat%"),
        )
    ).all()
    assert heartbeat_noise == []


# --- Offline detection (periodic task) -------------------------------------


def test_scan_marks_stale_endpoint_offline_and_audits(client, auth_headers, db):
    from app.tasks.jobs import scan_endpoint_offline

    endpoint_id, _cred = _enroll(client, auth_headers, "stale-host")
    _set_heartbeat_age(db, endpoint_id, seconds=2000)  # > 900s threshold

    transitions = scan_endpoint_offline()
    assert transitions >= 1

    ep_status = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()["status"]
    assert ep_status == "offline"

    events = _audit_events(db, endpoint_id, "endpoint.offline")
    assert len(events) == 1

    health = client.get(
        f"/api/v1/endpoints/{endpoint_id}/health", headers=auth_headers
    ).json()
    assert health["status"] == "offline"
    assert health["collector_status"] == "offline"


def test_scan_never_duplicates_transitions(client, auth_headers, db):
    from app.tasks.jobs import scan_endpoint_offline

    endpoint_id, _cred = _enroll(client, auth_headers, "once-host")
    _set_heartbeat_age(db, endpoint_id, seconds=2000)

    assert scan_endpoint_offline() >= 1
    assert len(_audit_events(db, endpoint_id, "endpoint.offline")) == 1

    # repeat runs: the row no longer matches (status='active') → no new
    # transition and no duplicate audit event for this endpoint
    scan_endpoint_offline()
    scan_endpoint_offline()
    assert len(_audit_events(db, endpoint_id, "endpoint.offline")) == 1


def test_scan_keeps_fresh_enrollment_active(client, auth_headers, db):
    from app.tasks.jobs import scan_endpoint_offline

    endpoint_id, _cred = _enroll(client, auth_headers, "fresh-host")
    # No heartbeat yet — grace is measured from enrollment (recent → active).
    scan_endpoint_offline()
    status = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()["status"]
    assert status == "active"


def test_never_heartbeated_beyond_grace_goes_offline_not_revoked(
    client, auth_headers, db
):
    """Missing heartbeat must never be confused with revocation."""
    from app.tasks.jobs import scan_endpoint_offline

    endpoint_id, _cred = _enroll(client, auth_headers, "silent-host")
    _set_enrollment_age(db, endpoint_id, seconds=5000)
    scan_endpoint_offline()

    ep = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert ep["status"] == "offline"
    assert ep["status"] != "revoked"

    health = client.get(
        f"/api/v1/endpoints/{endpoint_id}/health", headers=auth_headers
    ).json()
    assert health["collector_status"] == "offline"
    assert health["status"] == "offline"


# --- Recovery ---------------------------------------------------------------


def test_valid_heartbeat_recovers_offline_endpoint(client, auth_headers, db):
    from app.tasks.jobs import scan_endpoint_offline

    endpoint_id, cred = _enroll(client, auth_headers, "recover-host")
    _set_heartbeat_age(db, endpoint_id, seconds=2000)
    scan_endpoint_offline()
    assert _audit_events(db, endpoint_id, "endpoint.offline")

    resp = _hb(client, cred)  # offline endpoints still authenticate
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"

    health = client.get(
        f"/api/v1/endpoints/{endpoint_id}/health", headers=auth_headers
    ).json()
    assert health["status"] == "active"
    assert health["collector_status"] == "healthy"

    # exactly one recovery audit — repeated heartbeats add nothing
    assert _hb(client, cred).status_code == 200
    assert len(_audit_events(db, endpoint_id, "endpoint.online")) == 1


def test_late_heartbeat_band(client, auth_headers, db):
    """Between interval and threshold: still active but reported 'late'."""
    endpoint_id, _cred = _enroll(client, auth_headers, "late-host")
    _set_heartbeat_age(db, endpoint_id, seconds=500)  # >300 interval, <900
    health = client.get(
        f"/api/v1/endpoints/{endpoint_id}/health", headers=auth_headers
    ).json()
    assert health["status"] == "active"
    assert health["collector_status"] == "late"
    assert health["seconds_since_heartbeat"] >= 500


# --- Revocation is terminal -------------------------------------------------


def test_revoked_endpoint_never_returns_via_heartbeat(client, auth_headers, db):
    from app.tasks.jobs import scan_endpoint_offline

    endpoint_id, cred = _enroll(client, auth_headers, "revoked-host")
    resp = client.post(
        f"/api/v1/endpoints/{endpoint_id}/revoke", headers=auth_headers
    )
    assert resp.status_code == 200

    # heartbeat and inventory are both rejected for revoked credentials
    assert _hb(client, cred).status_code == 401
    inv = client.post(
        "/api/v1/agent/inventory",
        headers={"Authorization": f"Bearer {cred}"},
        json={"system": {"hostname": "revoked-host"}},
    )
    assert inv.status_code == 401

    # the scanner never touches revoked rows
    scan_endpoint_offline()
    ep = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert ep["status"] == "revoked"

    health = client.get(
        f"/api/v1/endpoints/{endpoint_id}/health", headers=auth_headers
    ).json()
    assert health["collector_status"] == "revoked"
    assert _audit_events(db, endpoint_id, "endpoint.online") == []
    assert _audit_events(db, endpoint_id, "endpoint.revoked")


def test_revoked_endpoint_stays_revoked_even_with_fresh_heartbeat_time(
    client, auth_headers, db
):
    """Status column is authoritative: a fresh timestamp cannot resurrect
    a revoked endpoint (auth already blocks it; the scanner's WHERE clause
    only matches 'active')."""
    from app.models import Endpoint
    from app.tasks.jobs import scan_endpoint_offline

    endpoint_id, _cred = _enroll(client, auth_headers, "zombie-host")
    client.post(f"/api/v1/endpoints/{endpoint_id}/revoke", headers=auth_headers)
    ep = db.get(Endpoint, uuid.UUID(endpoint_id))
    ep.last_heartbeat_at = datetime.now(UTC)  # pretend fresh
    db.commit()

    scan_endpoint_offline()
    db.expire_all()
    assert db.get(Endpoint, uuid.UUID(endpoint_id)).status == "revoked"


# --- Health endpoint --------------------------------------------------------


def test_health_endpoint_shape_and_utc(client, auth_headers):
    endpoint_id, _cred = _enroll(client, auth_headers, "shape-host")
    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/health", headers=auth_headers
    )
    assert resp.status_code == 200
    body = resp.json()
    for key in (
        "endpoint_id",
        "status",
        "collector_status",
        "last_heartbeat_at",
        "last_inventory_at",
        "seconds_since_heartbeat",
        "agent_version",
        "heartbeat_interval_seconds",
        "offline_threshold_seconds",
        "server_time",
    ):
        assert key in body, key
    assert body["endpoint_id"] == endpoint_id
    # server_time must be a UTC instant with timezone info
    server_time = datetime.fromisoformat(body["server_time"])
    assert server_time.utcoffset() == timedelta(0)


def test_health_404_for_unknown_endpoint(client, auth_headers):
    resp = client.get(
        f"/api/v1/endpoints/{uuid.uuid4()}/health", headers=auth_headers
    )
    assert resp.status_code == 404


# --- List filtering / sorting / overview ------------------------------------


def test_list_filters_status_os_agent_version_hostname(
    client, auth_headers, db
):
    win_id, _ = _enroll(client, auth_headers, "win01", os="windows", agent_version="1.0.0")
    lin_id, lin_cred = _enroll(client, auth_headers, "lin01", os="linux", agent_version="2.0.0")
    _hb(client, lin_cred, version="2.0.0")  # keep the enrolled agent_version

    # status filter
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"status": "active"}
    )
    assert resp.status_code == 200
    ids = {i["id"] for i in resp.json()["items"]}
    assert win_id in ids and lin_id in ids

    # os filter (shared test DB may hold other windows hosts)
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"os": "windows"}
    )
    ids = {i["id"] for i in resp.json()["items"]}
    assert win_id in ids and lin_id not in ids

    # agent version filter
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"agent_version": "2.0.0"}
    )
    ids = {i["id"] for i in resp.json()["items"]}
    assert lin_id in ids and win_id not in ids

    # hostname search
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"q": "win0"}
    )
    ids = {i["id"] for i in resp.json()["items"]}
    assert win_id in ids and lin_id not in ids

    # heartbeat range: only lin01 has a heartbeat (fresh)
    cutoff = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    resp = client.get(
        "/api/v1/endpoints",
        headers=auth_headers,
        params={"heartbeat_from": cutoff},
    )
    ids = {i["id"] for i in resp.json()["items"]}
    assert lin_id in ids
    assert win_id not in ids  # never heartbeated → excluded by range

    # equal bounds are valid (inclusive range)
    resp = client.get(
        "/api/v1/endpoints",
        headers=auth_headers,
        params={"heartbeat_from": cutoff, "heartbeat_to": cutoff},
    )
    assert resp.status_code == 200

    # offline status filter accepts the new state (no 422 from pattern)
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"status": "offline"}
    )
    assert resp.status_code == 200

    # allowlisted sorting only
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"sort": "hostname"}
    )
    assert resp.status_code == 200
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"sort": "secret"}
    )
    assert resp.status_code == 400

    # guard: both endpoints really exist (filters above are meaningful)
    from app.models import Endpoint
    from sqlalchemy import select

    found = {str(e.id) for e in db.scalars(select(Endpoint)).all()}
    assert {win_id, lin_id} <= found


def test_overview_counts_are_real(client, auth_headers):
    win_id, win_cred = _enroll(client, auth_headers, "ov-win", os="windows")
    _enroll(client, auth_headers, "ov-lin", os="linux")

    # One endpoint reports inventory → inventory_reported reflects it.
    from tests.test_agent_api import _agent_headers, _inventory

    inv = client.post(
        "/api/v1/agent/inventory",
        headers=_agent_headers(win_cred),
        json=_inventory("ov-win"),
    )
    assert inv.status_code == 200, inv.text

    body = client.get("/api/v1/endpoints/overview", headers=auth_headers).json()
    assert body["total"] >= 2
    assert body["windows"] >= 1
    assert body["linux"] >= 1
    assert body["total"] == body["active"] + body["offline"] + body["revoked"]
    assert body["total"] == body["windows"] + body["linux"] + body["other_os"]
    assert isinstance(body["inventory_reported"], int)
    assert 1 <= body["inventory_reported"] <= body["total"]
    assert len(body["latest_enrollments"]) >= 1
    assert any(e["id"] == win_id for e in body["latest_enrollments"])


def test_overview_visible_to_readonly(client, readonly_user):
    headers = _login(client, readonly_user.email)
    resp = client.get("/api/v1/endpoints/overview", headers=headers)
    assert resp.status_code == 200
    assert {"total", "active", "offline", "revoked", "windows", "linux"} <= set(
        resp.json()
    )


def test_list_rows_include_last_inventory_at(client, auth_headers):
    """Phase 2.8: list rows expose the last inventory timestamp so the
    dashboard table can show collection recency without extra requests."""
    endpoint_id, cred = _enroll(client, auth_headers, "invcol-host")

    def fetch_row():
        items = client.get(
            "/api/v1/endpoints",
            headers=auth_headers,
            params={"q": "invcol"},
        ).json()["items"]
        return next(r for r in items if r["id"] == endpoint_id)

    assert fetch_row()["last_inventory_at"] is None

    from tests.test_agent_api import _agent_headers, _inventory

    resp = client.post(
        "/api/v1/agent/inventory",
        headers=_agent_headers(cred),
        json=_inventory("invcol-host"),
    )
    assert resp.status_code == 200, resp.text

    row = fetch_row()
    assert row["last_inventory_at"] is not None
