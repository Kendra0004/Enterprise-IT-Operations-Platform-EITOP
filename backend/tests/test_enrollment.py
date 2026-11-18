"""Enrollment lifecycle tests (Phase 2.2): single-use tokens, expiration,
atomic consumption under concurrency, restrictions, rate limiting, audit."""

from __future__ import annotations

import threading
import uuid

import pytest
from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]

PASSWORD = "Str0ng!Passw0rd#2026"


def _login(client, email, password=PASSWORD):
    client.cookies.clear()
    resp = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _create_token(client, headers, **overrides):
    payload = {"expires_in_minutes": 60, **overrides}
    resp = client.post(
        "/api/v1/endpoints/enrollment-tokens", headers=headers, json=payload
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _enroll(client, token, hostname="enroll-host", **extra):
    body = {"token": token, "hostname": hostname, "os": "linux", **extra}
    return client.post("/api/v1/agent/enroll", json=body)


# --- Happy path -------------------------------------------------------------


def test_enrollment_full_lifecycle(client, auth_headers):
    created = _create_token(client, auth_headers)
    assert created["token"] and len(created["token"]) > 32
    assert created["used_at"] is None

    resp = _enroll(client, created["token"], hostname="web01.example.com")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    endpoint_id = body["endpoint_id"]
    credential = body["credential"]
    assert credential.startswith("eitop_ep_")

    # Token row is now consumed and linked to the endpoint
    from app.core.database import SessionLocal
    from app.models import EnrollmentToken
    from sqlalchemy import select

    with SessionLocal() as s:
        row = s.scalar(
            select(EnrollmentToken).where(EnrollmentToken.id == uuid.UUID(created["id"]))
        )
        assert row.used_at is not None
        assert str(row.consumed_by) == endpoint_id

    # Credential authenticates heartbeat + inventory
    headers = {"Authorization": f"Bearer {credential}"}
    hb = client.post(
        "/api/v1/agent/heartbeat", headers=headers, json={"agent_version": "0.2.0"}
    )
    assert hb.status_code == 200, hb.text
    assert hb.json()["endpoint_id"] == endpoint_id

    inv = client.post(
        "/api/v1/agent/inventory",
        headers=headers,
        json={
            "system": {
                "hostname": "web01.example.com",
                "os": "linux",
                "distribution": "ubuntu",
                "distribution_version": "24.04",
                "os_arch": "x86_64",
                "kernel": "6.8.0-45-generic",
                "uptime_seconds": 12345,
            },
            "packages": [
                {"name": "curl", "version": "8.5.0", "package_manager": "dpkg"}
            ],
        },
    )
    assert inv.status_code == 200, inv.text
    assert inv.json()["counts"]["packages"] == 1

    # Audit trail records both events, with NO raw token anywhere
    from app.models import AuditLog

    with SessionLocal() as s:
        events = {
            e.event_type
            for e in s.query(AuditLog)
            .filter(AuditLog.target.in_([created["id"], endpoint_id]))
            .all()
        }
        details = " ".join(
            (e.detail or "")
            for e in s.query(AuditLog)
            .filter(AuditLog.event_type.in_(
                ["endpoint.enrolled", "endpoint.enrollment_token.created"]
            ))
            .all()
        )
    assert "endpoint.enrollment_token.created" in events
    assert "endpoint.enrolled" in events
    assert created["token"] not in details
    assert credential not in details


def test_enrollment_token_single_use(client, auth_headers):
    created = _create_token(client, auth_headers)
    first = _enroll(client, created["token"], hostname="once-1")
    assert first.status_code == 201, first.text

    second = _enroll(client, created["token"], hostname="once-2")
    assert second.status_code == 401
    assert second.json()["title"] == "Invalid enrollment token"

    # The rejected endpoint was never created
    from app.core.database import SessionLocal
    from app.models import Endpoint
    from sqlalchemy import func, select

    with SessionLocal() as s:
        count = s.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(Endpoint.hostname == "once-2")
        )
    assert count == 0


def test_unknown_and_used_tokens_get_identical_responses(client, auth_headers):
    """No enrollment-token oracle: unknown vs used vs expired are identical."""
    created = _create_token(client, auth_headers)
    assert _enroll(client, created["token"], hostname="oracle-a").status_code == 201

    used = _enroll(client, created["token"], hostname="oracle-b")
    unknown = _enroll(client, "e" * 43, hostname="oracle-c")

    assert used.status_code == unknown.status_code == 401
    assert used.json() == unknown.json()


def test_expired_token_rejected(client, auth_headers):
    created = _create_token(client, auth_headers, expires_in_minutes=1)

    from datetime import UTC, datetime, timedelta

    from app.core.database import SessionLocal
    from app.models import EnrollmentToken
    from sqlalchemy import update

    with SessionLocal() as s:
        s.execute(
            update(EnrollmentToken)
            .where(EnrollmentToken.id == uuid.UUID(created["id"]))
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        s.commit()

    resp = _enroll(client, created["token"], hostname="expired-host")
    assert resp.status_code == 401
    assert resp.json() == {
        "type": "about:blank",
        "title": "Invalid enrollment token",
        "status": 401,
        "detail": "Enrollment token is invalid, expired, or already used.",
    }


def test_expired_token_is_audited_with_reason(client, auth_headers):
    created = _create_token(client, auth_headers, expires_in_minutes=1)
    from datetime import UTC, datetime, timedelta

    from app.core.database import SessionLocal
    from app.models import EnrollmentToken
    from sqlalchemy import update

    with SessionLocal() as s:
        s.execute(
            update(EnrollmentToken)
            .where(EnrollmentToken.id == uuid.UUID(created["id"]))
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        s.commit()

    assert _enroll(client, created["token"], hostname="expired-audit").status_code == 401

    from app.models import AuditLog

    with SessionLocal() as s:
        rows = (
            s.query(AuditLog)
            .filter(
                AuditLog.event_type == "endpoint.enrollment.rejected",
                AuditLog.target == created["id"],
            )
            .all()
        )
    assert rows, "rejected enrollment must be audited (commit-before-raise)"
    assert "expired" in (rows[-1].detail or "")
    assert rows[-1].outcome == "failure"


# --- Concurrency ------------------------------------------------------------


def test_concurrent_enrollment_has_exactly_one_winner(client, auth_headers):
    """Two simultaneous enrollments with the same token: atomic claim lets
    exactly one through (no duplicate endpoints, no double consumption)."""
    created = _create_token(client, auth_headers)
    token = created["token"]
    barrier = threading.Barrier(2)
    results: list[tuple] = []
    lock = threading.Lock()
    # Unique per run: the shared test database is not truncated between runs
    suffix = uuid.uuid4().hex[:8]
    hosts = (f"race-{suffix}-1", f"race-{suffix}-2")

    def attempt(hostname: str) -> None:
        from app.core.database import SessionLocal
        from app.core.exceptions import AppError
        from app.schemas.endpoints import AgentEnrollRequest
        from app.services.endpoint_service import enroll

        session = SessionLocal()
        try:
            payload = AgentEnrollRequest(token=token, hostname=hostname)
            barrier.wait(timeout=10)
            endpoint, _cred = enroll(session, payload)
            session.commit()
            with lock:
                results.append(("ok", endpoint.id))
        except AppError as exc:
            session.rollback()
            with lock:
                results.append(("fail", exc.status))
        finally:
            session.close()

    threads = [
        threading.Thread(target=attempt, args=(hosts[0],)),
        threading.Thread(target=attempt, args=(hosts[1],)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "fail"]
    assert len(winners) == 1, f"expected exactly one winner, got {results}"
    assert len(losers) == 1 and losers[0][1] == 401

    from app.core.database import SessionLocal
    from app.models import Endpoint
    from sqlalchemy import func, select

    with SessionLocal() as s:
        count = s.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(Endpoint.hostname.in_(list(hosts)))
        )
    assert count == 1


# --- Restrictions -----------------------------------------------------------


def test_hostname_restriction_rejects_non_matching(client, auth_headers):
    created = _create_token(
        client,
        auth_headers,
        restrictions={"allowed_hostname_patterns": ["*.example.com"]},
    )
    rejected = _enroll(client, created["token"], hostname="evil.attacker.test")
    assert rejected.status_code == 401
    assert rejected.json()["title"] == "Invalid enrollment token"

    accepted = _enroll(client, created["token"], hostname="db01.example.com")
    assert accepted.status_code == 201, accepted.text


def test_group_assignment_via_token(client, auth_headers):
    group = client.post(
        "/api/v1/endpoints/groups",
        headers=auth_headers,
        json={"name": f"prod-{uuid.uuid4().hex[:6]}", "description": "prod"},
    )
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]

    created = _create_token(client, auth_headers, group_id=group_id)
    resp = _enroll(client, created["token"], hostname="grouped-host")
    assert resp.status_code == 201, resp.text

    detail = client.get(
        f"/api/v1/endpoints/{resp.json()['endpoint_id']}", headers=auth_headers
    )
    assert detail.status_code == 200
    assert group.json()["name"] in detail.json()["groups"]


def test_token_for_unknown_group_rejected(client, auth_headers):
    resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=auth_headers,
        json={"expires_in_minutes": 60, "group_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 400
    assert resp.json()["title"] == "Unknown group"


# --- RBAC -------------------------------------------------------------------


def test_readonly_cannot_create_enrollment_tokens(client, readonly_user):
    headers = _login(client, readonly_user.email)
    resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=headers,
        json={"expires_in_minutes": 60},
    )
    assert resp.status_code == 403
    assert "endpoints:write" in resp.json()["detail"]


def test_readonly_can_list_but_not_see_token_values(client, readonly_user):
    headers = _login(client, readonly_user.email)
    resp = client.get("/api/v1/endpoints/enrollment-tokens", headers=headers)
    assert resp.status_code == 200
    for row in resp.json():
        assert "token" not in row


def test_operator_can_create_tokens_but_readonly_cannot(client, operator_user, readonly_user):
    """endpoints:write gates token creation; endpoints:read alone does not."""
    op_headers = _login(client, operator_user.email)
    resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=op_headers,
        json={"expires_in_minutes": 30},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["token"]

    ro_headers = _login(client, readonly_user.email)
    resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=ro_headers,
        json={"expires_in_minutes": 30},
    )
    assert resp.status_code == 403


# --- Rate limiting ----------------------------------------------------------


@requires_redis
def test_enroll_rate_limit_kicks_in(monkeypatch):
    """The enroll route is guarded by a per-IP limiter (token guessing)."""
    import app.core.rate_limit as rl
    from app.core.exceptions import AppError
    from starlette.requests import Request

    class _StubSettings:
        rate_limit_enroll_per_minute = 2

    monkeypatch.setattr(rl, "get_settings", lambda: _StubSettings())
    ident = f"203.0.113.{uuid.uuid4().int % 250}"

    def make_request() -> Request:
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/agent/enroll",
                "headers": [],
                "client": (ident, 4444),
            }
        )

    rl.enroll_rate_limit(make_request())
    rl.enroll_rate_limit(make_request())
    with pytest.raises(AppError) as exc:
        rl.enroll_rate_limit(make_request())
    assert exc.value.status == 429


def test_enroll_route_wires_rate_limit_dependency(client):
    """The dependency is registered on the actual route (not just defined)."""
    from app.api.v1 import agent as agent_module

    route = next(r for r in agent_module.router.routes if r.path == "/agent/enroll")
    dep_names = [
        dep.call.__name__ if hasattr(dep.call, "__name__") else str(dep.call)
        for dep in route.dependant.dependencies
    ]
    assert "enroll_rate_limit" in dep_names
