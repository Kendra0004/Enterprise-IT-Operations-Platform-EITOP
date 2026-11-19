"""Group membership API tests (Phase 2.7): assign/remove, group detail with
members, idempotency, audits, RBAC, 404s and the group_id list filter."""

from __future__ import annotations

import uuid

from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]


def _login(client, email, password="Str0ng!Passw0rd#2026"):
    client.cookies.clear()
    resp = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _enroll(client, headers, hostname: str) -> str:
    token_resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=headers,
        json={"expires_in_minutes": 60},
    )
    assert token_resp.status_code == 201, token_resp.text
    resp = client.post(
        "/api/v1/agent/enroll",
        json={"token": token_resp.json()["token"], "hostname": hostname},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["endpoint_id"]


def _create_group(client, headers, name: str | None = None) -> dict:
    name = name or f"grp-{uuid.uuid4().hex[:6]}"
    resp = client.post(
        "/api/v1/endpoints/groups",
        headers=headers,
        json={"name": name, "description": "membership tests"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


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


# --- Membership mutations ---------------------------------------------------


def test_add_and_remove_membership(client, auth_headers, db):
    endpoint_id = _enroll(client, auth_headers, "mem-host")
    group = _create_group(client, auth_headers)

    added = client.post(
        f"/api/v1/endpoints/{endpoint_id}/groups/{group['id']}",
        headers=auth_headers,
    )
    assert added.status_code == 200, added.text
    body = added.json()
    assert body["id"] == group["id"]
    assert body["endpoint_count"] == 1
    assert [m["id"] for m in body["members"]] == [endpoint_id]

    # group list now reports the membership
    listed = client.get("/api/v1/endpoints/groups", headers=auth_headers)
    row = next(g for g in listed.json() if g["id"] == group["id"])
    assert row["endpoint_count"] == 1

    # endpoint detail reflects the group
    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert group["name"] in detail["groups"]

    removed = client.request(
        "DELETE",
        f"/api/v1/endpoints/{endpoint_id}/groups/{group['id']}",
        headers=auth_headers,
    )
    assert removed.status_code == 200, removed.text
    assert removed.json()["endpoint_count"] == 0

    listed = client.get("/api/v1/endpoints/groups", headers=auth_headers)
    row = next(g for g in listed.json() if g["id"] == group["id"])
    assert row["endpoint_count"] == 0

    # audits recorded once each
    assert len(_audit_events(db, endpoint_id, "endpoint.group.member.added")) == 1
    assert len(_audit_events(db, endpoint_id, "endpoint.group.member.removed")) == 1


def test_membership_mutations_are_idempotent(client, auth_headers, db):
    endpoint_id = _enroll(client, auth_headers, "idem-host")
    group = _create_group(client, auth_headers)

    for _ in range(2):
        resp = client.post(
            f"/api/v1/endpoints/{endpoint_id}/groups/{group['id']}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
    # second add changed nothing → no duplicate audit
    assert len(_audit_events(db, endpoint_id, "endpoint.group.member.added")) == 1

    for _ in range(2):
        resp = client.request(
            "DELETE",
            f"/api/v1/endpoints/{endpoint_id}/groups/{group['id']}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
    assert len(_audit_events(db, endpoint_id, "endpoint.group.member.removed")) == 1


def test_group_detail_lists_members(client, auth_headers):
    a = _enroll(client, auth_headers, "det-a")
    b = _enroll(client, auth_headers, "det-b")
    group = _create_group(client, auth_headers)
    for endpoint_id in (a, b):
        client.post(
            f"/api/v1/endpoints/{endpoint_id}/groups/{group['id']}",
            headers=auth_headers,
        )

    resp = client.get(
        f"/api/v1/endpoints/groups/{group['id']}", headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["endpoint_count"] == 2
    assert {m["hostname"] for m in body["members"]} >= {"det-a", "det-b"}
    # members expose no credential material
    for member in body["members"]:
        assert "credential" not in str(member).lower()


def test_membership_404s(client, auth_headers):
    endpoint_id = _enroll(client, auth_headers, "nf-host")
    group = _create_group(client, auth_headers)

    assert (
        client.post(
            f"/api/v1/endpoints/{uuid.uuid4()}/groups/{group['id']}",
            headers=auth_headers,
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/v1/endpoints/{endpoint_id}/groups/{uuid.uuid4()}",
            headers=auth_headers,
        ).status_code
        == 404
    )
    assert (
        client.get(
            f"/api/v1/endpoints/groups/{uuid.uuid4()}", headers=auth_headers
        ).status_code
        == 404
    )


# --- Group filter on the endpoint list --------------------------------------


def test_endpoint_list_group_filter(client, auth_headers):
    group = _create_group(client, auth_headers)
    inside = _enroll(client, auth_headers, "flt-in")
    outside = _enroll(client, auth_headers, "flt-out")
    client.post(
        f"/api/v1/endpoints/{inside}/groups/{group['id']}", headers=auth_headers
    )

    resp = client.get(
        "/api/v1/endpoints",
        headers=auth_headers,
        params={"group_id": group["id"]},
    )
    assert resp.status_code == 200
    ids = {i["id"] for i in resp.json()["items"]}
    assert inside in ids
    assert outside not in ids


# --- RBAC -------------------------------------------------------------------


def test_readonly_cannot_mutate_membership(client, readonly_user, auth_headers):
    headers = _login(client, readonly_user.email)
    # admin mints the token (readonly lacks endpoints:write)
    token_resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=auth_headers,
        json={"expires_in_minutes": 60},
    )
    resp = client.post(
        "/api/v1/agent/enroll",
        json={"token": token_resp.json()["token"], "hostname": "ro-host"},
    )
    endpoint_id = resp.json()["endpoint_id"]
    group = _create_group(client, auth_headers)

    # reads are fine
    assert client.get("/api/v1/endpoints", headers=headers).status_code == 200
    assert (
        client.get(f"/api/v1/endpoints/groups/{group['id']}", headers=headers).status_code
        == 200
    )

    assert (
        client.post(
            f"/api/v1/endpoints/{endpoint_id}/groups/{group['id']}", headers=headers
        ).status_code
        == 403
    )
    assert (
        client.request(
            "DELETE",
            f"/api/v1/endpoints/{endpoint_id}/groups/{group['id']}",
            headers=headers,
        ).status_code
        == 403
    )


def test_anonymous_membership_access_rejected(client):
    endpoint_id = str(uuid.uuid4())
    group_id = str(uuid.uuid4())
    assert (
        client.post(f"/api/v1/endpoints/{endpoint_id}/groups/{group_id}").status_code
        == 401
    )
    assert (
        client.request(
            "DELETE", f"/api/v1/endpoints/{endpoint_id}/groups/{group_id}"
        ).status_code
        == 401
    )
    assert (
        client.get(f"/api/v1/endpoints/groups/{group_id}").status_code == 401
    )
