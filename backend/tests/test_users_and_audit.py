"""User creation and audit logging integration tests."""

from __future__ import annotations

import uuid

from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]

NEW_USER = {
    "email": "created.user@example.com",
    "password": "Cr3ated!User#Pass2026",
    "full_name": "Created User",
    "roles": ["operator"],
}


def test_admin_creates_user_with_role(client, auth_headers):
    payload = dict(NEW_USER)
    payload["email"] = f"u-{uuid.uuid4().hex[:8]}@example.com"
    resp = client.post("/api/v1/users", headers=auth_headers, json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == payload["email"]
    assert body["roles"] == ["operator"]
    assert body["is_active"] is True
    # Password must not appear in response
    assert "password" not in resp.text.lower().replace("must_change", "")

    # New user can log in with the given password
    login = client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    assert login.status_code == 200


def test_duplicate_user_is_409(client, auth_headers):
    payload = dict(NEW_USER)
    payload["email"] = f"dup-{uuid.uuid4().hex[:8]}@example.com"
    first = client.post("/api/v1/users", headers=auth_headers, json=payload)
    assert first.status_code == 201
    second = client.post("/api/v1/users", headers=auth_headers, json=payload)
    assert second.status_code == 409
    assert second.headers["content-type"].startswith("application/problem+json")


def test_unknown_role_is_400(client, auth_headers):
    payload = dict(NEW_USER)
    payload["email"] = f"r-{uuid.uuid4().hex[:8]}@example.com"
    payload["roles"] = ["nonexistent_role"]
    resp = client.post("/api/v1/users", headers=auth_headers, json=payload)
    assert resp.status_code == 400
    assert "nonexistent_role" in resp.json()["detail"]


def test_short_password_rejected_by_validation(client, auth_headers):
    payload = dict(NEW_USER)
    payload["email"] = f"p-{uuid.uuid4().hex[:8]}@example.com"
    payload["password"] = "short"
    resp = client.post("/api/v1/users", headers=auth_headers, json=payload)
    assert resp.status_code == 422


def test_user_creation_writes_audit_log(client, auth_headers):
    payload = dict(NEW_USER)
    payload["email"] = f"a-{uuid.uuid4().hex[:8]}@example.com"
    resp = client.post("/api/v1/users", headers=auth_headers, json=payload)
    assert resp.status_code == 201

    logs = client.get(
        "/api/v1/audit-logs",
        headers=auth_headers,
        params={"event_type": "user.created"},
    ).json()
    targets = [i["target"] for i in logs["items"]]
    assert payload["email"] in targets
    # Actor recorded as the admin who created the user
    entry = next(i for i in logs["items"] if i["target"] == payload["email"])
    assert entry["outcome"] == "success"


def test_failed_login_writes_audit_log(client, admin_user):
    client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "totally-wrong"},
    )
    # Read audit logs as admin
    from app.core.security import create_access_token

    token, _ = create_access_token(admin_user.id, admin_user.email)
    logs = client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {token}"},
        params={"event_type": "auth.login.failure"},
    ).json()
    assert logs["total"] >= 1
    assert logs["items"][0]["outcome"] == "failure"


def test_audit_log_has_no_password_material(client, auth_headers):
    payload = dict(NEW_USER)
    payload["email"] = f"n-{uuid.uuid4().hex[:8]}@example.com"
    client.post("/api/v1/users", headers=auth_headers, json=payload)
    logs = client.get("/api/v1/audit-logs", headers=auth_headers).json()
    blob = str(logs)
    assert payload["password"] not in blob
    assert "hashed_password" not in blob
