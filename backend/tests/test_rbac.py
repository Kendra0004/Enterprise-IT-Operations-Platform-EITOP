"""RBAC authorization tests — permission enforcement per role."""

from __future__ import annotations

import uuid

from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]

PASSWORD = "Str0ng!Passw0rd#2026"


def _login(client, email, password=PASSWORD):
    resp = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def test_anonymous_cannot_list_users(client):
    resp = client.get("/api/v1/users")
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_readonly_cannot_list_users(client, readonly_user):
    headers = _login(client, readonly_user.email)
    resp = client.get("/api/v1/users", headers=headers)
    assert resp.status_code == 403
    assert "admin:read" in resp.json()["detail"]


def test_readonly_cannot_create_users(client, readonly_user):
    headers = _login(client, readonly_user.email)
    resp = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "x@example.com",
            "password": "Another#Passw0rd9",
            "roles": ["readonly"],
        },
    )
    assert resp.status_code == 403


def test_admin_can_list_users(client, auth_headers):
    resp = client.get("/api/v1/users", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert "items" in body


def test_admin_can_list_roles_with_permissions(client, auth_headers):
    resp = client.get("/api/v1/roles", headers=auth_headers)
    assert resp.status_code == 200
    roles = {r["name"]: r for r in resp.json()}
    # All five initial roles must exist
    for name in ("admin", "security_auditor", "operator", "readonly", "agent"):
        assert name in roles, f"missing role {name}"
    # RBAC sanity: readonly must not hold write permissions
    assert not any(p.endswith(":write") for p in roles["readonly"]["permissions"])
    # admin holds admin:write
    assert "admin:write" in roles["admin"]["permissions"]
    # operator can execute automation, readonly cannot
    assert "automation:execute" in roles["operator"]["permissions"]
    assert "automation:execute" not in roles["readonly"]["permissions"]


def test_user_with_no_admin_perms_denied_even_with_valid_token(
    client, readonly_user
):
    headers = _login(client, readonly_user.email)
    # audit endpoint requires audit:read — readonly role lacks it
    resp = client.get("/api/v1/audit-logs", headers=headers)
    assert resp.status_code == 403


def test_admin_can_read_audit_logs(client, auth_headers):
    resp = client.get("/api/v1/audit-logs", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1  # login events were audited


def test_invalid_token_rejected(client):
    resp = client.get(
        "/api/v1/users", headers={"Authorization": "Bearer not.a.token"}
    )
    assert resp.status_code == 401


def test_agent_cannot_list_users(client, agent_user):
    headers = _login(client, agent_user.email)
    resp = client.get("/api/v1/users", headers=headers)
    assert resp.status_code == 403
    assert "admin:read" in resp.json()["detail"]


def test_agent_cannot_create_users(client, agent_user):
    headers = _login(client, agent_user.email)
    resp = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": f"esc-{uuid.uuid4().hex[:8]}@example.com",
            "password": "Escalat#Passw0rd9",
            "roles": ["admin"],
        },
    )
    assert resp.status_code == 403


def test_agent_cannot_read_audit_logs(client, agent_user):
    headers = _login(client, agent_user.email)
    resp = client.get("/api/v1/audit-logs", headers=headers)
    assert resp.status_code == 403


def test_agent_cannot_escalate_by_self_assigning_admin_role(client, agent_user):
    """Vertical escalation attempt: agent tries to mint an admin account."""
    headers = _login(client, agent_user.email)
    resp = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": f"self-{uuid.uuid4().hex[:8]}@example.com",
            "password": "SelfG#Privilege2026",
            "roles": ["admin"],
        },
    )
    assert resp.status_code == 403
    # And the agent still holds only its original permission
    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["roles"] == ["agent"]
    assert "admin:write" not in me["permissions"]


def test_auditor_can_read_audit_but_not_write_users(client, auditor_user):
    headers = _login(client, auditor_user.email)
    assert client.get("/api/v1/audit-logs", headers=headers).status_code == 200
    resp = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": f"no-{uuid.uuid4().hex[:8]}@example.com",
            "password": "Nope#Passw0rd2026",
            "roles": ["readonly"],
        },
    )
    assert resp.status_code == 403
    assert client.get("/api/v1/users", headers=headers).status_code == 403


def test_disabled_admin_token_is_401_not_403(client, auth_headers, admin_user):
    """A valid token for a deactivated account must not authorize anything."""
    from app.core.database import SessionLocal
    from app.models import User

    with SessionLocal() as s:
        u = s.get(User, admin_user.id)
        u.is_active = False
        s.commit()

    resp = client.get("/api/v1/users", headers=auth_headers)
    assert resp.status_code == 401
