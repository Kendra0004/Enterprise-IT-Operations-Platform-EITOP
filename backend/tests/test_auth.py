"""Authentication flow integration tests (login, refresh rotation, logout)."""

from __future__ import annotations

from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]

PASSWORD = "Str0ng!Passw0rd#2026"


def _login(client, email, password=PASSWORD):
    return client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )


def test_login_success_returns_token_pair(client, admin_user):
    resp = _login(client, admin_user.email)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] > 0
    assert body["refresh_expires_in"] > 0


def test_login_wrong_password_is_401_problem(client, admin_user):
    resp = _login(client, admin_user.email, "wrong-password")
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["title"] == "Invalid credentials"
    # Do not leak whether the email exists
    assert "not found" not in body["detail"].lower()


def test_login_unknown_email_is_401(client, admin_user):
    resp = _login(client, "nobody@example.com")
    assert resp.status_code == 401


def test_login_inactive_user_rejected(client, admin_user):
    from app.core.database import SessionLocal
    from app.models import User

    with SessionLocal() as s:
        u = s.get(User, admin_user.id)
        u.is_active = False
        s.commit()
    resp = _login(client, admin_user.email)
    assert resp.status_code == 401


def test_me_requires_token(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_me_returns_roles_and_permissions(client, auth_headers):
    resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "admin" in body["roles"]
    assert "admin:write" in body["permissions"]


def test_refresh_rotates_token(client, admin_user):
    login = _login(client, admin_user.email).json()
    old_refresh = login["refresh_token"]

    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 200, resp.text
    new_pair = resp.json()
    assert new_pair["refresh_token"] != old_refresh
    assert new_pair["access_token"]

    # Old refresh token is now revoked → reuse must fail
    reuse = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert reuse.status_code == 401
    assert reuse.json()["title"] in ("Token reuse detected", "Token expired")


def test_refresh_with_garbage_rejected(client):
    resp = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": "x" * 32}
    )
    assert resp.status_code == 401


def test_logout_revokes_refresh_family(client, admin_user):
    login = _login(client, admin_user.email).json()
    refresh = login["refresh_token"]

    out = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh},
        headers={"Authorization": f"Bearer {login['access_token']}"},
    )
    assert out.status_code == 204

    # Refreshing after logout must fail
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401
