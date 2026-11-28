"""Authentication flow integration tests (login, refresh rotation, logout).

Refresh tokens travel exclusively in the HttpOnly ``eitop_refresh`` cookie —
these tests assert both the behavior and the transport.
"""

from __future__ import annotations

from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]

PASSWORD = "Str0ng!Passw0rd#2026"
COOKIE = "eitop_refresh"


def _login(client, email, password=PASSWORD):
    """Log in with a clean cookie jar; returns the response."""
    client.cookies.clear()
    return client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )


def _cookie(client) -> str | None:
    return client.cookies.get(COOKIE)


def test_login_success_returns_access_token_and_httponly_cookie(client, admin_user):
    resp = _login(client, admin_user.email)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] > 0
    assert body["refresh_expires_in"] > 0

    # Refresh token must NOT be in the body (XSS could read it there).
    assert "refresh_token" not in body

    set_cookie = resp.headers.get_list("set-cookie")
    refresh_cookies = [c for c in set_cookie if c.startswith(f"{COOKIE}=")]
    assert refresh_cookies, f"missing {COOKIE} Set-Cookie: {set_cookie}"
    cookie = refresh_cookies[0].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert "path=/api/v1/auth" in cookie
    assert f"{COOKIE}=" in refresh_cookies[0]


def test_login_wrong_password_is_401_problem(client, admin_user):
    resp = _login(client, admin_user.email, "wrong-password")
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["title"] == "Invalid credentials"
    # Do not leak whether the email exists
    assert "not found" not in body["detail"].lower()
    # No session cookie is issued on failure
    assert not [c for c in resp.headers.get_list("set-cookie") if c.startswith(f"{COOKIE}=")]


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
    client.cookies.clear()
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_me_returns_roles_and_permissions(client, auth_headers):
    resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "admin" in body["roles"]
    assert "admin:write" in body["permissions"]


def _set_cookie(client, value: str) -> None:
    """Install a specific refresh cookie value in the jar (host-only).

    httpx's jar only sends cookies set with an empty domain for the
    ``testserver`` host, so we clear first to guarantee exactly one value.
    """
    client.cookies.clear()
    client.cookies.set(COOKIE, value)


def test_refresh_rotates_cookie_and_body_has_no_token(client, admin_user):
    _login(client, admin_user.email)
    old_refresh = _cookie(client)
    assert old_refresh

    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200, resp.text
    new_pair = resp.json()
    assert "refresh_token" not in new_pair
    assert new_pair["access_token"]
    new_refresh = _cookie(client)
    assert new_refresh and new_refresh != old_refresh

    # Old refresh token is now revoked → reuse must fail AND kill the family
    _set_cookie(client, old_refresh)
    reuse = client.post("/api/v1/auth/refresh")
    assert reuse.status_code == 401
    assert reuse.json()["title"] == "Token reuse detected"


def test_refresh_without_cookie_rejected(client):
    client.cookies.clear()
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401
    assert resp.json()["title"] == "Not authenticated"


def test_refresh_with_garbage_cookie_rejected(client):
    _set_cookie(client, "x" * 43)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401
    assert resp.json()["title"] == "Invalid refresh token"


def test_refresh_with_legacy_body_token_rejected(client, admin_user):
    """A raw refresh token in the JSON body must NOT authenticate rotation."""
    _login(client, admin_user.email)
    old_refresh = _cookie(client)
    client.cookies.clear()
    resp = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": old_refresh}
    )
    assert resp.status_code == 401


def test_logout_revokes_refresh_family_and_clears_cookie(client, admin_user):
    login = _login(client, admin_user.email)
    access = login.json()["access_token"]
    refresh = _cookie(client)
    assert refresh

    out = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert out.status_code == 204
    # Cookie is expired by the response
    cleared = [
        c for c in out.headers.get_list("set-cookie") if c.startswith(f"{COOKIE}=")
    ]
    assert cleared and "max-age=0" in cleared[0].lower()

    # Refreshing after logout must fail (family revoked)
    _set_cookie(client, refresh)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401


def test_access_jwt_stays_valid_until_expiry_after_logout(client, admin_user):
    """Verified Phase 6 contract: access JWTs are stateless.

    Logout revokes the refresh-token family only. An already-issued access
    JWT (HS256, 15 min) keeps authenticating until ``exp`` — this is the
    exact "operation after logout returned 200" case from the earlier
    integration audit, and it is the intended contract for stateless JWTs.
    The security-critical variant (revoked *refresh* token replayed after
    logout) is asserted by ``test_logout_revokes_refresh_family_and_clears_cookie``
    above and must stay 401.
    """
    login = _login(client, admin_user.email)
    access = login.json()["access_token"]

    out = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert out.status_code == 204

    # Old access JWT: still accepted until expiry (stateless, no denylist).
    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}
    )
    assert resp.status_code == 200, resp.text

    # A tampered copy of the same JWT must be rejected even though the
    # untampered one still works — signature check is not bypassed.
    tampered = access[:-4] + ("AAAA" if access[-4:] != "AAAA" else "BBBB")
    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered}"}
    )
    assert resp.status_code == 401


def test_disabled_user_cannot_refresh_and_is_audited(client, admin_user):
    from app.core.database import SessionLocal
    from app.models import User

    login = _login(client, admin_user.email)
    access = login.json()["access_token"]

    with SessionLocal() as s:
        u = s.get(User, admin_user.id)
        u.is_active = False
        s.commit()

    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401

    # The attempt must be recorded against this user. Read the audit trail
    # straight from the DB — the disabled admin's own token is now invalid,
    # so the API reader would (correctly) reject it.
    from app.models import AuditLog
    from sqlalchemy import select

    with SessionLocal() as s:
        rows = s.scalars(
            select(AuditLog).where(
                AuditLog.event_type == "auth.refresh.failure",
                AuditLog.target == admin_user.id.hex,
            )
        ).all()
    assert rows, "disabled-account refresh attempt was not audited"
    assert rows[0].outcome == "failure"

    # And the access token must stop working too
    me = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}
    )
    assert me.status_code == 401


def test_logout_succeeds_after_access_token_expiry(client, admin_user):
    """Phase 6 audit A2: the refresh cookie alone must authorize logout.

    Previously logout required a *valid* access JWT, so a user returning
    after the 15-minute expiry got 401 and the session family stayed
    alive — logout silently failed exactly when it mattered most.
    """
    from datetime import UTC, datetime, timedelta

    import jwt as pyjwt
    from app.core.config import get_settings
    from app.core.security import JWT_ALGORITHM, JWT_ISSUER

    _login(client, admin_user.email)
    refresh = _cookie(client)
    assert refresh

    settings = get_settings()
    now = datetime.now(UTC)
    expired = pyjwt.encode(
        {
            "sub": str(admin_user.id),
            "email": admin_user.email,
            "type": "access",
            "iss": JWT_ISSUER,
            "iat": now - timedelta(minutes=30),
            "exp": now - timedelta(minutes=15),
            "jti": "x" * 32,
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )

    # Expired access token presented → still logs out (cookie is authority)
    out = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {expired}"},
    )
    assert out.status_code == 204, out.text

    # The family must actually be dead
    _set_cookie(client, refresh)
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_logout_without_any_access_token_still_revokes(client, admin_user):
    """Cookie-only logout (no Authorization header at all) revokes too."""
    _login(client, admin_user.email)
    refresh = _cookie(client)
    assert refresh

    # Re-install the refresh cookie WITHOUT any Authorization header:
    # logout must succeed on cookie authority alone.
    _set_cookie(client, refresh)
    out = client.post("/api/v1/auth/logout")  # no bearer token
    assert out.status_code == 204, out.text

    _set_cookie(client, refresh)
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_logout_rejects_cookie_belonging_to_another_account(
    client, admin_user, readonly_user
):
    """Phase 6 audit A3: a JWT must not revoke a foreign cookie family."""
    # Victim (readonly) logs in; capture their refresh cookie
    _login(client, readonly_user.email)
    victim_refresh = _cookie(client)
    assert victim_refresh

    # Attacker (admin) logs in — jar now holds the attacker's cookie
    attacker_login = _login(client, admin_user.email)
    attacker_access = attacker_login.json()["access_token"]

    # Attacker presents their own valid JWT + the victim's cookie
    _set_cookie(client, victim_refresh)
    out = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {attacker_access}"},
    )
    assert out.status_code == 401, out.text

    # Victim's family must still be alive
    _set_cookie(client, victim_refresh)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200, resp.text


def test_absolute_session_cap_kills_old_family(client, admin_user):
    """Phase 6 audit A9: rotation must not extend a session forever."""
    from datetime import UTC, datetime, timedelta

    from app.core.config import get_settings
    from app.core.database import SessionLocal
    from app.models import RefreshToken
    from sqlalchemy import select

    _login(client, admin_user.email)
    refresh = _cookie(client)
    assert refresh

    # Backdate the whole family beyond the absolute session lifetime
    settings = get_settings()
    with SessionLocal() as s:
        rows = s.scalars(
            select(RefreshToken).where(RefreshToken.user_id == admin_user.id)
        ).all()
        assert rows
        family_id = rows[0].family_id
        cutoff = datetime.now(UTC) - timedelta(
            days=settings.refresh_token_expire_days, hours=1
        )
        for row in rows:
            if row.family_id == family_id:
                row.created_at = cutoff
        s.commit()

    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401, resp.text
    assert resp.json()["title"] == "Session expired"


def test_refresh_uses_row_lock_and_atomic_family_revoke():
    """Phase 6 audit A1/A4: source-level guard for the concurrency fix.

    Refresh must SELECT the presented token FOR UPDATE (serializes
    concurrent rotations of the same cookie) and family revocation must
    be a single UPDATE statement (no read-snapshot-then-loop, which let
    concurrently-committed tokens escape revocation).
    """
    import inspect

    from app.services import auth_service

    source = inspect.getsource(auth_service.refresh)
    assert "with_for_update()" in source, "refresh() must lock the token row"

    revoke_src = inspect.getsource(auth_service._revoke_family)
    assert "update(RefreshToken)" in revoke_src
    assert "synchronize_session=False" in revoke_src

    # The Python-loop revocation pattern must be gone from refresh/logout
    for fn in (auth_service.refresh, auth_service.logout):
        fn_src = inspect.getsource(fn)
        assert "for sibling in" not in fn_src
