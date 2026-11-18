"""Security hardening tests: CSRF origin check, response headers,
audit-log immutability at the DB level, production doc gating,
timing-equalized login, and admin bootstrap behavior."""

from __future__ import annotations

import uuid

import pytest
from tests.conftest import requires_postgres

PASSWORD = "Str0ng!Passw0rd#2026"


# --- Security headers -------------------------------------------------------


def test_security_headers_present_on_responses(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers["Permissions-Policy"]
    assert resp.headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_security_headers_present_on_error_responses(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


# --- CSRF / Origin check ----------------------------------------------------


def test_cross_origin_login_rejected(client, admin_user):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": PASSWORD},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403
    assert resp.json()["title"] == "Cross-origin request rejected"


def test_cross_origin_state_change_rejected_with_valid_token(client, auth_headers):
    resp = client.post(
        "/api/v1/users",
        headers={**auth_headers, "Origin": "https://evil.example"},
        json={
            "email": f"x-{uuid.uuid4().hex[:8]}@example.com",
            "password": "Cr3ated!User#Pass2026",
            "roles": ["readonly"],
        },
    )
    assert resp.status_code == 403


def test_allowed_origin_state_change_accepted(client, admin_user):
    from app.core.config import get_settings

    allowed_origin = get_settings().cors_origin_list[0]
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": PASSWORD},
        headers={"Origin": allowed_origin},
    )
    assert resp.status_code == 200, resp.text


def test_null_origin_state_change_rejected(client, admin_user):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": PASSWORD},
        headers={"Origin": "null"},
    )
    assert resp.status_code == 403


def test_safe_methods_not_blocked_by_origin(client):
    resp = client.get("/health", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 200


# --- Audit log immutability (database level) --------------------------------


@requires_postgres
def test_audit_logs_reject_update_and_delete_at_db_level(client, admin_user):
    """Even direct SQL as the app role cannot rewrite or remove audit rows."""
    from app.core.database import engine
    from sqlalchemy import text

    row_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_logs (id, event_type, outcome, created_at) "
                "VALUES (:id, 'test.immutability', 'success', now())"
            ),
            {"id": row_id},
        )

    try:
        with engine.begin() as conn, pytest.raises(Exception) as update_err:
            conn.execute(
                text(
                    "UPDATE audit_logs SET outcome = 'failure' WHERE id = :id"
                ),
                {"id": row_id},
            )
        assert "append-only" in str(update_err.value)

        with engine.begin() as conn, pytest.raises(Exception) as delete_err:
            conn.execute(
                text("DELETE FROM audit_logs WHERE id = :id"), {"id": row_id}
            )
        assert "append-only" in str(delete_err.value)
    finally:
        # Documented administrative escape hatch (table owner only).
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
            )
            conn.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": row_id})
            conn.execute(
                text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")
            )


@requires_postgres
def test_audit_logs_still_accept_inserts(client):
    from app.core.database import engine
    from sqlalchemy import text

    row_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_logs (id, event_type, outcome, created_at) "
                "VALUES (:id, 'test.insert', 'success', now())"
            ),
            {"id": row_id},
        )
    # cleanup via documented owner escape hatch
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only"))
        conn.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": row_id})
        conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only"))


# --- Production configuration -----------------------------------------------


def test_docs_disabled_in_production(monkeypatch):
    import app.main as main_module
    from app.core.config import Settings
    from fastapi.testclient import TestClient

    prod = Settings(app_env="production", secret_key="production-test-key-0123456789")
    monkeypatch.setattr(main_module, "get_settings", lambda: prod)

    app = main_module.create_app()
    assert app.docs_url is None
    assert app.openapi_url is None
    assert app.redoc_url is None

    with TestClient(app) as c:
        resp = c.get("/health")
        assert resp.status_code == 200
        assert "strict-transport-security" in resp.headers
        assert c.get("/openapi.json").status_code == 404


# --- Timing-equalized login -------------------------------------------------


@requires_postgres
def test_unknown_email_still_performs_password_verification(client):
    """authenticate_user must burn an Argon2 verify for unknown accounts."""
    import time

    from app.core.database import SessionLocal
    from app.core.security import dummy_password_hash, verify_password
    from app.services.auth_service import authenticate_user

    # The dummy hash must be a real, verifiable Argon2 hash.
    dummy = dummy_password_hash()
    assert dummy.startswith("$argon2")
    assert verify_password("anything", dummy) is False

    with SessionLocal() as s:
        t0 = time.perf_counter()
        result = authenticate_user(s, f"ghost-{uuid.uuid4().hex[:8]}@example.com", "pw")
        elapsed = time.perf_counter() - t0
    assert result is None
    # A real Argon2 verification takes multiple milliseconds; a missing-user
    # early return would be near-instant. Loose floor avoids flakiness.
    assert elapsed > 0.005


# --- Admin bootstrap --------------------------------------------------------


def test_bootstrap_admin_creation_refusal_and_no_password_leak(
    capsys, caplog
):
    """Bootstrap must create exactly once, refuse afterwards, and never
    emit the password to stdout or the logs."""
    from app.core.database import SessionLocal, engine
    from app.db.seed import bootstrap_admin
    from app.models import User
    from sqlalchemy import delete, func, select, text

    # Start from a guaranteed-empty users table. TRUNCATE bypasses the
    # audit append-only row trigger by design (documented in migration
    # 0002) and audit rows referencing these users are truncated with it.
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE users CASCADE"))

    email = f"boot-{uuid.uuid4().hex[:8]}@example.com"
    pw = "Boot#Str0ngPass2026"

    assert bootstrap_admin(email, pw) is True
    # Second run must refuse (users now exist)
    assert bootstrap_admin(f"other-{uuid.uuid4().hex[:8]}@example.com", pw) is False

    captured = capsys.readouterr()
    assert pw not in captured.out
    assert pw not in captured.err
    assert pw not in caplog.text

    with SessionLocal() as s:
        count = (
            s.scalar(
                select(func.count()).select_from(User).where(User.email == email)
            )
            or 0
        )
        assert count == 1
        # Cleanup so later tests see a predictable state (no audit rows
        # reference this user, so a plain delete cannot trip the trigger).
        s.execute(delete(User).where(User.email == email))
        s.commit()


def test_seed_cli_has_no_password_argument():
    """The bootstrap password must never be accepted via argv (ps/history)."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    backend_dir = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-m", "app.db.seed", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(backend_dir),
        env=dict(os.environ),
    )
    assert proc.returncode == 0, proc.stderr
    # Flag appears in usage + option list; after removing every occurrence
    # of the stdin flag, no argv-exposed `--admin-password` flag may remain.
    assert proc.stdout.count("--admin-password-stdin") == 2
    sans = proc.stdout.replace("--admin-password-stdin", "")
    assert "--admin-password" not in sans
