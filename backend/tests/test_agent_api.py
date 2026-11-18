"""Agent API tests (Phase 2.2/2.3 contract): credential authentication,
identity separation, cross-endpoint isolation, rotation, revocation,
payload validation and size limits."""

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


def _enroll(client, headers, hostname: str) -> tuple[str, str]:
    """Admin mints a token, agent enrolls. Returns (endpoint_id, credential)."""
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
    body = resp.json()
    return body["endpoint_id"], body["credential"]


def _agent_headers(credential: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {credential}"}


def _inventory(hostname: str, packages: list | None = None) -> dict:
    return {
        "system": {
            "hostname": hostname,
            "fqdn": f"{hostname}.example.com",
            "os": "linux",
            "distribution": "ubuntu",
            "distribution_version": "24.04",
            "os_arch": "x86_64",
            "kernel": "6.8.0-45-generic",
            "uptime_seconds": 999,
        },
        "hardware": {
            "manufacturer": "QEMU",
            "cpu_model": "Common KVM processor",
            "cpu_cores": 4,
            "memory_bytes": 8 * 1024**3,
            "disk_bytes": 100 * 1024**3,
        },
        "network": {
            "interfaces": [
                {
                    "name": "eth0",
                    "mac": "52:54:00:12:34:56",
                    "ipv4": ["192.0.2.10"],
                    "is_up": True,
                }
            ],
            "ip_addresses": ["192.0.2.10"],
            "mac_addresses": ["52:54:00:12:34:56"],
        },
        "filesystems": [
            {"mount": "/", "fstype": "ext4", "total_bytes": 100 * 1024**3,
             "used_bytes": 40 * 1024**3}
        ],
        "packages": [{"name": "curl", "version": "8.5.0", "package_manager": "dpkg"}]
        if packages is None
        else packages,
        "facts": {"collector.version": "0.2.0"},
    }


# --- Authentication ---------------------------------------------------------


def test_agent_routes_require_credential(client, auth_headers):
    endpoint_id, _cred = _enroll(client, auth_headers, "noauth-host")
    for path in ("/api/v1/agent/heartbeat", "/api/v1/agent/inventory"):
        resp = client.post(path, json={})
        assert resp.status_code == 401, path
        assert resp.headers["content-type"].startswith("application/problem+json")


def test_user_jwt_rejected_on_agent_routes(client, auth_headers):
    """Agent identity is separate: a user access token is not an agent
    credential."""
    resp = client.post(
        "/api/v1/agent/heartbeat", headers=auth_headers, json={}
    )
    assert resp.status_code == 401
    assert resp.json()["title"] == "Not authenticated"


def test_agent_credential_rejected_on_user_routes(client, auth_headers):
    _endpoint_id, cred = _enroll(client, auth_headers, "userroute-host")
    resp = client.get("/api/v1/users", headers=_agent_headers(cred))
    assert resp.status_code == 401
    resp = client.get("/api/v1/endpoints", headers=_agent_headers(cred))
    assert resp.status_code == 401


def test_garbage_bearer_rejected(client, auth_headers):
    resp = client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": "Bearer not-a-credential"},
        json={},
    )
    assert resp.status_code == 401


def test_wrong_prefix_credential_rejected(client, auth_headers):
    """A token shaped like a credential but without the agent prefix fails."""
    resp = client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer {'x' * 43}"},
        json={},
    )
    assert resp.status_code == 401


def test_failed_agent_auth_is_audited(client, auth_headers):
    _enroll(client, auth_headers, "auditfail-host")
    client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer eitop_ep_{'z' * 43}"},
        json={},
    )

    from app.core.database import SessionLocal
    from app.models import AuditLog
    from sqlalchemy import select

    with SessionLocal() as s:
        rows = s.scalars(
            select(AuditLog).where(AuditLog.event_type == "auth.agent.failure")
        ).all()
    assert rows, "failed agent authentication must be audited"
    assert rows[-1].outcome == "failure"
    assert "unknown_credential" in (rows[-1].detail or "")


# --- Heartbeat & inventory --------------------------------------------------


def test_heartbeat_updates_endpoint(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "hb-host")
    resp = client.post(
        "/api/v1/agent/heartbeat",
        headers=_agent_headers(cred),
        json={"agent_version": "0.3.1"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["endpoint_id"] == endpoint_id

    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert detail["agent_version"] == "0.3.1"
    assert detail["last_heartbeat_at"] is not None


def test_inventory_submission_and_admin_visibility(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "inv-host")
    resp = client.post(
        "/api/v1/agent/inventory",
        headers=_agent_headers(cred),
        json=_inventory("inv-host"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["endpoint_id"] == endpoint_id
    assert body["counts"]["packages"] == 1
    assert body["counts"]["facts"] >= 3

    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert detail["metadata"]["cpu_cores"] == 4
    assert detail["metadata"]["ip_addresses"] == ["192.0.2.10"]
    assert detail["metadata"]["serial_number"] is None
    assert detail["software_count"] == 1
    fact_keys = {f["key"] for f in detail["facts"]}
    assert {"system.distribution", "system.uptime_seconds",
            "network.interfaces", "filesystem.usage"} <= fact_keys


def test_inventory_is_idempotent(client, auth_headers):
    """Same submission twice → same counts, no duplicate rows."""
    endpoint_id, cred = _enroll(client, auth_headers, "idem-host")
    headers = _agent_headers(cred)

    first = client.post(
        "/api/v1/agent/inventory", headers=headers, json=_inventory("idem-host")
    )
    assert first.status_code == 200
    second = client.post(
        "/api/v1/agent/inventory", headers=headers, json=_inventory("idem-host")
    )
    assert second.status_code == 200
    assert first.json()["counts"] == second.json()["counts"]

    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert detail["software_count"] == 1
    # Facts are upserted, not appended
    keys = [f["key"] for f in detail["facts"]]
    assert len(keys) == len(set(keys))


def test_inventory_updates_changed_packages(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "pkg-host")
    headers = _agent_headers(cred)
    client.post(
        "/api/v1/agent/inventory", headers=headers, json=_inventory("pkg-host")
    )
    changed = _inventory(
        "pkg-host",
        packages=[
            {"name": "curl", "version": "8.6.0", "package_manager": "dpkg"},
            {"name": "nginx", "version": "1.24", "package_manager": "dpkg"},
        ],
    )
    client.post("/api/v1/agent/inventory", headers=headers, json=changed)

    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert detail["software_count"] == 2

    from app.core.database import SessionLocal
    from app.models import EndpointSoftware
    from sqlalchemy import select

    with SessionLocal() as s:
        rows = s.scalars(
            select(EndpointSoftware).where(
                EndpointSoftware.endpoint_id == uuid.UUID(endpoint_id)
            )
        ).all()
    by_name = {r.name: r.version for r in rows}
    assert by_name == {"curl": "8.6.0", "nginx": "1.24"}


def test_removed_packages_are_dropped(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "drop-host")
    headers = _agent_headers(cred)
    client.post("/api/v1/agent/inventory", headers=headers, json=_inventory("drop-host"))
    slim = _inventory("drop-host", packages=[])
    client.post("/api/v1/agent/inventory", headers=headers, json=slim)

    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert detail["software_count"] == 0


# --- Isolation & impersonation ----------------------------------------------


def test_cross_endpoint_isolation(client, auth_headers):
    """Agent A's inventory can only ever land on endpoint A."""
    ep_a, cred_a = _enroll(client, auth_headers, "iso-a")
    ep_b, _cred_b = _enroll(client, auth_headers, "iso-b")

    resp = client.post(
        "/api/v1/agent/inventory",
        headers=_agent_headers(cred_a),
        json=_inventory("iso-a"),
    )
    assert resp.status_code == 200
    assert resp.json()["endpoint_id"] == ep_a

    detail_b = client.get(
        f"/api/v1/endpoints/{ep_b}", headers=auth_headers
    ).json()
    assert detail_b["metadata"] is None
    assert detail_b["facts"] == []
    assert detail_b["software_count"] == 0

    detail_a = client.get(
        f"/api/v1/endpoints/{ep_a}", headers=auth_headers
    ).json()
    assert detail_a["software_count"] == 1


def test_endpoint_id_in_payload_is_rejected(client, auth_headers):
    """Impersonation attempt: a smuggled endpoint_id is a validation error,
    never an authorization input."""
    _ep_a, cred_a = _enroll(client, auth_headers, "smuggle-a")
    ep_b, _ = _enroll(client, auth_headers, "smuggle-b")

    payload = _inventory("smuggle-a")
    payload["endpoint_id"] = ep_b  # try to write onto B
    resp = client.post(
        "/api/v1/agent/inventory",
        headers=_agent_headers(cred_a),
        json=payload,
    )
    assert resp.status_code == 422

    payload2 = {"agent_version": "1.0", "endpoint_id": ep_b}
    resp2 = client.post(
        "/api/v1/agent/heartbeat",
        headers=_agent_headers(cred_a),
        json=payload2,
    )
    assert resp2.status_code == 422


def test_hostname_claim_does_not_grant_access(client, auth_headers):
    """Knowing another endpoint's hostname grants nothing."""
    _ep_a, _cred_a = _enroll(client, auth_headers, "claimed-host")
    resp = client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer eitop_ep_{'q' * 43}"},
        json={"agent_version": "0.0.1"},
    )
    assert resp.status_code == 401


# --- Rotation & revocation --------------------------------------------------


def test_agent_self_rotation_invalidates_old_credential(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "rot-host")

    rot = client.post(
        "/api/v1/agent/rotate-credential", headers=_agent_headers(cred)
    )
    assert rot.status_code == 200, rot.text
    new_cred = rot.json()["credential"]
    assert new_cred != cred
    assert new_cred.startswith("eitop_ep_")

    # Old credential is dead immediately
    old = client.post(
        "/api/v1/agent/heartbeat", headers=_agent_headers(cred), json={}
    )
    assert old.status_code == 401

    # New credential works
    new = client.post(
        "/api/v1/agent/heartbeat",
        headers=_agent_headers(new_cred),
        json={"agent_version": "0.4.0"},
    )
    assert new.status_code == 200


def test_admin_rotation_flow(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "adm-rot-host")

    resp = client.post(
        f"/api/v1/endpoints/{endpoint_id}/rotate-credential", headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    new_cred = resp.json()["credential"]
    assert new_cred != cred

    # Old credential rejected, new one accepted
    assert (
        client.post(
            "/api/v1/agent/heartbeat", headers=_agent_headers(cred), json={}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/agent/heartbeat", headers=_agent_headers(new_cred), json={}
        ).status_code
        == 200
    )

    # The credential appears ONLY in the rotate response — never in reads
    listed = client.get("/api/v1/endpoints", headers=auth_headers)
    detail = client.get(f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers)
    assert new_cred not in listed.text
    assert new_cred not in detail.text
    assert cred not in listed.text

    # Rotation is audited without the secret
    from app.core.database import SessionLocal
    from app.models import AuditLog
    from sqlalchemy import select

    with SessionLocal() as s:
        rows = s.scalars(
            select(AuditLog).where(
                AuditLog.event_type == "endpoint.credential.rotated",
                AuditLog.target == endpoint_id,
            )
        ).all()
    assert rows, "rotation must be audited"
    for row in rows:
        assert new_cred not in (row.detail or "")
        assert cred not in (row.detail or "")


def test_revoke_endpoint_kills_credentials_immediately(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "revoke-host")
    assert (
        client.post(
            "/api/v1/agent/heartbeat", headers=_agent_headers(cred), json={}
        ).status_code
        == 200
    )

    resp = client.post(
        f"/api/v1/endpoints/{endpoint_id}/revoke", headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "revoked"
    assert resp.json()["revoked_credentials"] >= 1

    # Immediate effect — no caching, no grace period
    assert (
        client.post(
            "/api/v1/agent/heartbeat", headers=_agent_headers(cred), json={}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/agent/inventory",
            headers=_agent_headers(cred),
            json=_inventory("revoke-host"),
        ).status_code
        == 401
    )

    # Double revoke is a conflict
    again = client.post(
        f"/api/v1/endpoints/{endpoint_id}/revoke", headers=auth_headers
    )
    assert again.status_code == 409


def test_revoked_endpoint_cannot_rotate(client, auth_headers):
    endpoint_id, _cred = _enroll(client, auth_headers, "rev-rot-host")
    client.post(f"/api/v1/endpoints/{endpoint_id}/revoke", headers=auth_headers)
    resp = client.post(
        f"/api/v1/endpoints/{endpoint_id}/rotate-credential", headers=auth_headers
    )
    assert resp.status_code == 409


def test_revoke_is_audited(client, auth_headers):
    endpoint_id, _cred = _enroll(client, auth_headers, "rev-audit-host")
    client.post(f"/api/v1/endpoints/{endpoint_id}/revoke", headers=auth_headers)

    from app.core.database import SessionLocal
    from app.models import AuditLog
    from sqlalchemy import select

    with SessionLocal() as s:
        rows = s.scalars(
            select(AuditLog).where(
                AuditLog.event_type == "endpoint.revoked",
                AuditLog.target == endpoint_id,
            )
        ).all()
    assert rows
    assert rows[-1].outcome == "success"


# --- Validation & limits ----------------------------------------------------


def test_oversized_enroll_payload_rejected(client):
    resp = client.post(
        "/api/v1/agent/enroll", json={"token": "x" * 20000, "hostname": "h"}
    )
    assert resp.status_code == 413
    assert resp.json()["title"] == "Payload too large"


def test_oversized_inventory_payload_rejected(client, auth_headers):
    _endpoint_id, cred = _enroll(client, auth_headers, "big-host")
    huge = _inventory("big-host")
    huge["facts"] = {"big": "y" * (6 * 1024 * 1024)}
    resp = client.post(
        "/api/v1/agent/inventory", headers=_agent_headers(cred), json=huge
    )
    assert resp.status_code == 413


def test_inventory_rejects_oversized_fact_value(client, auth_headers):
    _endpoint_id, cred = _enroll(client, auth_headers, "factlim-host")
    payload = _inventory("factlim-host")
    payload["facts"] = {"oversized": "z" * 9000}
    resp = client.post(
        "/api/v1/agent/inventory", headers=_agent_headers(cred), json=payload
    )
    assert resp.status_code == 422


def test_inventory_rejects_bad_package_rows(client, auth_headers):
    _endpoint_id, cred = _enroll(client, auth_headers, "badpkg-host")
    payload = _inventory("badpkg-host")
    payload["packages"] = [{"name": "", "version": "1"}]
    resp = client.post(
        "/api/v1/agent/inventory", headers=_agent_headers(cred), json=payload
    )
    assert resp.status_code == 422


def test_enroll_rejects_unknown_extra_fields(client, auth_headers):
    token_resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=auth_headers,
        json={"expires_in_minutes": 60},
    )
    resp = client.post(
        "/api/v1/agent/enroll",
        json={
            "token": token_resp.json()["token"],
            "hostname": "extra-host",
            "is_admin": True,
        },
    )
    assert resp.status_code == 422
