"""Directory API tests (Phase 3.1): RBAC, secrets, isolation, contracts.

Covers:
- permission matrix (admin full; readonly/auditor/operator read-only;
  agent denied everything; anonymous 401);
- the bind password as a WRITE-ONLY secret: absent from every response,
  encrypted at rest, absent from audit details, run errors, category
  results and application logs — traced through a real failure path
  (decrypted in memory, then a refused connection);
- structural isolation: object lists/details require ``connection_id``
  and never bleed across connections;
- expected-failure contract: ``POST …/test`` answers 200 with a
  sanitized label instead of raising;
- pagination/sort validation and the reconciliation decision endpoint.

Environment: PostgreSQL + Redis are real; no Active Directory is
involved anywhere in this file (no LDAP traffic is expected).
"""

from __future__ import annotations

import logging
import uuid

import pytest
from app.models import (
    AuditLog,
    DirectoryComputer,
    DirectoryConnection,
    DirectoryDomain,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectoryOrganizationalUnit,
    DirectoryReconciliation,
    DirectorySyncRun,
    DirectoryUser,
    Endpoint,
)
from app.services.directory.errors import message_for
from app.services.directory.secrets import decrypt_password
from sqlalchemy import delete, select
from tests.conftest import requires_postgres, requires_redis

pytestmark = [requires_postgres, requires_redis]

PASSWORD = "Str0ng!Passw0rd#2026"
SENTINEL = "Sentinel-Bind-Pa55word!"
SEARCH_BASE = "OU=HQ,DC=eitop,DC=test"
BIND_DN = "CN=svc-eitop,DC=eitop,DC=test"
API = "/api/v1/directory"

_TEST_FQDNS = ("ws01.eitop.test", "ws02.eitop.test")
_TEST_HOSTNAMES = ("ws01", "ws02")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_directory_rows(db):
    """Isolate every test: no directory rows or module endpoints linger."""
    for model in (
        DirectoryReconciliation,
        DirectorySyncRun,
        DirectoryGroupMembership,
        DirectoryComputer,
        DirectoryGroup,
        DirectoryUser,
        DirectoryOrganizationalUnit,
        DirectoryDomain,
        DirectoryConnection,
    ):
        db.execute(delete(model))
    db.execute(delete(Endpoint).where(Endpoint.fqdn.in_(_TEST_FQDNS)))
    db.execute(delete(Endpoint).where(Endpoint.hostname.in_(_TEST_HOSTNAMES)))
    db.commit()
    yield
    db.rollback()
    for model in (
        DirectoryReconciliation,
        DirectorySyncRun,
        DirectoryGroupMembership,
        DirectoryComputer,
        DirectoryGroup,
        DirectoryUser,
        DirectoryOrganizationalUnit,
        DirectoryDomain,
        DirectoryConnection,
    ):
        db.execute(delete(model))
    db.commit()


def _login(client, email, password=PASSWORD):
    client.cookies.clear()
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _payload(**overrides) -> dict:
    payload = {
        "name": f"ad-{uuid.uuid4().hex[:8]}",
        "domain_dns": "eitop.test",
        "host": "127.0.0.1",
        "port": 63663,  # nothing listens here: probes fail fast
        "tls_mode": "ldaps",
        "tls_ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "search_base": SEARCH_BASE,
        "bind_username": BIND_DN,
        "bind_password": SENTINEL,
        "page_size": 500,
        "auto_sync": False,
    }
    payload.update(overrides)
    return payload


def _create(client, headers, **overrides) -> dict:
    resp = client.post(f"{API}/connections", headers=headers, json=_payload(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _seed_user(db, connection_id, sam: str, guid: str | None = None) -> DirectoryUser:
    row = DirectoryUser(
        connection_id=connection_id,
        object_guid=guid or str(uuid.uuid4()),
        distinguished_name=f"CN={sam},{SEARCH_BASE}",
        sam_account_name=sam,
        display_name=sam.title(),
        enabled=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ---------------------------------------------------------------------------
# RBAC matrix
# ---------------------------------------------------------------------------


def test_anonymous_gets_401(client):
    resp = client.get(f"{API}/connections")
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_readonly_role_can_read_but_not_write(client, readonly_user):
    headers = _login(client, readonly_user.email)

    assert client.get(f"{API}/connections", headers=headers).status_code == 200
    assert client.get(f"{API}/overview", headers=headers).status_code == 200
    assert client.get(f"{API}/sync-runs", headers=headers).status_code == 200

    forbidden = [
        ("post", f"{API}/connections", _payload()),
        ("post", f"{API}/connections/{uuid.uuid4()}/test", None),
        ("post", f"{API}/connections/{uuid.uuid4()}/sync", None),
        ("delete", f"{API}/connections/{uuid.uuid4()}", None),
        ("patch", f"{API}/connections/{uuid.uuid4()}", {"name": "new-name"}),
    ]
    for method, url, body in forbidden:
        kwargs = {"headers": headers}
        if body is not None:
            kwargs["json"] = body
        resp = getattr(client, method)(url, **kwargs)
        assert resp.status_code == 403, (method, url, resp.status_code, resp.text)
        assert "directory:write" in resp.json()["detail"] or (
            "directory:sync" in resp.json()["detail"]
        )


def test_auditor_role_is_read_only(client, auditor_user):
    headers = _login(client, auditor_user.email)
    assert client.get(f"{API}/connections", headers=headers).status_code == 200
    resp = client.post(f"{API}/connections", headers=headers, json=_payload())
    assert resp.status_code == 403
    assert "directory:write" in resp.json()["detail"]


def test_operator_role_is_read_only(client, operator_user):
    headers = _login(client, operator_user.email)
    assert client.get(f"{API}/overview", headers=headers).status_code == 200
    resp = client.post(
        f"{API}/connections/{uuid.uuid4()}/sync", headers=headers, json={}
    )
    assert resp.status_code == 403
    assert "directory:sync" in resp.json()["detail"]


def test_agent_role_gets_nothing(client, agent_user):
    """The endpoint-collector identity must not see the directory at all."""
    headers = _login(client, agent_user.email)
    for method, url, body in (
        ("get", f"{API}/connections", None),
        ("get", f"{API}/overview", None),
        ("post", f"{API}/connections", _payload()),
        ("post", f"{API}/connections/{uuid.uuid4()}/sync", None),
    ):
        kwargs = {"headers": headers}
        if body is not None:
            kwargs["json"] = body
        resp = getattr(client, method)(url, **kwargs)
        assert resp.status_code == 403, (method, url, resp.status_code)
        # Whatever the route checks first, the agent lacks it.
        assert "directory:" in resp.json()["detail"]


def test_admin_can_manage_connections(client, auth_headers):
    created = _create(client, auth_headers)
    assert created["name"]
    assert created["tls_mode"] == "ldaps"
    assert "bind_password" not in created
    assert "bind_password_encrypted" not in created

    listed = client.get(f"{API}/connections", headers=auth_headers)
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] >= 1
    assert any(item["id"] == created["id"] for item in body["items"])

    detail = client.get(f"{API}/connections/{created['id']}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["tls_ca_pem"]  # CA bundle is not a secret

    deleted = client.delete(
        f"{API}/connections/{created['id']}", headers=auth_headers
    )
    assert deleted.status_code == 204
    assert (
        client.get(f"{API}/connections/{created['id']}", headers=auth_headers).status_code
        == 404
    )


# ---------------------------------------------------------------------------
# The bind password is write-only
# ---------------------------------------------------------------------------


def test_bind_password_never_appears_in_responses(client, auth_headers, db):
    created = _create(client, auth_headers)
    assert SENTINEL not in str(created)
    assert "bind_password" not in created

    # Detail view: no plaintext, no ciphertext.
    detail = client.get(f"{API}/connections/{created['id']}", headers=auth_headers)
    assert SENTINEL not in detail.text
    assert "bind_password_encrypted" not in detail.text

    # List view: no plaintext, no ciphertext, no CA/PEM surprises.
    listed = client.get(f"{API}/connections", headers=auth_headers)
    assert SENTINEL not in listed.text
    assert "bind_password_encrypted" not in listed.text

    # Rotation accepts a new secret and still echoes nothing back.
    rotated = client.patch(
        f"{API}/connections/{created['id']}",
        headers=auth_headers,
        json={"bind_password": "Rotated-Second-Sentinel!"},
    )
    assert rotated.status_code == 200
    assert SENTINEL not in rotated.text
    assert "Rotated-Second-Sentinel!" not in rotated.text
    assert "bind_password" not in rotated.json()

    # At rest: ciphertext only, decryptable back to the rotated value.
    row = db.get(DirectoryConnection, created["id"])
    assert row is not None
    assert row.bind_password_encrypted != SENTINEL
    assert row.bind_password_encrypted != "Rotated-Second-Sentinel!"
    assert decrypt_password(row.bind_password_encrypted) == "Rotated-Second-Sentinel!"
    assert SENTINEL not in row.bind_password_encrypted

    # Audit details carry field NAMES only.
    audits = db.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "directory.connection.updated",
            AuditLog.target == created["id"],
        )
    ).all()
    assert audits
    for audit in audits:
        assert SENTINEL not in (audit.detail or "")
        assert "Rotated-Second-Sentinel!" not in (audit.detail or "")
    created_audit = db.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "directory.connection.created",
            AuditLog.target == created["id"],
        )
    ).first()
    assert created_audit is not None
    assert SENTINEL not in (created_audit.detail or "")


def test_connection_repr_and_validation_reject_secrets_leakage(
    client, auth_headers
):
    # Unknown fields are rejected outright (no smuggling extra data in).
    resp = client.post(
        f"{API}/connections",
        headers=auth_headers,
        json={**_payload(), "bind_password_encrypted": "x" * 20},
    )
    assert resp.status_code == 422
    # Plaintext LDAP is not an option.
    resp = client.post(
        f"{API}/connections", headers=auth_headers, json=_payload(tls_mode="ldap")
    )
    assert resp.status_code == 422
    # A connection row's repr must not expose the credential.
    row = DirectoryConnection(
        name="repr-check",
        domain_dns="eitop.test",
        host="dc.eitop.test",
        search_base=SEARCH_BASE,
        bind_username=BIND_DN,
        bind_password_encrypted="ciphertext-not-plaintext",
    )
    assert SENTINEL not in repr(row)
    assert "ciphertext-not-plaintext" not in repr(row)


def test_failed_connection_test_returns_200_with_sanitized_label(
    client, auth_headers, caplog
):
    """Real decrypt + real probe against a closed port: never raises."""
    created = _create(client, auth_headers)
    with caplog.at_level(logging.DEBUG):
        resp = client.post(
            f"{API}/connections/{created['id']}/test", headers=auth_headers
        )
    # Expected connectivity failures are a 200 result, not an exception.
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert body["label"] in {
        "connection_failed",
        "timeout",
        "tls_error",
        "invalid_credentials",
        "search_base_not_found",
    }
    assert body["message"] == message_for(body["label"])
    assert SENTINEL not in resp.text
    assert "Traceback" not in resp.text
    # The secret never reached the logs either.
    assert SENTINEL not in caplog.text


def test_sync_failure_is_fully_sanitized_end_to_end(
    client, auth_headers, db, monkeypatch, caplog
):
    """Sentinel traced through engine -> run row -> API -> audit -> logs."""
    from app.services.directory.sync_engine import execute_sync

    created = _create(client, auth_headers)

    submitted: list[str] = []
    monkeypatch.setattr(
        "app.services.directory.connection_service.celery_app.send_task",
        lambda name, args=None, **kw: submitted.append(args[0]),
    )
    resp = client.post(f"{API}/connections/{created['id']}/sync", headers=auth_headers)
    assert resp.status_code == 202, resp.text
    run_id = submitted[0]
    assert resp.json()["id"] == run_id
    assert SENTINEL not in resp.text

    # Execute the run for real (decrypted bind password, refused port).
    with caplog.at_level(logging.DEBUG):
        status = execute_sync(uuid.UUID(run_id))
    assert status == "failed"

    run = db.get(DirectorySyncRun, uuid.UUID(run_id))
    assert run is not None
    assert run.status == "failed"
    # The TLS pre-flight runs before any LDAP I/O, so a refused port is
    # reported either as a TLS-handshake failure or a connection failure.
    assert run.category_results["connect"]["label"] in {
        "connection_failed",
        "tls_error",
        "timeout",
    }
    assert run.errors and run.errors[0]["label"] == run.category_results["connect"]["label"]
    blob = str(run.category_results) + str(run.errors)
    assert SENTINEL not in blob
    assert "Traceback" not in blob
    assert SENTINEL not in caplog.text

    # The API returns exactly the same sanitized artifact.
    detail = client.get(f"{API}/sync-runs/{run_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert SENTINEL not in detail.text
    label = run.category_results["connect"]["label"]
    assert detail.json()["errors"][0]["label"] == label
    assert detail.json()["category_results"]["connect"]["status"] == "failed"

    # Audit artifact is sanitized too.
    audit = db.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "directory.sync.failed",
            AuditLog.target == run_id,
        )
    ).first()
    assert audit is not None
    assert SENTINEL not in (audit.detail or "")
    assert label in (audit.detail or "")


def test_enqueue_failure_returns_503_and_leaves_no_running_row(
    client, auth_headers, db, monkeypatch
):
    created = _create(client, auth_headers)

    def boom(*_a, **_k):
        raise OSError("broker down")

    monkeypatch.setattr(
        "app.services.directory.connection_service.celery_app.send_task", boom
    )
    resp = client.post(f"{API}/connections/{created['id']}/sync", headers=auth_headers)
    assert resp.status_code == 503
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert SENTINEL not in resp.text

    runs = db.scalars(
        select(DirectorySyncRun).where(
            DirectorySyncRun.connection_id == uuid.UUID(created["id"])
        )
    ).all()
    assert len(runs) == 1
    assert runs[0].status == "failed"
    assert runs[0].errors[0]["label"] == "task_submission_failed"


def test_concurrent_sync_returns_409(client, auth_headers, db):
    created = _create(client, auth_headers)
    running = DirectorySyncRun(
        connection_id=uuid.UUID(created["id"]),
        status="running",
        trigger="manual",
        category_results={},
    )
    db.add(running)
    db.commit()

    resp = client.post(f"{API}/connections/{created['id']}/sync", headers=auth_headers)
    assert resp.status_code == 409
    assert "already in progress" in resp.json()["detail"]


def test_duplicate_connection_name_conflicts(client, auth_headers):
    created = _create(client, auth_headers, name="only-one")
    resp = client.post(
        f"{API}/connections", headers=auth_headers, json=_payload(name="only-one")
    )
    assert resp.status_code == 409
    assert created["name"] == "only-one"


# ---------------------------------------------------------------------------
# Structural isolation (connection_id required, no cross-bleed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/ous",
        "/users",
        "/groups",
        "/computers",
        "/domains",
    ],
)
def test_object_lists_require_connection_id(client, auth_headers, path):
    resp = client.get(f"{API}{path}", headers=auth_headers)
    assert resp.status_code == 422, resp.text
    assert "connection_id" in resp.text


def test_objects_never_bleed_across_connections(client, auth_headers, db):
    first = _create(client, auth_headers, name="conn-a")
    second = _create(client, auth_headers, name="conn-b")
    user_a = _seed_user(db, uuid.UUID(first["id"]), "alice-a")
    user_b = _seed_user(db, uuid.UUID(second["id"]), "bob-b")

    listed = client.get(
        f"{API}/users",
        headers=auth_headers,
        params={"connection_id": first["id"], "page_size": 100},
    )
    assert listed.status_code == 200
    items = listed.json()["items"]
    sams = {item["sam_account_name"] for item in items}
    assert sams == {"alice-a"}

    # Detail of B's user through A's connection scope -> 404, not a leak.
    resp = client.get(
        f"{API}/users/{user_b.id}",
        headers=auth_headers,
        params={"connection_id": first["id"]},
    )
    assert resp.status_code == 404

    resp = client.get(
        f"{API}/users/{user_a.id}",
        headers=auth_headers,
        params={"connection_id": first["id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["sam_account_name"] == "alice-a"

    # Unknown connection id -> 404 rather than an empty 200.
    resp = client.get(
        f"{API}/users",
        headers=auth_headers,
        params={"connection_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404


def test_search_and_sort_contract(client, auth_headers, db):
    created = _create(client, auth_headers)
    connection_id = created["id"]
    _seed_user(db, uuid.UUID(connection_id), "searchable")

    resp = client.get(
        f"{API}/users",
        headers=auth_headers,
        params={"connection_id": connection_id, "q": "search"},
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

    resp = client.get(
        f"{API}/users",
        headers=auth_headers,
        params={"connection_id": connection_id, "q": "%", "sort": "nope"},
    )
    assert resp.status_code == 400
    detail = resp.json()["detail"].lower()
    assert "allowed" in detail or "sort" in detail

    # page_size bounds are enforced by the schema.
    resp = client.get(
        f"{API}/users",
        headers=auth_headers,
        params={"connection_id": connection_id, "page_size": 5000},
    )
    assert resp.status_code == 422


def test_group_members_and_ou_detail(client, auth_headers, db):
    created = _create(client, auth_headers)
    connection_id = uuid.UUID(created["id"])

    parent = DirectoryOrganizationalUnit(
        connection_id=connection_id,
        object_guid=str(uuid.uuid4()),
        distinguished_name="OU=HQ,DC=eitop,DC=test",
        name="HQ",
    )
    child_ou = DirectoryOrganizationalUnit(
        connection_id=connection_id,
        object_guid=str(uuid.uuid4()),
        distinguished_name="OU=IT,OU=HQ,DC=eitop,DC=test",
        name="IT",
    )
    direct_user = _seed_user(db, connection_id, "carol")
    direct_user.distinguished_name = "CN=carol,OU=HQ,DC=eitop,DC=test"
    deep_user = _seed_user(db, connection_id, "dave")
    deep_user.distinguished_name = "CN=dave,OU=IT,OU=HQ,DC=eitop,DC=test"
    db.commit()
    group = DirectoryGroup(
        connection_id=connection_id,
        object_guid=str(uuid.uuid4()),
        distinguished_name="CN=Team,OU=HQ,DC=eitop,DC=test",
        name="Team",
    )
    db.add_all([parent, child_ou, group])
    db.commit()
    db.refresh(parent)
    db.refresh(group)

    db.add(
        DirectoryGroupMembership(
            connection_id=connection_id,
            group_id=group.id,
            member_type="user",
            member_dn=direct_user.distinguished_name,
            member_object_guid=direct_user.object_guid,
        )
    )
    db.add(
        DirectoryGroupMembership(
            connection_id=connection_id,
            group_id=group.id,
            member_type="unknown",
            member_dn="CN=Foreign,CN=Foreign,DC=other,DC=test",
            member_object_guid=None,
        )
    )
    db.commit()

    ou = client.get(
        f"{API}/ous/{parent.id}",
        headers=auth_headers,
        params={"connection_id": connection_id},
    )
    assert ou.status_code == 200
    body = ou.json()
    assert body["child_ous"] == 1
    assert body["users"] == 1  # direct child only; dave lives deeper
    assert body["groups"] == 1

    members = client.get(
        f"{API}/groups/{group.id}/members",
        headers=auth_headers,
        params={"connection_id": connection_id},
    )
    assert members.status_code == 200
    member_items = members.json()["items"]
    assert members.json()["total"] == 2
    resolved = {m["member_dn"]: m for m in member_items}
    assert resolved[direct_user.distinguished_name]["resolved"] is True
    assert resolved[direct_user.distinguished_name]["display_name"] == "carol"
    foreign = resolved["CN=Foreign,CN=Foreign,DC=other,DC=test"]
    assert foreign["resolved"] is False
    assert foreign["member_type"] == "unknown"
    assert foreign["member_object_guid"] is None

    # The group detail carries the member count without leaking members.
    detail = client.get(
        f"{API}/groups/{group.id}",
        headers=auth_headers,
        params={"connection_id": connection_id},
    )
    assert detail.status_code == 200
    assert detail.json()["member_count"] == 2


# ---------------------------------------------------------------------------
# Overview + sync history contracts
# ---------------------------------------------------------------------------


def test_overview_reports_real_aggregates(client, auth_headers, db):
    created = _create(client, auth_headers)
    connection_id = uuid.UUID(created["id"])
    _seed_user(db, connection_id, "one")
    _seed_user(db, connection_id, "two")
    db.add(
        DirectoryComputer(
            connection_id=connection_id,
            object_guid=str(uuid.uuid4()),
            distinguished_name="CN=WS01,OU=HQ,DC=eitop,DC=test",
            name="WS01",
            dns_hostname="ws01.eitop.test",
        )
    )
    db.commit()

    resp = client.get(f"{API}/overview", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["connections_total"] == 1
    assert body["connections_enabled"] == 1
    assert body["users_total"] == 2
    assert body["users_enabled"] == 2
    assert body["computers"] == 1
    assert body["running_syncs"] == 0
    assert body["failed_runs_24h"] == 0
    assert body["last_sync_success_at"] is None


def test_sync_history_filters_and_detail(client, auth_headers, db):
    created = _create(client, auth_headers)
    connection_id = uuid.UUID(created["id"])
    for status, trigger in (("success", "manual"), ("failed", "scheduled")):
        db.add(
            DirectorySyncRun(
                connection_id=connection_id,
                status=status,
                trigger=trigger,
                category_results={"connect": {"status": "success"}},
                errors=None
                if status == "success"
                else [{"category": "connect", "label": "timeout", "error_count": 1}],
                objects_discovered=5,
            )
        )
    db.commit()

    resp = client.get(
        f"{API}/sync-runs", headers=auth_headers, params={"connection_id": connection_id}
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 2

    resp = client.get(
        f"{API}/sync-runs",
        headers=auth_headers,
        params={"connection_id": connection_id, "status": "failed"},
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

    failed = resp.json()["items"][0]
    detail = client.get(f"{API}/sync-runs/{failed['id']}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["errors"][0]["label"] == "timeout"
    assert detail.json()["category_results"]["connect"]["status"] == "success"

    missing = client.get(f"{API}/sync-runs/{uuid.uuid4()}", headers=auth_headers)
    assert missing.status_code == 404


def test_connection_missing_returns_404(client, auth_headers):
    resp = client.get(f"{API}/connections/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404
    resp = client.post(
        f"{API}/connections/{uuid.uuid4()}/test", headers=auth_headers, json={}
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Reconciliation decisions (manual, audited, validated)
# ---------------------------------------------------------------------------


def _seed_computer(db, connection_id) -> DirectoryComputer:
    row = DirectoryComputer(
        connection_id=connection_id,
        object_guid=str(uuid.uuid4()),
        distinguished_name="CN=WS01,OU=HQ,DC=eitop,DC=test",
        name="WS01",
        dns_hostname="ws01.eitop.test",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _seed_endpoint(db, hostname="ws01", fqdn="ws01.eitop.test") -> Endpoint:
    row = Endpoint(hostname=hostname, fqdn=fqdn, status="active")
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_manual_match_and_reject(client, auth_headers, db):
    created = _create(client, auth_headers)
    connection_id = uuid.UUID(created["id"])
    computer = _seed_computer(db, connection_id)
    endpoint = _seed_endpoint(db)

    resp = client.post(
        f"{API}/computers/{computer.id}/match",
        headers=auth_headers,
        json={"decision": "match", "endpoint_id": str(endpoint.id)},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "matched"
    assert body["method"] == "manual"
    assert body["endpoint_id"] == str(endpoint.id)
    assert body["endpoint_hostname"] == "ws01"
    assert body["reviewed_at"] is not None

    audit = db.scalars(
        select(AuditLog).where(
            AuditLog.event_type == "directory.reconciliation.decided",
            AuditLog.target == str(computer.id),
        )
    ).first()
    assert audit is not None
    assert "match" in (audit.detail or "")

    resp = client.post(
        f"{API}/computers/{computer.id}/match",
        headers=auth_headers,
        json={"decision": "reject"},
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "rejected"
    assert resp.json()["endpoint_id"] is None


def test_match_requires_explicit_valid_endpoint(client, auth_headers, db):
    created = _create(client, auth_headers)
    computer = _seed_computer(db, uuid.UUID(created["id"]))

    resp = client.post(
        f"{API}/computers/{computer.id}/match",
        headers=auth_headers,
        json={"decision": "match"},
    )
    assert resp.status_code == 400

    resp = client.post(
        f"{API}/computers/{computer.id}/match",
        headers=auth_headers,
        json={"decision": "match", "endpoint_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404

    endpoint = _seed_endpoint(db)
    endpoint.status = "revoked"
    db.commit()
    resp = client.post(
        f"{API}/computers/{computer.id}/match",
        headers=auth_headers,
        json={"decision": "match", "endpoint_id": str(endpoint.id)},
    )
    assert resp.status_code == 400
    assert "revoked" in resp.json()["detail"].lower()


def test_reconciliation_queue_is_listed(client, auth_headers, db):
    created = _create(client, auth_headers)
    connection_id = uuid.UUID(created["id"])
    computer = _seed_computer(db, connection_id)
    db.add(
        DirectoryReconciliation(
            connection_id=connection_id,
            computer_id=computer.id,
            method="exact_fqdn",
            confidence="high",
            status="matched",
            candidates=[],
        )
    )
    db.commit()

    resp = client.get(
        f"{API}/reconciliations",
        headers=auth_headers,
        params={"connection_id": connection_id, "status": "matched"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["computer_name"] == "WS01"


def test_readonly_cannot_decide_matches(client, auth_headers, readonly_user, db):
    created = _create(client, auth_headers)
    connection_id = uuid.UUID(created["id"])
    computer = _seed_computer(db, connection_id)
    endpoint = _seed_endpoint(db)

    # Admin sets up, readonly must not be able to decide.
    headers = _login(client, readonly_user.email)
    resp = client.post(
        f"{API}/computers/{computer.id}/match",
        headers=headers,
        json={"decision": "match", "endpoint_id": str(endpoint.id)},
    )
    assert resp.status_code == 403
    assert "directory:write" in resp.json()["detail"]
