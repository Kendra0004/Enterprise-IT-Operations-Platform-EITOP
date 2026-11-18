"""Administrator endpoint API tests (Phase 2.1/2.2): listing, pagination,
filtering, sorting allowlist, groups, RBAC and response hygiene."""

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


# --- Listing / filtering / sorting ------------------------------------------


def test_list_endpoints_requires_auth(client):
    resp = client.get("/api/v1/endpoints")
    assert resp.status_code == 401


def test_list_endpoints_pagination(client, auth_headers):
    prefix = f"page-{uuid.uuid4().hex[:6]}"
    for i in range(3):
        _enroll(client, auth_headers, f"{prefix}-{i}")

    first = client.get(
        "/api/v1/endpoints",
        headers=auth_headers,
        params={"page": 1, "page_size": 2, "q": prefix},
    )
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["total"] == 3
    assert len(body["items"]) == 2

    second = client.get(
        "/api/v1/endpoints",
        headers=auth_headers,
        params={"page": 2, "page_size": 2, "q": prefix},
    )
    assert len(second.json()["items"]) == 1


def test_list_endpoints_status_filter(client, auth_headers):
    active_id = _enroll(client, auth_headers, f"flt-a-{uuid.uuid4().hex[:6]}")
    revoked_id = _enroll(client, auth_headers, f"flt-r-{uuid.uuid4().hex[:6]}")
    client.post(f"/api/v1/endpoints/{revoked_id}/revoke", headers=auth_headers)

    active = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"status": "active"}
    )
    active_ids = {i["id"] for i in active.json()["items"]}
    assert active_id in active_ids
    assert revoked_id not in active_ids

    revoked = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"status": "revoked"}
    )
    assert revoked_id in {i["id"] for i in revoked.json()["items"]}


def test_list_endpoints_group_filter(client, auth_headers):
    name = f"grp-{uuid.uuid4().hex[:6]}"
    group = client.post(
        "/api/v1/endpoints/groups",
        headers=auth_headers,
        json={"name": name, "description": "d"},
    )
    group_id = group.json()["id"]
    endpoint_id = _enroll(client, auth_headers, f"g-{uuid.uuid4().hex[:6]}")

    # Assign via enrollment token instead of a (not-yet-built) membership API
    token_resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=auth_headers,
        json={"expires_in_minutes": 60, "group_id": group_id},
    )
    grouped = client.post(
        "/api/v1/agent/enroll",
        json={"token": token_resp.json()["token"], "hostname": "grouped-flt"},
    )
    grouped_id = grouped.json()["endpoint_id"]

    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"group_id": group_id}
    )
    ids = {i["id"] for i in resp.json()["items"]}
    assert grouped_id in ids
    assert endpoint_id not in ids


def test_sort_allowlist_and_order(client, auth_headers):
    prefix = f"sort-{uuid.uuid4().hex[:6]}"
    for i in range(3):
        _enroll(client, auth_headers, f"{prefix}-{i}")

    resp = client.get(
        "/api/v1/endpoints",
        headers=auth_headers,
        params={"q": prefix, "sort": "hostname", "order": "asc"},
    )
    hostnames = [i["hostname"] for i in resp.json()["items"]]
    assert hostnames == sorted(hostnames)

    # Arbitrary column names are rejected (SQL injection / error surfacing)
    bad = client.get(
        "/api/v1/endpoints",
        headers=auth_headers,
        params={"sort": "token_hash; DROP TABLE users"},
    )
    assert bad.status_code == 400
    assert bad.json()["title"] == "Invalid sort field"

    bad_order = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"order": "sideways"}
    )
    assert bad_order.status_code == 422


def test_invalid_status_filter_rejected(client, auth_headers):
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"status": "bogus"}
    )
    assert resp.status_code == 422


# --- Detail -----------------------------------------------------------------


def test_endpoint_detail_shape_has_no_credential_fields(client, auth_headers):
    endpoint_id = _enroll(client, auth_headers, f"det-{uuid.uuid4().hex[:6]}")
    resp = client.get(f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    for forbidden in ("credential", "token", "token_hash", "secret"):
        assert forbidden not in body
    assert body["status"] == "active"
    assert body["id"] == endpoint_id


def test_endpoint_detail_404(client, auth_headers):
    resp = client.get(f"/api/v1/endpoints/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["title"] == "Endpoint not found"


def test_unknown_path_parameter_rejected(client, auth_headers):
    resp = client.get("/api/v1/endpoints/not-a-uuid", headers=auth_headers)
    assert resp.status_code == 422


# --- Groups -----------------------------------------------------------------


def test_group_create_list_and_duplicate(client, auth_headers):
    name = f"new-{uuid.uuid4().hex[:6]}"
    created = client.post(
        "/api/v1/endpoints/groups",
        headers=auth_headers,
        json={"name": name, "description": "test group"},
    )
    assert created.status_code == 201, created.text
    assert created.json()["endpoint_count"] == 0

    duplicate = client.post(
        "/api/v1/endpoints/groups",
        headers=auth_headers,
        json={"name": name},
    )
    assert duplicate.status_code == 409

    listed = client.get("/api/v1/endpoints/groups", headers=auth_headers)
    assert listed.status_code == 200
    names = [g["name"] for g in listed.json()]
    assert name in names


def test_group_requires_valid_name(client, auth_headers):
    resp = client.post(
        "/api/v1/endpoints/groups", headers=auth_headers, json={"name": ""}
    )
    assert resp.status_code == 422


# --- RBAC -------------------------------------------------------------------


def test_readonly_can_read_endpoints_but_not_mutate(client, readonly_user):
    headers = _login(client, readonly_user.email)

    assert client.get("/api/v1/endpoints", headers=headers).status_code == 200
    assert (
        client.get("/api/v1/endpoints/groups", headers=headers).status_code == 200
    )

    endpoint_id = str(uuid.uuid4())
    assert (
        client.post(
            f"/api/v1/endpoints/{endpoint_id}/revoke", headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/endpoints/{endpoint_id}/rotate-credential", headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/endpoints/groups",
            headers=headers,
            json={"name": "x"},
        ).status_code
        == 403
    )


def test_operator_can_manage_endpoints(client, operator_user):
    headers = _login(client, operator_user.email)
    endpoint_id = _enroll(client, headers, f"op-{uuid.uuid4().hex[:6]}")
    assert (
        client.get(f"/api/v1/endpoints/{endpoint_id}", headers=headers).status_code
        == 200
    )
    rotate = client.post(
        f"/api/v1/endpoints/{endpoint_id}/rotate-credential", headers=headers
    )
    assert rotate.status_code == 200
    revoke = client.post(f"/api/v1/endpoints/{endpoint_id}/revoke", headers=headers)
    assert revoke.status_code == 200


def test_anonymous_cannot_mutate(client):
    endpoint_id = str(uuid.uuid4())
    assert (
        client.post(f"/api/v1/endpoints/{endpoint_id}/revoke").status_code == 401
    )
    assert client.post("/api/v1/endpoints/groups", json={"name": "x"}).status_code == 401


# --- Token listing ----------------------------------------------------------


def test_token_listing_never_exposes_values(client, auth_headers):
    created = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        headers=auth_headers,
        json={"expires_in_minutes": 60},
    ).json()

    listed = client.get("/api/v1/endpoints/enrollment-tokens", headers=auth_headers)
    assert listed.status_code == 200
    rows = listed.json()
    assert any(r["id"] == created["id"] for r in rows)
    assert created["token"] not in listed.text

    # After use it disappears from the default listing
    client.post(
        "/api/v1/agent/enroll",
        json={"token": created["token"], "hostname": "used-in-list"},
    )
    listed2 = client.get(
        "/api/v1/endpoints/enrollment-tokens", headers=auth_headers
    )
    assert created["id"] not in {r["id"] for r in listed2.json()}

    with_used = client.get(
        "/api/v1/endpoints/enrollment-tokens",
        headers=auth_headers,
        params={"include_used": True},
    )
    used_row = next(r for r in with_used.json() if r["id"] == created["id"])
    assert used_row["used_at"] is not None
    assert "token" not in used_row
