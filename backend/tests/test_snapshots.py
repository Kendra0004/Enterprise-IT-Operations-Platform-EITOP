"""Inventory snapshot tests (Phase 2.6): creation, deduplication,
pagination, date filtering, comparison, cross-endpoint isolation,
software/network history, schema versioning, partial inventory,
migration columns and query bounds."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

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


def _agent(credential: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {credential}"}


def _inventory(
    hostname: str,
    packages: list | None = None,
    facts: dict | None = None,
    hardware: dict | None = None,
) -> dict:
    return {
        "system": {
            "hostname": hostname,
            "fqdn": f"{hostname}.example.com",
            "os": "linux",
            "distribution": "ubuntu",
            "distribution_version": "24.04",
            "os_arch": "x86_64",
            "kernel": "6.8.0-45-generic",
            "uptime_seconds": 100,
        },
        "hardware": hardware
        if hardware is not None
        else {
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
            {
                "mount": "/",
                "fstype": "ext4",
                "total_bytes": 100 * 1024**3,
                "used_bytes": 40 * 1024**3,
            }
        ],
        "packages": packages
        if packages is not None
        else [
            {"name": "curl", "version": "8.5.0", "package_manager": "dpkg"},
            {"name": "openssl", "version": "3.0.13", "package_manager": "dpkg"},
        ],
        "facts": facts if facts is not None else {"collector.version": "0.2.0"},
    }


def _submit(client, credential: str, payload: dict) -> dict:
    resp = client.post(
        "/api/v1/agent/inventory", headers=_agent(credential), json=payload
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _snapshots(client, headers, endpoint_id: str, **params) -> dict:
    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots", headers=headers, params=params
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- Creation & deduplication ----------------------------------------------


def test_snapshot_created_on_valid_inventory(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "snap-host")
    counts = _submit(client, cred, _inventory("snap-host"))
    assert counts["counts"]["snapshots"] == 1

    page = _snapshots(client, auth_headers, endpoint_id)
    assert page["total"] == 1
    row = page["items"][0]
    assert row["endpoint_id"] == endpoint_id
    assert row["schema_version"] == 1
    assert row["package_count"] == 2
    assert row["has_hardware"] is True
    assert row["has_network"] is True
    assert row["collected_at"] is not None
    assert row["received_at"] is not None

    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots/{row['id']}",
        headers=auth_headers,
    ).json()
    assert detail["system"]["hostname"] == "snap-host"
    assert {p["name"] for p in detail["packages"]} == {"curl", "openssl"}
    assert detail["facts"]["collector.version"] == "0.2.0"


def test_identical_resubmission_creates_no_duplicate(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "dup-host")
    payload = _inventory("dup-host")
    _submit(client, cred, payload)
    counts = _submit(client, cred, payload)  # e.g. a network retry
    assert counts["counts"]["snapshots"] == 0
    _submit(client, cred, payload)
    assert _snapshots(client, auth_headers, endpoint_id)["total"] == 1


def test_changed_submission_creates_new_snapshot(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "hist-host")
    _submit(client, cred, _inventory("hist-host", facts={"run": "1"}))
    _submit(client, cred, _inventory("hist-host", facts={"run": "2"}))
    page = _snapshots(client, auth_headers, endpoint_id)
    assert page["total"] == 2
    # newest first
    assert page["items"][0]["received_at"] >= page["items"][1]["received_at"]


def test_list_rows_include_reported_ips(client, auth_headers):
    """Inventory table data: list rows carry the last reported IPs."""
    endpoint_id, cred = _enroll(client, auth_headers, "ips-host")
    _submit(client, cred, _inventory("ips-host"))
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"q": "ips-host"}
    )
    row = next(i for i in resp.json()["items"] if i["id"] == endpoint_id)
    assert row["ip_addresses"] == ["192.0.2.10"]

    # an endpoint that never reported inventory has an empty list, not null
    fresh_id, _ = _enroll(client, auth_headers, "ips-none")
    resp = client.get(
        "/api/v1/endpoints", headers=auth_headers, params={"q": "ips-none"}
    )
    row = next(i for i in resp.json()["items"] if i["id"] == fresh_id)
    assert row["ip_addresses"] == []


def test_last_inventory_at_recorded_on_endpoint(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "lastinv-host")
    detail_before = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert detail_before["last_inventory_at"] is None
    _submit(client, cred, _inventory("lastinv-host"))
    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}", headers=auth_headers
    ).json()
    assert detail["last_inventory_at"] is not None


# --- Pagination & date filtering -------------------------------------------


def test_snapshot_pagination(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "page-host")
    for i in range(5):
        _submit(client, cred, _inventory("page-host", facts={"n": str(i)}))

    page1 = _snapshots(client, auth_headers, endpoint_id, page=1, page_size=2)
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    page3 = _snapshots(client, auth_headers, endpoint_id, page=3, page_size=2)
    assert len(page3["items"]) == 1
    ids = {s["id"] for s in page1["items"]} | {s["id"] for s in page3["items"]}
    assert len(ids) == 3  # pages do not overlap

    # page_size cap enforced
    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots",
        headers=auth_headers,
        params={"page_size": 500},
    )
    assert resp.status_code == 422


def test_snapshot_date_filter(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "date-host")
    _submit(client, cred, _inventory("date-host", facts={"n": "1"}))
    future = (datetime.now(UTC) + timedelta(days=2)).isoformat()
    past = (datetime.now(UTC) - timedelta(days=2)).isoformat()

    page = _snapshots(
        client, auth_headers, endpoint_id, **{"from": past, "to": future}
    )
    assert page["total"] == 1
    page = _snapshots(
        client,
        auth_headers,
        endpoint_id,
        **{
            "from": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "to": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
        },
    )
    assert page["total"] == 0


def test_history_query_bounds(client, auth_headers):
    endpoint_id, _cred = _enroll(client, auth_headers, "bounds-host")
    too_wide_from = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots",
        headers=auth_headers,
        params={"from": too_wide_from},
    )
    assert resp.status_code == 400
    # a 'to' without a 'from' is rejected (would be an unbounded scan)
    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots",
        headers=auth_headers,
        params={"to": datetime.now(UTC).isoformat()},
    )
    assert resp.status_code == 400
    # inverted range rejected
    now = datetime.now(UTC)
    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots",
        headers=auth_headers,
        params={
            "from": now.isoformat(),
            "to": (now - timedelta(days=1)).isoformat(),
        },
    )
    assert resp.status_code == 400


# --- Comparison -------------------------------------------------------------


def test_snapshot_comparison_packages_and_hardware(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "cmp-host")
    _submit(
        client,
        cred,
        _inventory(
            "cmp-host",
            packages=[
                {"name": "curl", "version": "8.5.0", "package_manager": "dpkg"},
                {"name": "openssl", "version": "3.0.13", "package_manager": "dpkg"},
                {"name": "legacy", "version": "1.0", "package_manager": "dpkg"},
            ],
            hardware={"cpu_cores": 4, "memory_bytes": 8 * 1024**3},
            facts={"run": "1"},
        ),
    )
    _submit(
        client,
        cred,
        _inventory(
            "cmp-host",
            packages=[
                {"name": "curl", "version": "8.6.0", "package_manager": "dpkg"},
                {"name": "openssl", "version": "3.0.13", "package_manager": "dpkg"},
                {"name": "newapp", "version": "2.0", "package_manager": "dpkg"},
            ],
            hardware={"cpu_cores": 8, "memory_bytes": 8 * 1024**3},
            facts={"run": "2"},
        ),
    )
    page = _snapshots(client, auth_headers, endpoint_id)
    assert page["total"] == 2
    base_id = page["items"][1]["id"]  # older
    target_id = page["items"][0]["id"]  # newer

    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots/{target_id}",
        headers=auth_headers,
        params={"compare_to": base_id},
    ).json()
    changes = detail["changes"]
    assert changes is not None
    assert changes["base_snapshot_id"] == base_id
    assert changes["target_snapshot_id"] == target_id

    added = {p["name"] for p in changes["added_packages"]}
    removed = {p["name"] for p in changes["removed_packages"]}
    changed = {p["name"]: p for p in changes["changed_packages"]}
    assert added == {"newapp"}
    assert removed == {"legacy"}
    assert "curl" in changed
    assert changed["curl"]["previous_version"] == "8.5.0"
    assert changed["curl"]["version"] == "8.6.0"

    hw_fields = {c["field"]: c for c in changes["hardware_changes"]}
    assert hw_fields["cpu_cores"]["before"] == 4
    assert hw_fields["cpu_cores"]["after"] == 8
    assert "memory_bytes" not in hw_fields  # unchanged


def test_comparison_with_partial_inventory(client, auth_headers):
    """Missing hardware on either side → no hardware diff, packages still
    compared (partial submissions handled safely)."""
    endpoint_id, cred = _enroll(client, auth_headers, "partial-host")
    _submit(client, cred, _inventory("partial-host", hardware=None, facts={"r": "1"}))
    _submit(
        client,
        cred,
        _inventory(
            "partial-host",
            packages=[{"name": "only", "version": "1", "package_manager": "dpkg"}],
            facts={"r": "2"},
        ),
    )
    page = _snapshots(client, auth_headers, endpoint_id)
    base_id, target_id = page["items"][1]["id"], page["items"][0]["id"]
    detail = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots/{target_id}",
        headers=auth_headers,
        params={"compare_to": base_id},
    ).json()
    assert detail["changes"]["hardware_changes"] == []
    assert {p["name"] for p in detail["changes"]["added_packages"]} == {"only"}


def test_comparison_requires_same_endpoint(client, auth_headers):
    """A snapshot of endpoint B cannot be used as compare_to for endpoint A
    (it simply does not exist in A's scope → 404)."""
    a_id, a_cred = _enroll(client, auth_headers, "iso-a")
    b_id, b_cred = _enroll(client, auth_headers, "iso-b")
    _submit(client, a_cred, _inventory("iso-a", facts={"n": "1"}))
    _submit(client, b_cred, _inventory("iso-b", facts={"n": "1"}))
    a_snap = _snapshots(client, auth_headers, a_id)["items"][0]["id"]
    b_snap = _snapshots(client, auth_headers, b_id)["items"][0]["id"]

    resp = client.get(
        f"/api/v1/endpoints/{a_id}/snapshots/{a_snap}",
        headers=auth_headers,
        params={"compare_to": b_snap},
    )
    assert resp.status_code == 404


# --- Isolation --------------------------------------------------------------


def test_cross_endpoint_snapshot_isolation(client, auth_headers):
    a_id, a_cred = _enroll(client, auth_headers, "cross-a")
    b_id, _b_cred = _enroll(client, auth_headers, "cross-b")
    _submit(client, a_cred, _inventory("cross-a"))
    a_snap = _snapshots(client, auth_headers, a_id)["items"][0]["id"]

    # endpoint B's scope cannot reach A's snapshot
    resp = client.get(
        f"/api/v1/endpoints/{b_id}/snapshots/{a_snap}", headers=auth_headers
    )
    assert resp.status_code == 404
    # listing under B never contains A's rows
    assert _snapshots(client, auth_headers, b_id)["total"] == 0
    # software/network history scoped to B excludes A's data
    resp = client.get(
        f"/api/v1/endpoints/{b_id}/software",
        headers=auth_headers,
        params={"view": "history"},
    )
    assert resp.json()["total"] == 0


def test_agents_cannot_read_history(client, auth_headers):
    """Agent credentials are rejected on user routes — agents can never
    request historical data."""
    endpoint_id, cred = _enroll(client, auth_headers, "agentread-host")
    _submit(client, cred, _inventory("agentread-host"))
    for path in (
        f"/api/v1/endpoints/{endpoint_id}/snapshots",
        f"/api/v1/endpoints/{endpoint_id}/software",
        f"/api/v1/endpoints/{endpoint_id}/network",
        f"/api/v1/endpoints/{endpoint_id}/health",
    ):
        resp = client.get(path, headers=_agent(cred))
        assert resp.status_code == 401, path


def test_snapshot_404_for_unknown_ids(client, auth_headers):
    endpoint_id, _cred = _enroll(client, auth_headers, "ghost-host")
    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/snapshots/{uuid.uuid4()}",
        headers=auth_headers,
    )
    assert resp.status_code == 404
    resp = client.get(
        f"/api/v1/endpoints/{uuid.uuid4()}/snapshots", headers=auth_headers
    )
    assert resp.status_code == 404


# --- Software & network history --------------------------------------------


def test_software_views_current_and_history(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "sw-host")
    _submit(
        client,
        cred,
        _inventory(
            "sw-host",
            packages=[{"name": "alpha", "version": "1.0", "package_manager": "dpkg"}],
            facts={"n": "1"},
        ),
    )
    _submit(
        client,
        cred,
        _inventory(
            "sw-host",
            packages=[
                {"name": "alpha", "version": "2.0", "package_manager": "dpkg"},
                {"name": "beta", "version": "1.0", "package_manager": "dpkg"},
            ],
            facts={"n": "2"},
        ),
    )

    # current view: live table reflects the latest submission only
    cur = client.get(
        f"/api/v1/endpoints/{endpoint_id}/software",
        headers=auth_headers,
        params={"view": "current"},
    ).json()
    assert cur["total"] == 2
    versions = {i["name"]: i["version"] for i in cur["items"]}
    assert versions == {"alpha": "2.0", "beta": "1.0"}

    # history view: alpha@1.0 from snapshot 1 and alpha@2.0 from snapshot 2
    hist = client.get(
        f"/api/v1/endpoints/{endpoint_id}/software",
        headers=auth_headers,
        params={"view": "history", "name": "alpha"},
    ).json()
    assert hist["total"] == 2
    assert {i["version"] for i in hist["items"]} == {"1.0", "2.0"}
    assert all("snapshot_id" in i for i in hist["items"])

    # name filter on current view
    cur_alpha = client.get(
        f"/api/v1/endpoints/{endpoint_id}/software",
        headers=auth_headers,
        params={"view": "current", "name": "beta"},
    ).json()
    assert cur_alpha["total"] == 1


def test_network_history(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "net-host")
    _submit(client, cred, _inventory("net-host", facts={"n": "1"}))
    _submit(client, cred, _inventory("net-host", facts={"n": "2"}))

    resp = client.get(
        f"/api/v1/endpoints/{endpoint_id}/network", headers=auth_headers
    )
    assert resp.status_code == 200
    page = resp.json()
    assert page["total"] == 2
    item = page["items"][0]
    assert item["network"]["ip_addresses"] == ["192.0.2.10"]
    assert item["collected_at"] is not None

    # snapshot without a network section is excluded from network history
    bare = {
        "system": {"hostname": "net-host", "os": "linux"},
        "facts": {"n": "3"},
    }
    _submit(client, cred, bare)
    page = client.get(
        f"/api/v1/endpoints/{endpoint_id}/network", headers=auth_headers
    ).json()
    assert page["total"] == 2  # bare submission has network=None


# --- Schema versioning & migration -----------------------------------------


def test_schema_version_recorded(client, auth_headers):
    endpoint_id, cred = _enroll(client, auth_headers, "ver-host")
    payload = _inventory("ver-host")
    payload["schema_version"] = 2
    payload["collected_at"] = datetime.now(UTC).isoformat()
    _submit(client, cred, payload)
    row = _snapshots(client, auth_headers, endpoint_id)["items"][0]
    assert row["schema_version"] == 2
    # collected_at from the agent is honored (not just server receipt)
    assert (
        datetime.fromisoformat(row["collected_at"])
        <= datetime.now(UTC) + timedelta(seconds=5)
    )


def test_invalid_schema_version_rejected(client, auth_headers):
    _endpoint_id, cred = _enroll(client, auth_headers, "ver-bad")
    payload = _inventory("ver-bad")
    payload["schema_version"] = 0
    resp = client.post(
        "/api/v1/agent/inventory", headers=_agent(cred), json=payload
    )
    assert resp.status_code == 422


def test_migration_creates_health_and_snapshot_columns(client, db):
    """Database migration 0004 artifacts exist after upgrade-to-head."""
    from sqlalchemy import inspect

    insp = inspect(db.bind)
    assert "endpoint_snapshots" in insp.get_table_names()
    assert "endpoint_snapshot_software" in insp.get_table_names()

    endpoint_cols = {c["name"] for c in insp.get_columns("endpoints")}
    assert "last_inventory_at" in endpoint_cols

    snap_cols = {c["name"] for c in insp.get_columns("endpoint_snapshots")}
    assert {
        "id",
        "endpoint_id",
        "collected_at",
        "received_at",
        "agent_version",
        "schema_version",
        "content_hash",
        "system",
        "hardware",
        "network",
        "filesystems",
        "facts",
    } <= snap_cols

    uniques = {
        tuple(u["column_names"]) for u in insp.get_unique_constraints("endpoint_snapshots")
    }
    assert ("endpoint_id", "content_hash") in uniques
    indexes = {tuple(i["column_names"]) for i in insp.get_indexes("endpoint_snapshots")}
    assert ("endpoint_id", "received_at") in indexes


def test_retention_defaults_to_keep_forever():
    """No retention configured → the prune task deletes nothing."""
    from app.core.config import get_settings
    from app.tasks.jobs import prune_endpoint_snapshots

    assert get_settings().snapshot_retention_days is None
    assert prune_endpoint_snapshots() == 0
