"""Runner tests: enrollment flow, rotation, loop behavior — no real server."""

from __future__ import annotations

import httpx
import pytest

from eitop_collector.api import EitopClient
from eitop_collector.config import CollectorConfig
from eitop_collector.credentials import load_credentials, save_credentials
from eitop_collector.runner import Runner

CRED = "eitop_ep_initial00000000000000000000000000"
NEW_CRED = "eitop_ep_rotated000000000000000000000000"


@pytest.fixture()
def config(tmp_path) -> CollectorConfig:
    return CollectorConfig(
        server_url="http://server.example:8080",
        credential_file=str(tmp_path / "creds" / "credentials.json"),
        max_retries=1,
        interval_seconds=10,
        heartbeat_interval_seconds=10,
    )


def _client(handler, sleeps: list | None = None) -> EitopClient:
    return EitopClient(
        "http://server.example:8080",
        max_retries=1,
        transport=httpx.MockTransport(handler),
        sleep=(sleeps if sleeps is not None else []),
    )


def test_enroll_persists_credential(config, monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen["body"] = json.loads(request.content)
        return httpx.Response(
            201, json={"endpoint_id": "ep-9", "credential": CRED}
        )

    monkeypatch.setattr(
        "eitop_collector.runner.enroll_payload",
        lambda token: {"token": token, "hostname": "web01", "os": "linux"},
    )
    runner = Runner(config, _client(handler))
    endpoint_id, cred = runner.enroll("tok-12345678901234567890")

    assert endpoint_id == "ep-9"
    assert cred == CRED
    stored = load_credentials(config.credential_file)
    assert stored.endpoint_id == "ep-9"
    assert stored.credential == CRED
    assert seen["body"]["token"] == "tok-12345678901234567890"
    assert seen["body"]["hostname"] == "web01"


def test_rotate_replaces_stored_credential(config):
    save_credentials(config.credential_file, "ep-9", CRED)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {CRED}"
        return httpx.Response(
            200, json={"endpoint_id": "ep-9", "credential": NEW_CRED}
        )

    runner = Runner(config, _client(handler))
    got = runner.rotate()
    assert got == NEW_CRED
    assert load_credentials(config.credential_file).credential == NEW_CRED


def test_heartbeat_uses_stored_credential(config):
    save_credentials(config.credential_file, "ep-9", CRED)
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"endpoint_id": "ep-9", "status": "active"})

    runner = Runner(config, _client(handler))
    runner.heartbeat_once()
    assert seen["auth"] == f"Bearer {CRED}"
    assert seen["path"] == "/api/v1/agent/heartbeat"


def test_inventory_once_submits_and_returns_counts(config):
    save_credentials(config.credential_file, "ep-9", CRED)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/agent/inventory"
        return httpx.Response(
            200,
            json={"endpoint_id": "ep-9", "accepted": True, "counts": {"packages": 0}},
        )

    runner = Runner(config, _client(handler))
    result = runner.inventory_once()
    assert result["accepted"] is True


def test_run_forever_stops_on_signal(config, monkeypatch):
    """SIGTERM-equivalent stops the loop; no external commands executed."""
    save_credentials(config.credential_file, "ep-9", CRED)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            200,
            json={"endpoint_id": "ep-9", "status": "active", "accepted": True,
                  "counts": {}},
        )

    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        # Stop after the first idle slice — simulates SIGTERM arrival.
        sleeps.append(seconds)
        runner.request_stop()

    runner = Runner(config, _client(handler, sleeps=sleeps), sleep=fake_sleep)
    runner.run_forever()
    assert calls["n"] >= 2  # heartbeat + inventory happened
    assert sleeps  # loop slept and exited cleanly


def test_run_forever_backs_off_on_failure(config):
    save_credentials(config.credential_file, "ep-9", CRED)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Not authenticated"})

    sleeps: list[float] = []
    runner = Runner(
        config,
        _client(handler, sleeps=sleeps),
        sleep=lambda s: sleeps.append(s) or runner.request_stop(),
    )
    runner.run_forever()
    # 401 is not retried by the HTTP layer; the loop backs off then stops.
    assert sleeps and sleeps[0] >= config.heartbeat_interval_seconds


def test_run_forever_gives_up_when_credential_missing(config, monkeypatch):
    """No credential file → clean exit, no credential invented."""

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not talk to server without credentials")

    runner = Runner(config, _client(handler))
    runner.run_forever()  # returns without raising


def test_server_supplied_data_never_executed(config, monkeypatch):
    """Guard: runner only serializes payloads; nothing interprets them."""
    import eitop_collector.runner as mod

    executed: list = []

    def guard(*a, **k):  # pragma: no cover
        executed.append((a, k))

    monkeypatch.setattr(mod, "collect_all", guard)
    monkeypatch.setattr(mod, "save_credentials", guard)

    def handler(request: httpx.Request) -> httpx.Response:
        # Server response containing a would-be command — must be inert JSON.
        return httpx.Response(
            200,
            json={
                "endpoint_id": "ep-9",
                "status": "active",
                "command": "rm -rf /",
            },
        )

    save_credentials(config.credential_file, "ep-9", CRED)
    runner = Runner(config, _client(handler))
    runner.heartbeat_once()  # response body discarded; no execution path
    assert not executed
