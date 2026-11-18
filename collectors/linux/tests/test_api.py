"""API client tests: enrollment, auth headers, retry/backoff, error handling.

All HTTP goes through httpx.MockTransport — no network, no server.
"""

from __future__ import annotations

import httpx
import pytest

from eitop_collector.api import CollectorError, EitopClient

CRED = "eitop_ep_testcredential0000000000000000000"


def _client(handler, retries: int = 2, sleep=None) -> tuple[EitopClient, list]:
    calls: list[httpx.Request] = []

    def counting_handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    sleeps: list[float] = []
    client = EitopClient(
        "http://server.example:8080",
        max_retries=retries,
        transport=httpx.MockTransport(counting_handler),
        sleep=sleep or (lambda s: sleeps.append(s)),
    )
    client._test_sleeps = sleeps  # type: ignore[attr-defined]
    return client, calls


def test_enroll_returns_credential():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/agent/enroll"
        body = json_body(request)
        assert body["token"] == "tok-12345678901234567890"
        assert body["hostname"] == "web01"
        return httpx.Response(
            201, json={"endpoint_id": "ep-1", "credential": CRED}
        )

    client, calls = _client(handler)
    result = client.enroll(
        "tok-12345678901234567890",
        {"hostname": "web01", "os": "linux"},
    )
    assert result["credential"] == CRED
    assert len(calls) == 1
    # Enrollment token must not be sent as an auth header
    assert "authorization" not in calls[0].headers


def test_heartbeat_sends_bearer_credential():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"endpoint_id": "ep-1", "status": "active"})

    client, calls = _client(handler)
    client.heartbeat(CRED, "0.1.0")
    assert seen["auth"] == f"Bearer {CRED}"
    assert calls[0].url.path == "/api/v1/agent/heartbeat"


def test_inventory_submission_posts_payload(sample_inventory):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json_body(request)
        assert body["system"]["hostname"] == "web01"
        assert len(body["packages"]) == 2
        return httpx.Response(
            200,
            json={"endpoint_id": "ep-1", "accepted": True, "counts": {"packages": 2}},
        )

    client, _ = _client(handler)
    result = client.submit_inventory(CRED, sample_inventory)
    assert result["accepted"] is True


def test_client_error_not_retried():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={
                "title": "Not authenticated",
                "detail": "Missing or invalid endpoint credential.",
            },
        )

    client, calls = _client(handler, retries=3)
    with pytest.raises(CollectorError) as exc:
        client.heartbeat(CRED, "0.1.0")
    assert exc.value.status_code == 401
    assert "Not authenticated" in str(exc.value)
    assert len(calls) == 1  # 401 is never retried


def test_5xx_is_retried_then_succeeds():
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] < 3:
            return httpx.Response(503, json={"title": "Unavailable"})
        return httpx.Response(200, json={"endpoint_id": "ep-1", "status": "active"})

    client, calls = _client(handler, retries=3)
    client.heartbeat(CRED, "0.1.0")
    assert len(calls) == 3
    # Exponential backoff: 1s, then 2s
    assert client._test_sleeps == [1.0, 2.0]


def test_timeout_is_retried():
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            raise httpx.ConnectTimeout("slow")
        return httpx.Response(200, json={"endpoint_id": "ep-1", "status": "active"})

    client, calls = _client(handler, retries=2)
    client.heartbeat(CRED, "0.1.0")
    assert len(calls) == 2


def test_retries_exhausted_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"title": "Unavailable"})

    client, calls = _client(handler, retries=2)
    with pytest.raises(CollectorError) as exc:
        client.heartbeat(CRED, "0.1.0")
    # Final attempt reports the server's problem response
    assert "503" in str(exc.value)
    assert len(calls) == 3  # initial + 2 retries


def test_network_error_retries_then_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client, calls = _client(handler, retries=1)
    with pytest.raises(CollectorError):
        client.heartbeat(CRED, "0.1.0")
    assert len(calls) == 2


def test_problem_response_without_json_is_safe():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="gateway exploded")

    client, _ = _client(handler, retries=0)
    with pytest.raises(CollectorError) as exc:
        client.heartbeat(CRED, "0.1.0")
    assert "HTTP 500" in str(exc.value)


def test_rotate_credential_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/agent/rotate-credential"
        assert request.headers.get("authorization") == f"Bearer {CRED}"
        return httpx.Response(
            200, json={"endpoint_id": "ep-1", "credential": CRED + "rotated"}
        )

    client, _ = _client(handler)
    result = client.rotate_credential(CRED)
    assert result["credential"].endswith("rotated")


def test_enroll_response_missing_credential_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"endpoint_id": "ep-1"})

    client, _ = _client(handler)
    with pytest.raises(CollectorError):
        client.enroll("tok-12345678901234567890", {"hostname": "h"})


def json_body(request: httpx.Request) -> dict:
    import json

    return json.loads(request.content.decode("utf-8"))
