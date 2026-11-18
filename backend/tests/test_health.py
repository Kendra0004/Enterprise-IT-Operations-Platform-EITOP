"""Application startup and health endpoint tests."""

from __future__ import annotations

from tests.conftest import requires_postgres, requires_redis


def test_app_starts_and_has_openapi(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()
    assert spec["info"]["title"] == "EITOP"
    assert "/api/v1/auth/login" in spec["paths"]
    assert "/health" in spec["paths"]


def test_liveness_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@requires_postgres
@requires_redis
def test_readiness_all_up(client):
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["redis"] == "ok"


def test_validation_error_uses_problem_json(client):
    resp = client.post("/api/v1/auth/login", json={"email": "not-an-email"})
    assert resp.status_code == 422
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["title"] == "Validation error"
    assert any(e["field"] == "email" for e in body["errors"])


def test_unknown_route_is_problem_json(client):
    resp = client.get("/api/v1/nope")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert resp.json()["status"] == 404
