"""Rate limiter tests (Redis fixed-window)."""

from __future__ import annotations

import uuid

import pytest
from app.core.exceptions import AppError
from tests.conftest import requires_redis


@requires_redis
def test_rate_limiter_allows_up_to_limit():
    from app.core.rate_limit import RateLimiter

    bucket = f"test-{uuid.uuid4().hex[:8]}"
    limiter = RateLimiter(bucket, limit_per_minute=3)
    ident = "10.0.0.1"
    # First 3 requests pass
    for _ in range(3):
        limiter.check(ident)
    # 4th raises 429
    with pytest.raises(AppError) as exc:
        limiter.check(ident)
    assert exc.value.status == 429


@requires_redis
def test_rate_limiter_isolates_identifiers():
    from app.core.rate_limit import RateLimiter

    bucket = f"test-{uuid.uuid4().hex[:8]}"
    limiter = RateLimiter(bucket, limit_per_minute=1)
    limiter.check("ip-a")
    limiter.check("ip-b")  # different identifier, still allowed
    with pytest.raises(AppError):
        limiter.check("ip-a")


@requires_redis
def test_client_ip_prefers_forwarded_header():
    from app.core.rate_limit import client_ip
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"1.2.3.4, 10.0.0.1")],
        "client": ("9.9.9.9", 12345),
        "query_string": b"",
        "scheme": "http",
    }
    request = Request(scope)
    assert client_ip(request) == "1.2.3.4"
