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
def test_client_ip_uses_nearest_proxy_hop():
    """X-Forwarded-For: the RIGHTMOST hop wins (Phase 6 audit A5).

    Our proxies overwrite XFF so legitimate traffic is single-hop; in an
    append scenario (or a client forging a leftmost value while talking
    to the backend directly) the nearest-proxy hop — added by nginx — is
    the trustworthy one.
    """
    from app.core.rate_limit import client_ip
    from starlette.requests import Request

    def make(headers, client=("9.9.9.9", 12345)):
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": headers,
                "client": client,
                "query_string": b"",
                "scheme": "http",
            }
        )

    # Multi-hop: attacker-controlled leftmost value must NOT become the
    # rate-limit key / audit IP.
    request = make([(b"x-forwarded-for", b"1.2.3.4, 10.0.0.1")])
    assert client_ip(request) == "10.0.0.1"
    # Single hop (our proxies overwrite with $remote_addr).
    request = make([(b"x-forwarded-for", b"1.2.3.4")])
    assert client_ip(request) == "1.2.3.4"
    # No header: direct peer address.
    request = make([])
    assert client_ip(request) == "9.9.9.9"
