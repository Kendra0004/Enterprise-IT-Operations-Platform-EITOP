"""Redis-backed fixed-window rate limiting for authentication endpoints.

Fails closed: if Redis is unreachable the request is rejected with 503 so an
outage cannot silently disable brute-force protection.
"""

from __future__ import annotations

import hashlib
import time
from typing import cast

from fastapi import Request, status

from app.core.config import get_settings
from app.core.exceptions import AppError, problem
from app.core.redis_client import get_redis


class RateLimiter:
    """Fixed-window counter keyed by ``bucket:identifier``."""

    def __init__(self, bucket: str, limit_per_minute: int) -> None:
        self.bucket = bucket
        self.limit = limit_per_minute
        self.window_seconds = 60

    def check(self, identifier: str) -> None:
        """Raise AppError(429) when the identifier exceeded the limit."""
        now = int(time.time())
        window = now // self.window_seconds
        key = f"ratelimit:{self.bucket}:{identifier}:{window}"
        try:
            redis = get_redis()
            # redis-py stubs type incr() as possibly async; this client is sync.
            count = cast(int, redis.incr(key))
            if count == 1:
                redis.expire(key, self.window_seconds + 1)
        except Exception as exc:  # Redis down → fail closed
            raise AppError(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Rate limiter unavailable",
                "Rate limiting backend is unreachable.",
            ) from exc
        if count > self.limit:
            raise AppError(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many requests",
                f"Limit of {self.limit} requests per minute exceeded.",
            )


def client_ip(request: Request) -> str:
    """Resolve the real client IP for throttling and audit records.

    Both production proxies OVERWRITE ``X-Forwarded-For`` with
    ``$remote_addr`` (never append), so legitimate traffic carries exactly
    one hop. When a multi-hop value appears it can only have come from a
    client talking to the backend directly or from a future appending
    proxy; the RIGHTMOST hop is the one added by the nearest proxy and is
    therefore the trustworthy one (Phase 6 audit A5 — the previous
    leftmost choice let a direct client pick its own rate-limit bucket
    and audit IP by sending a forged header).
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def login_rate_limit(request: Request) -> None:
    settings = get_settings()
    RateLimiter("login", settings.rate_limit_login_per_minute).check(
        client_ip(request)
    )


def login_email_rate_limit(email: str) -> None:
    """Per-account login throttle (Phase 6 audit A6).

    The IP bucket cannot stop credential stuffing distributed across many
    source IPs; this second bucket caps attempts against one account no
    matter where they come from. The key is a SHA-256 digest so raw
    email addresses never appear in Redis keys.
    """
    settings = get_settings()
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    RateLimiter(
        "login_email", settings.rate_limit_login_per_minute
    ).check(digest)


def refresh_rate_limit(request: Request) -> None:
    settings = get_settings()
    RateLimiter("refresh", settings.rate_limit_refresh_per_minute).check(
        client_ip(request)
    )


def enroll_rate_limit(request: Request) -> None:
    """Throttle agent enrollment attempts (token guessing defense)."""
    settings = get_settings()
    RateLimiter("enroll", settings.rate_limit_enroll_per_minute).check(
        client_ip(request)
    )


__all__ = [
    "RateLimiter",
    "client_ip",
    "enroll_rate_limit",
    "login_email_rate_limit",
    "login_rate_limit",
    "problem",
    "refresh_rate_limit",
]
