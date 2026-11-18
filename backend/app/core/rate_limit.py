"""Redis-backed fixed-window rate limiting for authentication endpoints.

Fails closed: if Redis is unreachable the request is rejected with 503 so an
outage cannot silently disable brute-force protection.
"""

from __future__ import annotations

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
    """Best-effort client IP (honors X-Forwarded-For when behind proxy)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def login_rate_limit(request: Request) -> None:
    settings = get_settings()
    RateLimiter("login", settings.rate_limit_login_per_minute).check(
        client_ip(request)
    )


def refresh_rate_limit(request: Request) -> None:
    settings = get_settings()
    RateLimiter("refresh", settings.rate_limit_refresh_per_minute).check(
        client_ip(request)
    )


__all__ = [
    "RateLimiter",
    "client_ip",
    "login_rate_limit",
    "problem",
    "refresh_rate_limit",
]
