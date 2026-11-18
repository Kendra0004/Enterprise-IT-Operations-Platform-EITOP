"""Redis client factory.

Used for rate limiting, caching and (later) Celery broker connectivity.
Connections are lazy — creating the client does not open a socket.
"""

from __future__ import annotations

import redis as redis_lib

from app.core.config import get_settings

_pool: redis_lib.Redis | None = None


def get_redis() -> redis_lib.Redis:
    """Return a shared Redis client (decode responses to str)."""
    global _pool
    if _pool is None:
        _pool = redis_lib.Redis.from_url(
            get_settings().redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
    return _pool


def reset_redis() -> None:
    """Drop the cached client (used by tests when REDIS_URL changes)."""
    global _pool
    if _pool is not None:
        _pool.close()
    _pool = None
