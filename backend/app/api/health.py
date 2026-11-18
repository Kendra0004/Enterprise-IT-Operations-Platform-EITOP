"""Health and readiness endpoints (unauthenticated by design)."""

from __future__ import annotations

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.core.database import SessionLocal
from app.core.redis_client import get_redis

router = APIRouter(tags=["health"])


@router.get("/health", status_code=status.HTTP_200_OK)
def health() -> dict:
    """Liveness: process is up. No dependencies checked."""
    return {"status": "ok"}


@router.get("/health/ready", status_code=status.HTTP_200_OK)
def readiness(response: Response) -> dict:
    """Readiness: database and Redis both reachable."""
    checks: dict[str, str] = {}
    ready = True

    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"
        ready = False

    try:
        get_redis().ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unavailable"
        ready = False

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready else "not_ready", "checks": checks}


__all__ = ["router"]
