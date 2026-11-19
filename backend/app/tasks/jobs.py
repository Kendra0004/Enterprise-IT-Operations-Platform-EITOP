"""Celery task registry.

Phase 2.5/2.6 background jobs:
- ``scan_endpoint_offline`` — periodic offline detection (the ONLY writer
  of the active→offline transition; recovery happens synchronously on the
  next valid heartbeat).
- ``prune_endpoint_snapshots`` — retention enforcement; a no-op unless an
  operator sets ``SNAPSHOT_RETENTION_DAYS`` (default: keep forever).

No FastAPI request handler ever polls the database for health state.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.models import EndpointSnapshot, EndpointSnapshotSoftware
from app.tasks.job_db import session_scope


@celery_app.task(name="eitop.scan_endpoint_offline")
def scan_endpoint_offline() -> int:
    """Flip stale active endpoints to offline and audit each transition.

    Returns the number of endpoints transitioned. Duplicate events are
    impossible: the underlying UPDATE only matches rows still 'active'.
    """
    from app.services.endpoint_service import scan_offline_endpoints

    with session_scope() as db:
        return scan_offline_endpoints(db)


@celery_app.task(name="eitop.prune_endpoint_snapshots")
def prune_endpoint_snapshots() -> int:
    """Delete snapshots older than the configured retention window.

    Default configuration (``snapshot_retention_days = None``) deletes
    NOTHING — history is preserved until an operator opts in. When enabled,
    old snapshot rows are removed and their normalized software rows follow
    via ON DELETE CASCADE.
    """
    settings = get_settings()
    if settings.snapshot_retention_days is None:
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=settings.snapshot_retention_days)
    with session_scope() as db:
        stale_ids = select(EndpointSnapshot.id).where(EndpointSnapshot.received_at < cutoff)
        # Software rows cascade, but delete explicitly first so the planner
        # never relies on cascade for a potentially large batch.
        db.execute(
            delete(EndpointSnapshotSoftware).where(
                EndpointSnapshotSoftware.snapshot_id.in_(stale_ids)
            )
        )
        result = db.execute(delete(EndpointSnapshot).where(EndpointSnapshot.received_at < cutoff))
        return int(getattr(result, "rowcount", 0) or 0)


__all__ = ["prune_endpoint_snapshots", "scan_endpoint_offline"]
