"""Celery task registry.

Phase 2.5/2.6 background jobs:
- ``scan_endpoint_offline`` — periodic offline detection (the ONLY writer
  of the active→offline transition; recovery happens synchronously on the
  next valid heartbeat).
- ``prune_endpoint_snapshots`` — retention enforcement; a no-op unless an
  operator sets ``SNAPSHOT_RETENTION_DAYS`` (default: keep forever).

Phase 3.1:
- ``sync_directory`` — executes one sync run to completion; the run row
  always reaches a terminal state (success/failed/skipped) inside the
  task, so a crashed worker can never leave a run ``running`` forever
  (the lease-aware reaper on the next trigger is the second line of
  defence). Phase 3.1.1: the engine claims the run with an execution
  token + lease before any write — a duplicate delivery of the same run
  (broker redelivery) loses the claim and returns ``skipped`` without
  touching data or run status. The task is bounded by the limits set in
  ``app/core/celery_app.py`` (``task_soft_time_limit`` /
  ``task_time_limit`` sized from ``directory_max_sync_minutes``, with
  the broker ``visibility_timeout`` above them), so it cannot outlive
  its DB lease ladder indefinitely.
- ``directory_sync_tick`` — beat-driven enqueue of due scheduled syncs.

Phase 3.2.1:
- ``directory_insights_tick`` — beat-driven recompute of directory
  findings for every enabled connection (per-connection advisory lock;
  a colliding tick skips with zero writes).

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


@celery_app.task(name="eitop.sync_directory")
def sync_directory(run_id: str) -> str:
    """Execute one directory sync run (Phase 3.1).

    Returns the terminal run status. The engine always finalizes the run
    (success/failed/skipped) — even on unexpected errors — so a ``running``
    row can never outlive its task; the lease-aware stale reaper on the
    next trigger covers hard worker crashes on top of that. Ownership
    (Phase 3.1.1): only the worker holding the run's execution token and
    a live lease may write mirror data or finalize the status; every
    other delivery returns ``skipped`` untouched.
    """
    import uuid as _uuid

    from app.services.directory.sync_engine import execute_sync

    return execute_sync(_uuid.UUID(run_id))


@celery_app.task(name="eitop.directory_sync_tick")
def directory_sync_tick() -> int:
    """Beat task: enqueue scheduled directory syncs that are due.

    Returns the number of runs enqueued. Concurrency conflicts (409) and
    broker failures (503) are handled per connection inside the service
    and never abort the remaining connections.
    """
    from app.services.directory.connection_service import enqueue_due_syncs

    return enqueue_due_syncs()


@celery_app.task(name="eitop.directory_insights_tick")
def directory_insights_tick() -> int:
    """Beat task: recompute directory findings for every enabled
    connection (Phase 3.2.1).

    Returns the number of connections recomputed (lock-skipped ones do
    not count). Each connection runs in its own session/transaction
    under the per-connection advisory lock, so a collision between this
    tick and another writer skips cleanly with zero writes instead of
    blocking or duplicating work.
    """
    from app.models import DirectoryConnection
    from app.services.directory.insights import recompute_connection

    with session_scope() as db:
        connection_ids = list(
            db.scalars(
                select(DirectoryConnection.id).where(
                    DirectoryConnection.enabled.is_(True)
                )
            )
        )
    done = 0
    for connection_id in connection_ids:
        with session_scope() as db:
            result = recompute_connection(db, connection_id)
        if not result.get("skipped"):
            done += 1
    return done


__all__ = [
    "directory_insights_tick",
    "directory_sync_tick",
    "prune_endpoint_snapshots",
    "scan_endpoint_offline",
    "sync_directory",
]
