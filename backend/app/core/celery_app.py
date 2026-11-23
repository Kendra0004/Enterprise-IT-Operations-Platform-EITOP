"""Celery application for background jobs.

Tasks live in ``app.tasks.jobs``; this module defines the shared app so
worker, beat and the API agree on broker/serialization settings and the
periodic schedule (Phase 2.5/2.6: offline detection, snapshot retention).
"""

from __future__ import annotations

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

# --- Runtime limits (Phase 3.1.1): one consistent ladder --------------------
# Sized from config so the DB, the worker and the broker agree:
#   directory_max_sync_minutes  = DB hard cap on one run   (from run creation)
#   task_soft_time_limit        = same, from task start    (graceful failure)
#   task_time_limit             = soft + 1 min             (hard worker kill)
#   broker visibility_timeout   = max + 15 min             (unacked redelivery)
# The run is created before the task starts, so the database reaps a run
# at or before the soft limit; the hard limit then guarantees the worker
# dies shortly after; visibility_timeout staying ABOVE task_time_limit
# guarantees Redis never redelivers a task that is still running. The
# execution-token lease (directory_sync_lease_seconds) makes any
# duplicate delivery harmless regardless: the second worker skips.
_SYNC_SOFT_LIMIT_SECONDS = settings.directory_max_sync_minutes * 60
_SYNC_HARD_LIMIT_SECONDS = _SYNC_SOFT_LIMIT_SECONDS + 60
_VISIBILITY_TIMEOUT_SECONDS = (settings.directory_max_sync_minutes + 15) * 60

celery_app = Celery(
    "eitop",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.jobs"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,  # fair scheduling for long-running jobs
    result_expires=3600 * 24,
    # Every task is bounded (Phase 3.1.1); eitop.sync_directory is the
    # longest-running one and defines the ladder above.
    task_soft_time_limit=_SYNC_SOFT_LIMIT_SECONDS,
    task_time_limit=_SYNC_HARD_LIMIT_SECONDS,
    # Explicit broker redelivery window for the Redis transport: must
    # exceed task_time_limit or a live task could be delivered twice.
    broker_transport_options={"visibility_timeout": _VISIBILITY_TIMEOUT_SECONDS},
    # Periodic jobs (Phase 2.5/2.6): offline detection runs continuously;
    # snapshot retention is a daily no-op unless explicitly configured.
    # Phase 3.1: directory sync scan runs on its own (configurable) tick.
    beat_schedule={
        "scan-endpoint-offline": {
            "task": "eitop.scan_endpoint_offline",
            "schedule": float(settings.endpoint_health_scan_seconds),
        },
        "prune-endpoint-snapshots": {
            "task": "eitop.prune_endpoint_snapshots",
            "schedule": 60.0 * 60.0 * 24.0,  # daily
        },
        "directory-sync-tick": {
            "task": "eitop.directory_sync_tick",
            "schedule": float(settings.directory_sync_scan_seconds),
        },
        # Phase 3.2.1: findings recompute (idempotent, advisory-locked per
        # connection — colliding ticks skip cleanly with zero writes).
        "directory-insights-tick": {
            "task": "eitop.directory_insights_tick",
            "schedule": float(settings.directory_insight_scan_seconds),
        },
    },
)
