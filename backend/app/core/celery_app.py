"""Celery application for background jobs.

Tasks live in ``app.tasks.jobs``; this module defines the shared app so
worker, beat and the API agree on broker/serialization settings and the
periodic schedule (Phase 2.5/2.6: offline detection, snapshot retention).
"""

from __future__ import annotations

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

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
    },
)
