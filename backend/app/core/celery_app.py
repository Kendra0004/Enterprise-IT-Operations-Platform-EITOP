"""Celery application for background jobs (phase 1: configuration only).

Jobs (inventory collection, CVE sync, SNMP polling) are added in later
phases; this module establishes the shared Celery app so worker processes
and the API agree on broker/serialization settings.
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
)
