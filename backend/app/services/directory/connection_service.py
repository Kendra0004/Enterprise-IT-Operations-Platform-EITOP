"""Directory connection management and sync orchestration (Phase 3.1).

Security/audit rules:
- The bind password is write-only: encrypted at rest (secrets.py), never
  returned by any schema, never logged, never audited (audit details carry
  connection name/host/counts/labels only).
- Every mutation writes a ``directory.*`` audit event; failure-path audits
  are committed BEFORE the AppError propagates (get_db would otherwise
  roll them back).
- ``create_sync_run`` reaps only runs whose owner can no longer be
  executing them (expired lease, never-claimed and aged past the
  fallback threshold, or past the absolute max sync duration — see
  services/directory/ownership.py), so a crashed worker or a failed task
  submission can never block retries forever, while a live lease always
  spares an actively working sync. The partial unique index guarantees a
  clean 409 on concurrent triggers.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.exceptions import AppError
from app.models import (
    SYNC_FAILED,
    SYNC_RUNNING,
    SYNC_TRIGGER_MANUAL,
    SYNC_TRIGGER_SCHEDULED,
    DirectoryConnection,
    DirectorySyncRun,
    User,
)
from app.schemas.directory import ConnectionCreate, ConnectionUpdate
from app.services.auth_service import _record_audit
from app.services.directory import factory
from app.services.directory.errors import (
    LABEL_SEARCH_BASE,
    LABEL_STALE_RUN,
    LABEL_TASK_SUBMISSION,
    classify_error,
    message_for,
    static_error,
)
from app.services.directory.ldap_client import DirectoryLdapClient
from app.services.directory.ownership import find_reapable_runs
from app.services.directory.secrets import encrypt_password
from app.services.directory.sync_engine import failed_results, initial_category_results

SYNC_TASK_NAME = "eitop.sync_directory"


# --- Connection CRUD ---------------------------------------------------------


def create_connection(
    db: Session,
    payload: ConnectionCreate,
    *,
    actor: User,
    request: Request,
) -> DirectoryConnection:
    """Create a connection. The bind password is encrypted immediately."""
    existing = db.scalar(
        select(DirectoryConnection).where(DirectoryConnection.name == payload.name)
    )
    if existing is not None:
        raise AppError(
            status.HTTP_409_CONFLICT,
            "Connection already exists",
            f"A connection named '{payload.name}' already exists.",
        )
    row = DirectoryConnection(
        name=payload.name,
        domain_dns=payload.domain_dns,
        host=payload.host,
        port=payload.port,
        tls_mode=payload.tls_mode,
        tls_ca_pem=payload.tls_ca_pem,
        search_base=payload.search_base,
        bind_username=payload.bind_username,
        bind_password_encrypted=encrypt_password(payload.bind_password),
        connect_timeout_seconds=payload.connect_timeout_seconds,
        search_timeout_seconds=payload.search_timeout_seconds,
        page_size=payload.page_size,
        enabled=payload.enabled,
        auto_sync=payload.auto_sync,
        sync_interval_minutes=payload.sync_interval_minutes,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        raise AppError(
            status.HTTP_409_CONFLICT,
            "Connection already exists",
            f"A connection named '{payload.name}' already exists.",
        ) from None
    _record_audit(
        db,
        event_type="directory.connection.created",
        outcome="success",
        request=request,
        actor=actor,
        target=str(row.id),
        detail={
            "name": row.name,
            "host": row.host,
            "port": row.port,
            "tls_mode": row.tls_mode,
        },
    )
    return row


def update_connection(
    db: Session,
    row: DirectoryConnection,
    payload: ConnectionUpdate,
    *,
    actor: User,
    request: Request,
) -> DirectoryConnection:
    """Partial update. Audits changed field NAMES — never values of secrets."""
    data = payload.model_dump(exclude_unset=True)
    # Phase 6 audit AD1: the bind password is advertised write-only, but
    # PATCHing ``host`` (or ``tls_ca_pem``) used to silently retarget
    # where the decrypted credential is sent — the next test/sync would
    # hand the AD password to an attacker listener validated by an
    # attacker CA. Changing the target therefore requires re-entering
    # the credential in the same request.
    retargeted = ("host" in data and data["host"] != row.host) or (
        "tls_ca_pem" in data and data["tls_ca_pem"] != row.tls_ca_pem
    )
    if retargeted and not data.get("bind_password"):
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "bind_password required",
            "Changing host or TLS CA requires re-entering the bind "
            "password so the credential is never sent to a new target "
            "unchecked.",
        )
    if "name" in data and data["name"] != row.name:
        clash = db.scalar(
            select(DirectoryConnection).where(
                DirectoryConnection.name == data["name"],
                DirectoryConnection.id != row.id,
            )
        )
        if clash is not None:
            raise AppError(
                status.HTTP_409_CONFLICT,
                "Connection already exists",
                f"A connection named '{data['name']}' already exists.",
            )
    changes: list[str] = []
    if "bind_password" in data:
        new_password = data.pop("bind_password")
        # Pydantic's min_length does not reject an explicit JSON null, and
        # encrypt_password(None) used to escape as an unhandled ValueError
        # → 500 (Phase 6 audit AD2). Null/blank is a 422, not a crash.
        if not isinstance(new_password, str) or not new_password.strip():
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Invalid bind password",
                "bind_password must be a non-empty string when provided.",
            )
        row.bind_password_encrypted = encrypt_password(new_password)
        changes.append("bind_password")
    for field, value in data.items():
        if getattr(row, field) != value:
            setattr(row, field, value)
            changes.append(field)
    if changes:
        _record_audit(
            db,
            event_type="directory.connection.updated",
            outcome="success",
            request=request,
            actor=actor,
            target=str(row.id),
            detail={"name": row.name, "changed": changes},
        )
    return row


def delete_connection(
    db: Session,
    row: DirectoryConnection,
    *,
    actor: User,
    request: Request,
) -> None:
    """Remove a connection; DB cascades remove its mirror and run history."""
    _record_audit(
        db,
        event_type="directory.connection.deleted",
        outcome="success",
        request=request,
        actor=actor,
        target=str(row.id),
        detail={"name": row.name, "host": row.host},
    )
    db.delete(row)


# --- Connectivity test -------------------------------------------------------


def test_connection(
    db: Session,
    row: DirectoryConnection,
    *,
    actor: User,
    request: Request,
) -> dict[str, Any]:
    """Probe TLS + bind + rootDSE + search-base visibility.

    Never raises for connectivity outcomes (the frontend renders the
    result); returns a sanitized ``{ok, label, message, duration_ms, ...}``.
    """
    started = time.monotonic()
    label: str | None = None
    info: dict[str, Any] = {}
    client: DirectoryLdapClient | None = None
    try:
        client = factory.build_client(row)
        client.connect()
        root = client.root_dse()
        if root.get("defaultNamingContext"):
            info["default_naming_context"] = root["defaultNamingContext"]
        if root.get("dnsHostName"):
            info["dns_hostname"] = root["dnsHostName"]
        if not client.validate_search_base(row.search_base):
            label = LABEL_SEARCH_BASE
    except Exception as exc:  # noqa: BLE001 - classified, never re-raised raw
        label = classify_error(exc)
    finally:
        if client is not None:
            client.close()
    duration_ms = int((time.monotonic() - started) * 1000)
    ok = label is None
    _record_audit(
        db,
        event_type="directory.connection.tested",
        outcome="success" if ok else "failure",
        request=request,
        actor=actor,
        target=str(row.id),
        detail={"name": row.name, "host": row.host}
        | ({} if ok else {"label": label}),
    )
    return {
        "ok": ok,
        "label": label,
        "message": message_for(label) if label else None,
        "duration_ms": duration_ms,
        **info,
    }


# --- Sync run lifecycle ------------------------------------------------------


def create_sync_run(
    db: Session,
    row: DirectoryConnection,
    *,
    trigger: str,
    actor: User | None = None,
    request: Request | None = None,
) -> DirectorySyncRun:
    """Insert a ``running`` sync row, reaping dead runs first.

    The reap is lease-aware (Phase 3.1.1): a run is collected only when
    its lease expired (crashed/stalled worker), it was never claimed and
    aged past the fallback threshold (lost broker delivery), or it
    exceeded the absolute max sync duration — a live lease always spares
    an actively working sync, however old its ``started_at`` is.

    Raises ``AppError(409)`` when another run is active (partial unique
    index ``uq_directory_sync_runs_running``) after rolling back this
    transaction, so concurrent triggers get a clean conflict response.
    """
    now = datetime.now(UTC)
    stale = find_reapable_runs(db, row.id)
    for run in stale:
        run.status = SYNC_FAILED
        run.finished_at = now
        run.errors = [static_error("connect", LABEL_STALE_RUN)]
        run.category_results = failed_results(LABEL_STALE_RUN)
        _record_audit(
            db,
            event_type="directory.sync.failed",
            outcome="failure",
            request=request,
            actor=actor,
            target=str(run.id),
            detail={
                "connection": row.name,
                "host": row.host,
                "label": LABEL_STALE_RUN,
            },
        )
    if stale:
        db.flush()  # apply reaps BEFORE the insert (ordering matters)

    run = DirectorySyncRun(
        connection_id=row.id,
        trigger=trigger,
        status=SYNC_RUNNING,
        category_results=initial_category_results(),
    )
    db.add(run)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        if "uq_directory_sync_runs_running" in str(getattr(exc, "orig", exc)):
            raise AppError(
                status.HTTP_409_CONFLICT,
                "Sync already running",
                "A sync run is already in progress for this connection.",
            ) from None
        raise
    return run


def trigger_sync(
    db: Session,
    row: DirectoryConnection,
    *,
    trigger: str,
    actor: User | None = None,
    request: Request | None = None,
) -> DirectorySyncRun:
    """Create a run row and enqueue the Celery task.

    If submission fails the run is immediately marked failed with a
    sanitized label, audited, and COMMITTED before the 503 propagates —
    a ``running`` row never survives a failed enqueue, so retries work.
    """
    run = create_sync_run(db, row, trigger=trigger, actor=actor, request=request)
    # Publish the run row BEFORE the task exists (Phase 6 audit AD4): the
    # worker loads the row as soon as it can receive the task, and the
    # route's commit only happens after this function returns — without
    # this commit the worker can see "no such run" while the INSERT is
    # still open, silently skipping a run that later commits as
    # unowned ``running`` (self-healing only via the 30-minute reaper).
    db.commit()
    try:
        celery_app.send_task(SYNC_TASK_NAME, args=[str(run.id)])
    except Exception:  # noqa: BLE001 - broker failure must not strand the run
        run.status = SYNC_FAILED
        run.finished_at = datetime.now(UTC)
        run.errors = [static_error("connect", LABEL_TASK_SUBMISSION)]
        run.category_results = failed_results(LABEL_TASK_SUBMISSION)
        _record_audit(
            db,
            event_type="directory.sync.failed",
            outcome="failure",
            request=request,
            actor=actor,
            target=str(run.id),
            detail={
                "connection": row.name,
                "host": row.host,
                "trigger": trigger,
                "label": LABEL_TASK_SUBMISSION,
            },
        )
        db.commit()  # persist BEFORE raising: get_db rolls back on AppError
        raise AppError(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Sync submission failed",
            message_for(LABEL_TASK_SUBMISSION),
        ) from None
    if trigger == SYNC_TRIGGER_MANUAL and actor is not None:
        _record_audit(
            db,
            event_type="directory.sync.triggered",
            outcome="success",
            request=request,
            actor=actor,
            target=str(run.id),
            detail={"connection": row.name, "host": row.host, "trigger": trigger},
        )
    return run


def enqueue_due_syncs(
    *,
    session_factory: Callable[[], Session] = SessionLocal,
) -> int:
    """Beat tick: enqueue scheduled syncs whose per-connection interval
    elapsed. Each connection uses its OWN session/transaction so one
    connection's 409/503 can never discard another's freshly created run.
    """
    now = datetime.now(UTC)
    due_ids: list[uuid.UUID] = []
    with session_factory() as db:
        last_run = (
            select(
                DirectorySyncRun.connection_id.label("cid"),
                func.max(DirectorySyncRun.started_at).label("last_started"),
            )
            .group_by(DirectorySyncRun.connection_id)
            .subquery()
        )
        rows = db.execute(
            select(DirectoryConnection, last_run.c.last_started)
            .outerjoin(
                last_run, last_run.c.cid == DirectoryConnection.id
            )
            .where(
                DirectoryConnection.enabled.is_(True),
                DirectoryConnection.auto_sync.is_(True),
            )
        ).all()
        for connection_row, last_started in rows:
            if last_started is not None and last_started > now - timedelta(
                minutes=connection_row.sync_interval_minutes
            ):
                continue
            due_ids.append(connection_row.id)

    enqueued = 0
    for connection_id in due_ids:
        try:
            with session_factory() as per_connection:
                row = per_connection.get(DirectoryConnection, connection_id)
                if row is None or not (row.enabled and row.auto_sync):
                    continue
                trigger_sync(per_connection, row, trigger=SYNC_TRIGGER_SCHEDULED)
                per_connection.commit()
                enqueued += 1
        except AppError:
            # 409: a manual run is active; 503: submission already
            # persisted as a failed run. Either way: continue with the rest.
            continue
    return enqueued


__all__ = [
    "SYNC_TASK_NAME",
    "create_connection",
    "create_sync_run",
    "delete_connection",
    "enqueue_due_syncs",
    "test_connection",
    "trigger_sync",
    "update_connection",
]
