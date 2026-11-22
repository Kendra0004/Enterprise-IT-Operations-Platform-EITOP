"""Per-run execution ownership for directory synchronization (Phase 3.1.1).

Motivation: a sync task can be delivered more than once (broker
redelivery after the visibility timeout, worker crash + retry) and the
stale-run reaper runs independently of any worker. Timestamp-only
staleness cannot tell a crashed worker from a legitimately long sync, so
the DATABASE is the single authority for who may execute a run:

- ``claim_run`` — one atomic UPDATE: exactly one worker ever holds a
  live lease; every other delivery gets False and must stop without
  touching data or run status (duplicate-delivery guard).
- ``extend_lease`` — heartbeat + ownership re-check; the worker
  re-proves ownership immediately before the first mirror write and
  ATOMICALLY with the mirror commit (same transaction), so a lost or
  expired lease rolls every mirror write back.
- ``finalize_if_owned`` — run status is written only while this worker
  still owns the run AND the status is still ``running``: a stale worker
  can never overwrite a reaped (failed) run — failed stays failed.
- ``find_reapable_runs`` — the reaper collects only runs whose lease
  expired, that were never claimed and aged out, or that exceeded the
  absolute maximum sync duration. A live lease always spares the worker;
  the reaper never kills a legitimately active sync.

All time predicates use PostgreSQL ``clock_timestamp()`` (actual DB
server time, per statement) so every actor — API reaper, worker,
heartbeat thread — compares against ONE clock.

Ownership columns: ``directory_sync_runs.execution_token`` /
``lease_expires_at`` (migration 0006_directory_sync_ownership).
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import SYNC_RUNNING, DirectorySyncRun

logger = logging.getLogger(__name__)

# DB-server clock: the single time source for every ownership predicate.
_NOW = func.clock_timestamp()


class OwnershipLostError(Exception):
    """Ownership is gone mid-transaction: roll back, write nothing.

    Raised inside the mirror transaction so the Session context manager
    rolls back every mirror write; the caller must NOT finalize the run.
    """


def new_execution_token() -> str:
    """Fresh opaque claim token for one worker execution of one run."""
    return uuid.uuid4().hex


def _rowcount(result: Any) -> int:
    """Affected-row count of a DML statement (``rowcount`` lives on
    CursorResult; getattr keeps mypy and runtime in agreement)."""
    return int(getattr(result, "rowcount", 0) or 0)


def _lease_deadline() -> Any:
    """``clock_timestamp() + lease`` — renewal deadline on the DB clock."""
    return _NOW + timedelta(seconds=get_settings().directory_sync_lease_seconds)


def _owned_and_live(run_id: uuid.UUID, token: str) -> tuple[Any, ...]:
    """Criteria that this token currently owns a still-running run."""
    return (
        DirectorySyncRun.id == run_id,
        DirectorySyncRun.execution_token == token,
        DirectorySyncRun.status == SYNC_RUNNING,
        DirectorySyncRun.lease_expires_at.is_not(None),
        DirectorySyncRun.lease_expires_at > _NOW,
    )


def claim_run(db: Session, run_id: uuid.UUID, token: str) -> bool:
    """Atomically claim a ``running`` run for this worker.

    Succeeds only when the run is still ``running`` AND unowned or the
    previous owner's lease has expired (crashed/stalled worker — the
    recovery path). Returns False when another worker holds a live
    lease: the caller must then return without writing anything.
    """
    result = db.execute(
        update(DirectorySyncRun)
        .where(
            DirectorySyncRun.id == run_id,
            DirectorySyncRun.status == SYNC_RUNNING,
            or_(
                DirectorySyncRun.execution_token.is_(None),
                DirectorySyncRun.lease_expires_at.is_(None),
                DirectorySyncRun.lease_expires_at < _NOW,
            ),
        )
        .values(execution_token=token, lease_expires_at=_lease_deadline())
        .execution_options(synchronize_session=False)
    )
    return _rowcount(result) == 1


def extend_lease(db: Session, run_id: uuid.UUID, token: str) -> bool:
    """Re-prove ownership and extend the lease in one atomic UPDATE.

    True only while THIS token owns the run, the status is still
    ``running`` and the lease has not expired yet — an already-expired
    worker must stop, never revive itself. Used as the heartbeat, as the
    pre-write proof, and as the gate immediately before the mirror
    commit; in the mirror transaction the UPDATE joins that transaction,
    so the proof and the mirror writes commit together or not at all.
    """
    result = db.execute(
        update(DirectorySyncRun)
        .where(*_owned_and_live(run_id, token))
        .values(lease_expires_at=_lease_deadline())
        .execution_options(synchronize_session=False)
    )
    return _rowcount(result) == 1


def finalize_if_owned(
    db: Session,
    run_id: uuid.UUID,
    token: str,
    values: dict[str, Any],
) -> bool:
    """Write terminal run bookkeeping only while still the live owner.

    ``values`` is applied only when the run is still ``running`` under
    this token with an unexpired lease; otherwise nothing is written —
    the reaper or a newer owner already decided the outcome, and a stale
    worker never overwrites it (failed never flips to success).
    """
    result = db.execute(
        update(DirectorySyncRun)
        .where(*_owned_and_live(run_id, token))
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return _rowcount(result) == 1


def find_reapable_runs(db: Session, connection_id: uuid.UUID) -> list[DirectorySyncRun]:
    """Runs whose executing worker can no longer be executing them.

    A ``running`` run is reaped when ANY of these hold:

    - its lease expired (claimed worker crashed or stalled), or
    - it was never claimed and aged past the fallback threshold
      (lost broker delivery / pre-lease rows), or
    - it exceeded the absolute maximum sync duration — enforced even
      against a live lease (hard cap on one run's wall time).

    A claimed run with a LIVE lease is never reaped by the age checks:
    the heartbeat keeps legitimately long syncs alive.
    """
    settings = get_settings()
    stale_before = _NOW - timedelta(minutes=settings.directory_stale_run_minutes)
    hard_cap_before = _NOW - timedelta(minutes=settings.directory_max_sync_minutes)
    return list(
        db.scalars(
            select(DirectorySyncRun).where(
                DirectorySyncRun.connection_id == connection_id,
                DirectorySyncRun.status == SYNC_RUNNING,
                or_(
                    DirectorySyncRun.started_at < hard_cap_before,
                    and_(
                        DirectorySyncRun.lease_expires_at.is_not(None),
                        DirectorySyncRun.lease_expires_at < _NOW,
                    ),
                    and_(
                        DirectorySyncRun.lease_expires_at.is_(None),
                        DirectorySyncRun.started_at < stale_before,
                    ),
                ),
            )
        ).all()
    )


class LeaseHeartbeat:
    """Background lease renewal for one executing sync worker.

    A single stage can legitimately outlast the lease (large paged
    categories), so the lease is renewed on a timer instead of only at
    stage boundaries — the stale reaper therefore never mistakes a slow
    but healthy worker for a crashed one. When renewal reports the
    ownership is gone the thread stops quietly; the worker discovers the
    loss at its next gate (pre-commit or finalize) and rolls back
    without writing anything.
    """

    def __init__(
        self,
        session_factory: Callable[[], Session],
        run_id: uuid.UUID,
        token: str,
        *,
        interval: float | None = None,
    ) -> None:
        settings = get_settings()
        self._session_factory = session_factory
        self._run_id = run_id
        self._token = token
        # Three renewal ticks per lease by default.
        self._interval = (
            interval
            if interval is not None
            else max(1.0, settings.directory_sync_lease_seconds / 3)
        )
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"dir-sync-lease-{run_id}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop and wait for it to exit (safe to call once)."""
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                with self._session_factory() as db:
                    owned = extend_lease(db, self._run_id, self._token)
                    db.commit()
            except Exception as exc:  # noqa: BLE001 - transient DB errors
                # Never log raw exception content (Phase 3.1 rule): if the
                # DB stays unreachable the lease simply expires and the
                # reaper / ownership gates take over.
                logger.warning(
                    "directory_sync_heartbeat_error",
                    extra={
                        "run_id": str(self._run_id),
                        "error_type": type(exc).__name__,
                    },
                )
                continue
            if not owned:
                logger.warning(
                    "directory_sync_heartbeat_lost_ownership",
                    extra={"run_id": str(self._run_id)},
                )
                return


__all__ = [
    "LeaseHeartbeat",
    "OwnershipLostError",
    "claim_run",
    "extend_lease",
    "finalize_if_owned",
    "find_reapable_runs",
    "new_execution_token",
]
