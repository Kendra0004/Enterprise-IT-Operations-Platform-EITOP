"""Endpoint administration: enrollment tokens, listing, groups, revocation.

RBAC: ``endpoints:read`` for reads, ``endpoints:write`` for mutations.
No response ever contains agent credential material (rotation is the sole
issuance moment and returns the new secret exactly once).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from app.api.deps import DbSession, require_permissions
from app.core.config import get_settings
from app.core.exceptions import AppError
from app.models import (
    ENDPOINT_ACTIVE,
    ENDPOINT_OFFLINE,
    ENDPOINT_REVOKED,
    Endpoint,
    EndpointCredential,
    EndpointFact,
    EndpointGroup,
    EndpointMetadata,
    EndpointSnapshot,
    EndpointSnapshotSoftware,
    EndpointSoftware,
    EnrollmentToken,
    User,
)
from app.schemas.auth import Page
from app.schemas.endpoints import (
    CredentialRotateOut,
    EndpointDetailOut,
    EndpointHealthOut,
    EndpointOut,
    EndpointRevokeOut,
    EnrollmentTokenCreate,
    EnrollmentTokenCreatedOut,
    EnrollmentTokenOut,
    FactOut,
    GroupCreate,
    GroupDetailOut,
    GroupOut,
    HardwareChangeOut,
    MetadataOut,
    NetworkHistoryOut,
    OverviewStatsOut,
    SnapshotDetailOut,
    SnapshotDiffOut,
    SnapshotOut,
    SnapshotSoftwareOut,
    SoftwareHistoryOut,
)
from app.services.auth_service import _record_audit
from app.services.endpoint_service import (
    create_enrollment_token,
    derive_collector_status,
    revoke_endpoint,
    rotate_credential,
)

router = APIRouter(tags=["endpoints"])

EndpointsRead = Annotated[User, Depends(require_permissions("endpoints:read"))]
EndpointsWrite = Annotated[User, Depends(require_permissions("endpoints:write"))]

# Sorting allowlist — arbitrary column names never reach ORDER BY.
_SORT_FIELDS = {
    "hostname": Endpoint.hostname,
    "status": Endpoint.status,
    "os": Endpoint.os,
    "agent_version": Endpoint.agent_version,
    "enrolled_at": Endpoint.enrolled_at,
    "last_heartbeat_at": Endpoint.last_heartbeat_at,
    "created_at": Endpoint.created_at,
}


def _get_endpoint(db: Session, endpoint_id: uuid.UUID) -> Endpoint:
    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND, "Endpoint not found", str(endpoint_id)
        )
    return endpoint


def _parse_dt(value: datetime | None, *, name: str) -> datetime | None:
    """Normalize query timestamps to UTC (naive input assumed UTC)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


# --- Groups (declared before /{endpoint_id} so "groups" never matches a path
# parameter) ---------------------------------------------------------------


@router.get("/endpoints/groups", response_model=list[GroupOut])
def list_groups(db: DbSession, _: EndpointsRead) -> list[GroupOut]:
    rows = db.execute(
        select(EndpointGroup, func.count(Endpoint.id))
        .outerjoin(EndpointGroup.endpoints)
        .group_by(EndpointGroup.id)
        .order_by(EndpointGroup.name)
    ).all()
    return [
        GroupOut(
            id=g.id,
            name=g.name,
            description=g.description,
            created_at=g.created_at,
            updated_at=g.updated_at,
            endpoint_count=count,
        )
        for g, count in rows
    ]


@router.post(
    "/endpoints/groups", response_model=GroupOut, status_code=status.HTTP_201_CREATED
)
def create_group(
    payload: GroupCreate, request: Request, db: DbSession, admin: EndpointsWrite
) -> GroupOut:
    existing = db.scalar(select(EndpointGroup).where(EndpointGroup.name == payload.name))
    if existing is not None:
        raise AppError(status.HTTP_409_CONFLICT, "Group already exists", payload.name)
    group = EndpointGroup(name=payload.name, description=payload.description)
    db.add(group)
    db.flush()
    _record_audit(
        db,
        event_type="endpoint.group.created",
        outcome="success",
        request=request,
        actor=admin,
        target=str(group.id),
        detail={"name": group.name},
    )
    return GroupOut(
        id=group.id,
        name=group.name,
        description=group.description,
        created_at=group.created_at,
        updated_at=group.updated_at,
        endpoint_count=0,
    )


def _group_detail(db: Session, group: EndpointGroup) -> GroupDetailOut:
    members = db.scalars(
        select(Endpoint)
        .where(Endpoint.groups.any(EndpointGroup.id == group.id))
        .order_by(Endpoint.hostname)
    ).all()
    ips = _ip_map(db, members)
    return GroupDetailOut(
        id=group.id,
        name=group.name,
        description=group.description,
        created_at=group.created_at,
        updated_at=group.updated_at,
        endpoint_count=len(members),
        members=[_to_out(e, ips.get(e.id)) for e in members],
    )


@router.get("/endpoints/groups/{group_id}", response_model=GroupDetailOut)
def get_group(group_id: uuid.UUID, db: DbSession, _: EndpointsRead) -> GroupDetailOut:
    group = db.get(EndpointGroup, group_id)
    if group is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND, "Group not found", str(group_id)
        )
    return _group_detail(db, group)


@router.post(
    "/endpoints/{endpoint_id}/groups/{group_id}", response_model=GroupDetailOut
)
def add_group_member(
    endpoint_id: uuid.UUID,
    group_id: uuid.UUID,
    request: Request,
    db: DbSession,
    admin: EndpointsWrite,
) -> GroupDetailOut:
    """Assign an endpoint to a group (idempotent). Audited."""
    endpoint = _get_endpoint(db, endpoint_id)
    group = db.get(EndpointGroup, group_id)
    if group is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND, "Group not found", str(group_id)
        )
    if group not in endpoint.groups:
        endpoint.groups.append(group)
        db.flush()
        _record_audit(
            db,
            event_type="endpoint.group.member.added",
            outcome="success",
            request=request,
            actor=admin,
            target=str(endpoint.id),
            detail={"group_id": str(group.id), "group_name": group.name},
        )
    return _group_detail(db, group)


@router.delete(
    "/endpoints/{endpoint_id}/groups/{group_id}", response_model=GroupDetailOut
)
def remove_group_member(
    endpoint_id: uuid.UUID,
    group_id: uuid.UUID,
    request: Request,
    db: DbSession,
    admin: EndpointsWrite,
) -> GroupDetailOut:
    """Remove an endpoint from a group (idempotent). Audited on change."""
    endpoint = _get_endpoint(db, endpoint_id)
    group = db.get(EndpointGroup, group_id)
    if group is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND, "Group not found", str(group_id)
        )
    if group in endpoint.groups:
        endpoint.groups.remove(group)
        db.flush()
        _record_audit(
            db,
            event_type="endpoint.group.member.removed",
            outcome="success",
            request=request,
            actor=admin,
            target=str(endpoint.id),
            detail={"group_id": str(group.id), "group_name": group.name},
        )
    return _group_detail(db, group)


# --- Enrollment tokens ------------------------------------------------------


@router.post(
    "/endpoints/enrollment-tokens",
    response_model=EnrollmentTokenCreatedOut,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment_token_endpoint(
    payload: EnrollmentTokenCreate,
    request: Request,
    db: DbSession,
    admin: EndpointsWrite,
) -> EnrollmentTokenCreatedOut:
    row, raw = create_enrollment_token(db, created_by=admin, payload=payload)
    return EnrollmentTokenCreatedOut(
        id=row.id,
        expires_at=row.expires_at,
        used_at=row.used_at,
        group_id=row.group_id,
        created_at=row.created_at,
        consumed_by=row.consumed_by,
        token=raw,  # shown exactly once; never stored or logged
    )


@router.get(
    "/endpoints/enrollment-tokens", response_model=list[EnrollmentTokenOut]
)
def list_enrollment_tokens(
    db: DbSession,
    _: EndpointsRead,
    include_used: bool = Query(False),
) -> list[EnrollmentTokenOut]:
    stmt = select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc())
    if not include_used:
        stmt = stmt.where(EnrollmentToken.used_at.is_(None))
    rows = db.scalars(stmt.limit(100)).all()
    return [
        EnrollmentTokenOut(
            id=r.id,
            expires_at=r.expires_at,
            used_at=r.used_at,
            group_id=r.group_id,
            created_at=r.created_at,
            consumed_by=r.consumed_by,
        )
        for r in rows
    ]


# --- Endpoints --------------------------------------------------------------


@router.get("/endpoints", response_model=Page)
def list_endpoints(
    db: DbSession,
    _: EndpointsRead,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Annotated[
        str | None, Query(alias="status", pattern="^(active|offline|revoked)$")
    ] = None,
    group_id: uuid.UUID | None = None,
    q: Annotated[str | None, Query(max_length=255)] = None,
    os: Annotated[str | None, Query(max_length=64)] = None,
    agent_version: Annotated[str | None, Query(max_length=32)] = None,
    heartbeat_from: datetime | None = None,
    heartbeat_to: datetime | None = None,
    sort: str = Query("enrolled_at"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> Page:
    """Paginated endpoint list.

    Filters: status (incl. offline), ``q`` = hostname search, exact ``os``
    and ``agent_version``, and a ``last_heartbeat_at`` range
    (``heartbeat_from``/``heartbeat_to``). Sorting is allowlisted.
    """
    if sort not in _SORT_FIELDS:
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Invalid sort field",
            f"Allowed: {', '.join(sorted(_SORT_FIELDS))}",
        )
    column = _SORT_FIELDS[sort]
    direction = column.desc() if order == "desc" else column.asc()

    stmt = select(Endpoint)
    count_stmt = select(func.count()).select_from(Endpoint)
    if status_filter is not None:
        stmt = stmt.where(Endpoint.status == status_filter)
        count_stmt = count_stmt.where(Endpoint.status == status_filter)
    if group_id is not None:
        stmt = stmt.where(
            Endpoint.groups.any(EndpointGroup.id == group_id)
        )
        count_stmt = count_stmt.where(
            Endpoint.groups.any(EndpointGroup.id == group_id)
        )
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(Endpoint.hostname.ilike(pattern))
        count_stmt = count_stmt.where(Endpoint.hostname.ilike(pattern))
    if os:
        stmt = stmt.where(Endpoint.os == os)
        count_stmt = count_stmt.where(Endpoint.os == os)
    if agent_version:
        stmt = stmt.where(Endpoint.agent_version == agent_version)
        count_stmt = count_stmt.where(Endpoint.agent_version == agent_version)
    hb_from = _parse_dt(heartbeat_from, name="heartbeat_from")
    if hb_from is not None:
        stmt = stmt.where(Endpoint.last_heartbeat_at >= hb_from)
        count_stmt = count_stmt.where(Endpoint.last_heartbeat_at >= hb_from)
    hb_to = _parse_dt(heartbeat_to, name="heartbeat_to")
    if hb_to is not None:
        stmt = stmt.where(Endpoint.last_heartbeat_at <= hb_to)
        count_stmt = count_stmt.where(Endpoint.last_heartbeat_at <= hb_to)

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(direction, Endpoint.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    ip_map = _ip_map(db, rows)
    items = [_to_out(e, ip_map.get(e.id)) for e in rows]
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/endpoints/overview", response_model=OverviewStatsOut)
def endpoints_overview(db: DbSession, _: EndpointsRead) -> OverviewStatsOut:
    """Aggregate counters + latest enrollments for the overview page.

    All numbers are computed from real rows — never fabricated client-side.
    """
    counts = {
        status_value: count
        for status_value, count in db.execute(
            select(Endpoint.status, func.count()).group_by(Endpoint.status)
        ).all()
    }
    os_counts = {
        os_value: count
        for os_value, count in db.execute(
            select(Endpoint.os, func.count()).group_by(Endpoint.os)
        ).all()
    }
    windows = os_counts.get("windows", 0)
    linux = os_counts.get("linux", 0)
    total = sum(counts.values())
    inventory_reported = (
        db.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(Endpoint.last_inventory_at.is_not(None))
        )
        or 0
    )
    latest = db.scalars(
        select(Endpoint).order_by(Endpoint.enrolled_at.desc()).limit(5)
    ).all()
    ip_map = _ip_map(db, list(latest))
    return OverviewStatsOut(
        total=total,
        active=counts.get(ENDPOINT_ACTIVE, 0),
        offline=counts.get(ENDPOINT_OFFLINE, 0),
        revoked=counts.get(ENDPOINT_REVOKED, 0),
        windows=windows,
        linux=linux,
        other_os=max(0, total - windows - linux),
        inventory_reported=inventory_reported,
        latest_enrollments=[_to_out(e, ip_map.get(e.id)) for e in latest],
    )


def _ip_map(db: Session, endpoints: Sequence[Endpoint]) -> dict[uuid.UUID, list[str]]:
    """Batch-load reported IPs for a page of endpoints (no N+1)."""
    if not endpoints:
        return {}
    ids = [e.id for e in endpoints]
    rows = db.execute(
        select(EndpointMetadata.endpoint_id, EndpointMetadata.ip_addresses).where(
            EndpointMetadata.endpoint_id.in_(ids)
        )
    ).all()
    return {r.endpoint_id: list(r.ip_addresses or []) for r in rows}


def _to_out(endpoint: Endpoint, ip_addresses: list[str] | None = None) -> EndpointOut:
    return EndpointOut(
        id=endpoint.id,
        hostname=endpoint.hostname,
        fqdn=endpoint.fqdn,
        os=endpoint.os,
        os_version=endpoint.os_version,
        os_arch=endpoint.os_arch,
        kernel_version=endpoint.kernel_version,
        status=endpoint.status,
        agent_version=endpoint.agent_version,
        enrolled_at=endpoint.enrolled_at,
        last_heartbeat_at=endpoint.last_heartbeat_at,
        created_at=endpoint.created_at,
        updated_at=endpoint.updated_at,
        groups=[g.name for g in endpoint.groups],
        ip_addresses=list(ip_addresses or []),
        last_inventory_at=endpoint.last_inventory_at,
    )


@router.get("/endpoints/{endpoint_id}", response_model=EndpointDetailOut)
def get_endpoint(
    endpoint_id: uuid.UUID, db: DbSession, _: EndpointsRead
) -> EndpointDetailOut:
    endpoint = _get_endpoint(db, endpoint_id)
    meta = endpoint.metadata_row
    base = _to_out(
        endpoint, list(meta.ip_addresses or []) if meta and meta.ip_addresses else None
    )
    facts = db.scalars(
        select(EndpointFact)
        .where(EndpointFact.endpoint_id == endpoint.id)
        .order_by(EndpointFact.key)
    ).all()
    software_count = (
        db.scalar(
            select(func.count())
            .select_from(EndpointSoftware)
            .where(EndpointSoftware.endpoint_id == endpoint.id)
        )
        or 0
    )
    return EndpointDetailOut(
        **base.model_dump(),
        metadata=MetadataOut.model_validate(meta) if meta else None,
        facts=[FactOut.model_validate(f) for f in facts],
        software_count=software_count,
    )


# --- Health (Phase 2.5) -----------------------------------------------------


@router.get("/endpoints/{endpoint_id}/health", response_model=EndpointHealthOut)
def get_endpoint_health(
    endpoint_id: uuid.UUID, db: DbSession, _: EndpointsRead
) -> EndpointHealthOut:
    """Health view: persisted status + read-time derived collector status.

    Derived between background scans from UTC timestamps, so a heartbeat
    that arrived seconds ago shows healthy even before the next scan.
    """
    endpoint = _get_endpoint(db, endpoint_id)
    settings = get_settings()
    now = datetime.now(UTC)
    collector_status, seconds_since = derive_collector_status(
        endpoint,
        now,
        interval=settings.endpoint_heartbeat_interval_seconds,
        threshold=settings.endpoint_offline_threshold_seconds,
    )
    return EndpointHealthOut(
        endpoint_id=endpoint.id,
        status=endpoint.status,
        collector_status=collector_status,
        last_heartbeat_at=endpoint.last_heartbeat_at,
        last_inventory_at=endpoint.last_inventory_at,
        seconds_since_heartbeat=seconds_since,
        agent_version=endpoint.agent_version,
        heartbeat_interval_seconds=settings.endpoint_heartbeat_interval_seconds,
        offline_threshold_seconds=settings.endpoint_offline_threshold_seconds,
        server_time=now,
    )


# --- Inventory snapshots (Phase 2.6) ---------------------------------------


def _snapshot_out(db: Session, snap: EndpointSnapshot) -> SnapshotOut:
    package_count = (
        db.scalar(
            select(func.count())
            .select_from(EndpointSnapshotSoftware)
            .where(EndpointSnapshotSoftware.snapshot_id == snap.id)
        )
        or 0
    )
    return SnapshotOut(
        id=snap.id,
        endpoint_id=snap.endpoint_id,
        collected_at=snap.collected_at,
        received_at=snap.received_at,
        agent_version=snap.agent_version,
        schema_version=snap.schema_version,
        package_count=package_count,
        fact_count=len(snap.facts or {}),
        has_hardware=snap.hardware is not None,
        has_network=snap.network is not None,
    )


def _apply_date_range(
    stmt: Select[Any],
    column: Any,  # InstrumentedAttribute or SQL expression
    date_from: datetime | None,
    date_to: datetime | None,
) -> Select[Any]:
    start = _parse_dt(date_from, name="from")
    if start is not None:
        stmt = stmt.where(column >= start)
    end = _parse_dt(date_to, name="to")
    if end is not None:
        stmt = stmt.where(column <= end)
    return stmt


def _validate_range(date_from: datetime | None, date_to: datetime | None) -> None:
    """Bound history queries: reject spans longer than one year and require
    a lower bound when an upper bound is given (prevents accidentally
    unbounded scans; narrow the window instead)."""
    start = _parse_dt(date_from, name="from")
    end = _parse_dt(date_to, name="to")
    if start is None and end is not None:
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Missing 'from'",
            "'from' is required when 'to' is provided.",
        )
    if start is None:
        return
    if end is None:
        end = datetime.now(UTC)
    if end < start:
        raise AppError(
            status.HTTP_400_BAD_REQUEST, "Invalid date range", "'to' precedes 'from'."
        )
    if (end - start).days > 366:
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Date range too large",
            "History queries are limited to 366 days per request.",
        )


@router.get("/endpoints/{endpoint_id}/snapshots", response_model=Page)
def list_snapshots(
    endpoint_id: uuid.UUID,
    db: DbSession,
    _: EndpointsRead,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
) -> Page:
    """Snapshot history for one endpoint (newest first).

    Always scoped to the path endpoint — another endpoint's snapshots are
    unreachable (cross-endpoint isolation is part of the WHERE clause).
    """
    _validate_range(date_from, date_to)
    endpoint = _get_endpoint(db, endpoint_id)
    stmt = select(EndpointSnapshot).where(
        EndpointSnapshot.endpoint_id == endpoint.id
    )
    count_stmt = (
        select(func.count())
        .select_from(EndpointSnapshot)
        .where(EndpointSnapshot.endpoint_id == endpoint.id)
    )
    stmt = _apply_date_range(stmt, EndpointSnapshot.received_at, date_from, date_to)
    count_stmt = _apply_date_range(
        count_stmt, EndpointSnapshot.received_at, date_from, date_to
    )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(EndpointSnapshot.received_at.desc(), EndpointSnapshot.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [_snapshot_out(db, s) for s in rows]
    return Page(items=items, total=total, page=page, page_size=page_size)


def _load_snapshot(
    db: Session, endpoint_id: uuid.UUID, snapshot_id: uuid.UUID
) -> EndpointSnapshot:
    snap = db.scalar(
        select(EndpointSnapshot).where(
            EndpointSnapshot.id == snapshot_id,
            EndpointSnapshot.endpoint_id == endpoint_id,
        )
    )
    if snap is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND, "Snapshot not found", str(snapshot_id)
        )
    return snap


def _snapshot_packages(
    db: Session, snapshot_id: uuid.UUID
) -> dict[tuple[str, str], str]:
    rows = db.execute(
        select(
            EndpointSnapshotSoftware.name,
            EndpointSnapshotSoftware.package_manager,
            EndpointSnapshotSoftware.version,
        ).where(EndpointSnapshotSoftware.snapshot_id == snapshot_id)
    ).all()
    return {(r.name, r.package_manager): r.version for r in rows}


def _compute_diff(
    db: Session, base: EndpointSnapshot, target: EndpointSnapshot
) -> SnapshotDiffOut:
    """Package + hardware differences from ``base`` → ``target``.

    Partial inventory is handled: a missing hardware section on either side
    yields no hardware changes (nothing to compare).
    """
    base_pkgs = _snapshot_packages(db, base.id)
    target_pkgs = _snapshot_packages(db, target.id)

    added = [
        SnapshotSoftwareOut(
            name=name, version=version, package_manager=manager
        )
        for (name, manager), version in sorted(target_pkgs.items())
        if (name, manager) not in base_pkgs
    ]
    removed = [
        SnapshotSoftwareOut(
            name=name, version=version, package_manager=manager
        )
        for (name, manager), version in sorted(base_pkgs.items())
        if (name, manager) not in target_pkgs
    ]
    changed = [
        SnapshotSoftwareOut(
            name=name,
            version=version,
            package_manager=manager,
            previous_version=base_pkgs[(name, manager)],
        )
        for (name, manager), version in sorted(target_pkgs.items())
        if (name, manager) in base_pkgs
        and base_pkgs[(name, manager)] != version
    ]

    hardware_changes: list[HardwareChangeOut] = []
    if base.hardware and target.hardware:
        for field_name in sorted(set(base.hardware) | set(target.hardware)):
            before = base.hardware.get(field_name)
            after = target.hardware.get(field_name)
            if before != after:
                hardware_changes.append(
                    HardwareChangeOut(field=field_name, before=before, after=after)
                )

    return SnapshotDiffOut(
        base_snapshot_id=base.id,
        target_snapshot_id=target.id,
        added_packages=added,
        removed_packages=removed,
        changed_packages=changed,
        hardware_changes=hardware_changes,
    )


@router.get(
    "/endpoints/{endpoint_id}/snapshots/{snapshot_id}",
    response_model=SnapshotDetailOut,
)
def get_snapshot(
    endpoint_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    db: DbSession,
    _: EndpointsRead,
    compare_to: uuid.UUID | None = None,
) -> SnapshotDetailOut:
    """Full snapshot payload; optional ``compare_to`` (base snapshot of the
    SAME endpoint) adds an inline diff (packages + hardware)."""
    snap = _load_snapshot(db, endpoint_id, snapshot_id)
    base = _snapshot_out(db, snap)
    package_rows = db.execute(
        select(
            EndpointSnapshotSoftware.name,
            EndpointSnapshotSoftware.version,
            EndpointSnapshotSoftware.package_manager,
        )
        .where(EndpointSnapshotSoftware.snapshot_id == snap.id)
        .order_by(EndpointSnapshotSoftware.name)
    ).all()
    changes = None
    if compare_to is not None:
        base_snap = _load_snapshot(db, endpoint_id, compare_to)
        changes = _compute_diff(db, base=base_snap, target=snap)
    return SnapshotDetailOut(
        **base.model_dump(),
        system=snap.system,
        hardware=snap.hardware,
        network=snap.network,
        filesystems=snap.filesystems or [],
        facts=snap.facts or {},
        packages=[
            SnapshotSoftwareOut(
                name=r.name, version=r.version, package_manager=r.package_manager
            )
            for r in package_rows
        ],
        changes=changes,
    )


@router.get("/endpoints/{endpoint_id}/software", response_model=Page)
def list_endpoint_software(
    endpoint_id: uuid.UUID,
    db: DbSession,
    _: EndpointsRead,
    view: str = Query("current", pattern="^(current|history)$"),
    name: Annotated[str | None, Query(max_length=255)] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
) -> Page:
    """Installed software for one endpoint.

    - ``view=current`` (default): live package table (detail page).
    - ``view=history``: package rows across snapshots, newest snapshot
      first (software inventory history); ``from``/``to`` filter on the
      snapshot's received time and require a bounded range.
    """
    _validate_range(date_from, date_to)
    endpoint = _get_endpoint(db, endpoint_id)

    if view == "current":
        stmt = select(EndpointSoftware).where(
            EndpointSoftware.endpoint_id == endpoint.id
        )
        count_stmt = (
            select(func.count())
            .select_from(EndpointSoftware)
            .where(EndpointSoftware.endpoint_id == endpoint.id)
        )
        if name:
            pattern = f"%{name}%"
            stmt = stmt.where(EndpointSoftware.name.ilike(pattern))
            count_stmt = count_stmt.where(EndpointSoftware.name.ilike(pattern))
        total = db.scalar(count_stmt) or 0
        rows = db.scalars(
            stmt.order_by(EndpointSoftware.name)
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        items = [
            {
                "name": r.name,
                "version": r.version,
                "package_manager": r.package_manager,
                "collected_at": r.collected_at,
            }
            for r in rows
        ]
        return Page(items=items, total=total, page=page, page_size=page_size)

    # history: join through snapshots (endpoint isolation in WHERE)
    hist_stmt = (
        select(EndpointSnapshotSoftware, EndpointSnapshot)
        .join(
            EndpointSnapshot,
            EndpointSnapshotSoftware.snapshot_id == EndpointSnapshot.id,
        )
        .where(EndpointSnapshot.endpoint_id == endpoint.id)
    )
    hist_count = (
        select(func.count())
        .select_from(EndpointSnapshotSoftware)
        .join(
            EndpointSnapshot,
            EndpointSnapshotSoftware.snapshot_id == EndpointSnapshot.id,
        )
        .where(EndpointSnapshot.endpoint_id == endpoint.id)
    )
    if name:
        pattern = f"%{name}%"
        hist_stmt = hist_stmt.where(EndpointSnapshotSoftware.name.ilike(pattern))
        hist_count = hist_count.where(EndpointSnapshotSoftware.name.ilike(pattern))
    hist_stmt = _apply_date_range(
        hist_stmt, EndpointSnapshot.received_at, date_from, date_to
    )
    hist_count = _apply_date_range(
        hist_count, EndpointSnapshot.received_at, date_from, date_to
    )
    total = db.scalar(hist_count) or 0
    hist_rows = db.execute(
        hist_stmt.order_by(
            EndpointSnapshot.received_at.desc(),
            EndpointSnapshotSoftware.name,
            EndpointSnapshotSoftware.package_manager,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [
        SoftwareHistoryOut(
            snapshot_id=snap.id,
            collected_at=snap.collected_at,
            name=pkg.name,
            version=pkg.version,
            package_manager=pkg.package_manager,
        ).model_dump()
        for pkg, snap in hist_rows
    ]
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/endpoints/{endpoint_id}/network", response_model=Page)
def list_endpoint_network(
    endpoint_id: uuid.UUID,
    db: DbSession,
    _: EndpointsRead,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
) -> Page:
    """Network inventory history (snapshots that reported a network section)."""
    _validate_range(date_from, date_to)
    endpoint = _get_endpoint(db, endpoint_id)
    stmt = select(EndpointSnapshot).where(
        EndpointSnapshot.endpoint_id == endpoint.id,
        EndpointSnapshot.network.is_not(None),
    )
    stmt = _apply_date_range(stmt, EndpointSnapshot.received_at, date_from, date_to)
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(EndpointSnapshot.received_at.desc(), EndpointSnapshot.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [
        NetworkHistoryOut(
            snapshot_id=s.id,
            collected_at=s.collected_at,
            network=s.network,
        )
        for s in rows
    ]
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.post(
    "/endpoints/{endpoint_id}/revoke",
    response_model=EndpointRevokeOut,
)
def revoke_endpoint_route(
    endpoint_id: uuid.UUID,
    request: Request,
    db: DbSession,
    admin: EndpointsWrite,
) -> EndpointRevokeOut:
    endpoint = _get_endpoint(db, endpoint_id)
    if endpoint.status == ENDPOINT_REVOKED:
        raise AppError(
            status.HTTP_409_CONFLICT, "Endpoint already revoked", str(endpoint_id)
        )
    revoked = revoke_endpoint(db, endpoint, request=request, actor=admin)
    return EndpointRevokeOut(id=endpoint.id, status=ENDPOINT_REVOKED, revoked_credentials=revoked)


@router.post(
    "/endpoints/{endpoint_id}/rotate-credential",
    response_model=CredentialRotateOut,
)
def rotate_endpoint_credential(
    endpoint_id: uuid.UUID,
    request: Request,
    db: DbSession,
    admin: EndpointsWrite,
) -> CredentialRotateOut:
    """Issue a fresh credential, revoking the previous one.

    The raw credential appears ONLY in this response (issuance); it is stored
    as a SHA-256 digest and is never retrievable again. The action is audited
    without the secret.
    """
    endpoint = _get_endpoint(db, endpoint_id)
    if endpoint.status != ENDPOINT_ACTIVE:
        raise AppError(
            status.HTTP_409_CONFLICT,
            "Endpoint not active",
            "Revoked endpoints cannot receive credentials.",
        )
    active = db.scalar(
        select(EndpointCredential)
        .where(
            EndpointCredential.endpoint_id == endpoint.id,
            EndpointCredential.revoked_at.is_(None),
        )
        .order_by(EndpointCredential.created_at.desc())
    )
    if active is None:
        raise AppError(
            status.HTTP_409_CONFLICT,
            "No active credential",
            "Re-enroll the endpoint instead.",
        )
    raw = rotate_credential(
        db, endpoint, active, request=request, actor_email=admin.email
    )
    return CredentialRotateOut(
        endpoint_id=endpoint.id,
        credential=raw,
        issued_at=datetime.now(UTC),
    )


__all__ = ["router"]
