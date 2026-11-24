"""Directory (read-only Active Directory) API (Phase 3.1, extended 3.2.2).

Route conventions (mirrors endpoints.py):
- ``Page`` + ``page/page_size/q/sort/order`` with per-resource sort
  allowlists; ``connection_id`` is REQUIRED on every object list and
  detail so results can never bleed across connections.
- Every route declares its permission (``directory:read|write|sync``);
  the ``agent`` role holds none of them.
- No response schema exposes the bind password or its ciphertext; LDAP
  filter construction goes through ``build_filter`` (escaped) — user
  input never reaches a filter raw.

Phase 3.2.2 adds the findings/health/correlation read APIs and the
manual finding lifecycle (ack/suppress/reopen): transition logic lives
in ``services.directory.insights`` (never in route handlers), audit
rows are appended only for successful state changes, and every query
is connection-scoped.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import DbSession, require_permissions
from app.core.exceptions import AppError
from app.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    ENDPOINT_REVOKED,
    FINDING_ACCESSES,
    FINDING_SEVERITIES,
    FINDING_STATUSES,
    FINDING_SUBJECT_TYPES,
    RECON_MANUAL,
    RECON_NEEDS_REVIEW,
    RECON_UNMATCHED,
    SYNC_FAILED,
    SYNC_RUNNING,
    SYNC_SUCCESS,
    SYNC_TRIGGER_MANUAL,
    DirectoryComputer,
    DirectoryConnection,
    DirectoryDomain,
    DirectoryFinding,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectoryOrganizationalUnit,
    DirectoryReconciliation,
    DirectorySyncRun,
    DirectoryUser,
    Endpoint,
    User,
)
from app.schemas.auth import Page
from app.schemas.directory import (
    ConnectionCreate,
    ConnectionOut,
    ConnectionSummaryOut,
    ConnectionTestOut,
    ConnectionUpdate,
    CorrelationGapOut,
    DirectoryComputerDetailOut,
    DirectoryComputerOut,
    DirectoryGroupDetailOut,
    DirectoryGroupOut,
    DirectoryHealthOut,
    DirectoryOverviewOut,
    DirectoryUserOut,
    DomainOut,
    FindingOut,
    FindingSummaryOut,
    GroupMemberOut,
    MatchDecisionIn,
    OrganizationalUnitDetailOut,
    OrganizationalUnitOut,
    ReconciliationOut,
    SyncFreshnessOut,
    SyncRunDetailOut,
    SyncRunHealthOut,
    SyncRunOut,
)
from app.services.auth_service import _record_audit
from app.services.directory import connection_service, insights
from app.services.directory.insights import RULE_KEYS

router = APIRouter(prefix="/directory", tags=["directory"])

DirectoryRead = Annotated[User, Depends(require_permissions("directory:read"))]
DirectoryWrite = Annotated[User, Depends(require_permissions("directory:write"))]
DirectorySyncPerm = Annotated[User, Depends(require_permissions("directory:sync"))]


def _enum_pattern(values: Any) -> str:
    """Regex from exact string values — query filters can never drift
    from the model constants they mirror."""
    return "^(?:" + "|".join(re.escape(v) for v in values) + ")$"


_SUBJECT_TYPE_PATTERN = _enum_pattern(FINDING_SUBJECT_TYPES)
_ACCESS_PATTERN = _enum_pattern(FINDING_ACCESSES)
_FINDING_STATUS_PATTERN = _enum_pattern(FINDING_STATUSES)
_SEVERITY_PATTERN = _enum_pattern(FINDING_SEVERITIES)
_RULE_KEY_PATTERN = _enum_pattern(RULE_KEYS)


def _connection_or_404(db: Session, connection_id: uuid.UUID) -> DirectoryConnection:
    row = db.get(DirectoryConnection, connection_id)
    if row is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND,
            "Connection not found",
            "The directory connection does not exist.",
        )
    return row


def _scoped_or_404(
    db: Session, model: Any, object_id: uuid.UUID, connection_id: uuid.UUID
) -> Any:
    row = db.scalar(
        select(model).where(model.id == object_id, model.connection_id == connection_id)
    )
    if row is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND,
            "Not found",
            "The requested directory object does not exist "
            "for this connection.",
        )
    return row


def _apply_sort(
    stmt: Any,
    *,
    sort: str,
    order: str,
    allowlist: dict[str, Any],
    tiebreak: Any,
) -> Any:
    if sort not in allowlist:
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "Invalid sort field",
            f"Allowed: {', '.join(sorted(allowlist))}",
        )
    column = allowlist[sort]
    direction = column.desc() if order == "desc" else column.asc()
    return stmt.order_by(direction, tiebreak)


def _page(
    db: Session,
    stmt: Any,
    count_stmt: Any,
    *,
    page: int,
    page_size: int,
    out: Any,
) -> Page:
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).all()
    return Page(
        items=[out.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


def _run_stats(
    db: Session, connection_ids: list[uuid.UUID]
) -> dict[uuid.UUID, dict[str, Any]]:
    """Last run + last success per connection in TWO aggregate queries."""
    stats: dict[uuid.UUID, dict[str, Any]] = {}
    if not connection_ids:
        return stats
    last_rows = db.execute(
        select(
            DirectorySyncRun.connection_id,
            DirectorySyncRun.status,
            DirectorySyncRun.started_at,
        )
        .where(DirectorySyncRun.connection_id.in_(connection_ids))
        .distinct(DirectorySyncRun.connection_id)
        .order_by(
            DirectorySyncRun.connection_id, DirectorySyncRun.started_at.desc()
        )
    ).all()
    for connection_id, run_status, started_at in last_rows:
        stats.setdefault(connection_id, {})["last_run_status"] = run_status
        stats[connection_id]["last_run_started_at"] = started_at
    success_rows = db.execute(
        select(
            DirectorySyncRun.connection_id,
            func.max(DirectorySyncRun.finished_at),
        )
        .where(
            DirectorySyncRun.connection_id.in_(connection_ids),
            DirectorySyncRun.status == SYNC_SUCCESS,
        )
        .group_by(DirectorySyncRun.connection_id)
    ).all()
    for connection_id, last_success in success_rows:
        stats.setdefault(connection_id, {})["last_success_at"] = last_success
    return stats


def _connection_out(db: Session, row: DirectoryConnection) -> ConnectionOut:
    out = ConnectionOut.model_validate(row)
    out.has_custom_ca = row.tls_ca_pem is not None
    stats = _run_stats(db, [row.id]).get(row.id, {})
    out.last_run_status = stats.get("last_run_status")
    out.last_run_started_at = stats.get("last_run_started_at")
    out.last_success_at = stats.get("last_success_at")
    return out


# --- Overview ----------------------------------------------------------------


@router.get("/overview", response_model=DirectoryOverviewOut)
def directory_overview(db: DbSession, _: DirectoryRead) -> DirectoryOverviewOut:
    """Dashboard KPIs from real aggregates (no cached or synthetic data)."""
    def count(model: Any, *criteria: Any) -> int:
        stmt = select(func.count()).select_from(model)
        if criteria:
            stmt = stmt.where(*criteria)
        return int(db.scalar(stmt) or 0)

    now = datetime.now(UTC)
    recon_rows = db.execute(
        select(
            DirectoryReconciliation.status, func.count(DirectoryReconciliation.id)
        ).group_by(DirectoryReconciliation.status)
    ).all()
    recon = {row_status: int(cnt) for row_status, cnt in recon_rows}
    last_success = db.scalar(
        select(func.max(DirectorySyncRun.finished_at)).where(
            DirectorySyncRun.status == SYNC_SUCCESS
        )
    )
    last_failure = db.scalar(
        select(func.max(DirectorySyncRun.finished_at)).where(
            DirectorySyncRun.status == SYNC_FAILED
        )
    )
    return DirectoryOverviewOut(
        domains=count(DirectoryDomain),
        users_total=count(DirectoryUser),
        users_enabled=count(DirectoryUser, DirectoryUser.enabled.is_(True)),
        users_disabled=count(DirectoryUser, DirectoryUser.enabled.is_(False)),
        groups=count(DirectoryGroup),
        computers=count(DirectoryComputer),
        missing_objects=(
            count(
                DirectoryOrganizationalUnit,
                DirectoryOrganizationalUnit.missing_since.is_not(None),
            )
            + count(DirectoryUser, DirectoryUser.missing_since.is_not(None))
            + count(DirectoryGroup, DirectoryGroup.missing_since.is_not(None))
            + count(DirectoryComputer, DirectoryComputer.missing_since.is_not(None))
        ),
        connections_total=count(DirectoryConnection),
        connections_enabled=count(
            DirectoryConnection, DirectoryConnection.enabled.is_(True)
        ),
        reconciliation_matched=recon.get("matched", 0),
        reconciliation_needs_review=recon.get("needs_review", 0),
        reconciliation_unmatched=recon.get("unmatched", 0),
        reconciliation_rejected=recon.get("rejected", 0),
        running_syncs=count(DirectorySyncRun, DirectorySyncRun.status == SYNC_RUNNING),
        failed_runs_24h=count(
            DirectorySyncRun,
            DirectorySyncRun.status == SYNC_FAILED,
            DirectorySyncRun.started_at >= now - timedelta(hours=24),
        ),
        last_sync_success_at=last_success,
        last_sync_failure_at=last_failure,
    )


# --- Connections -------------------------------------------------------------


_CONNECTION_SORTS = {
    "name": DirectoryConnection.name,
    "created_at": DirectoryConnection.created_at,
    "host": DirectoryConnection.host,
}


@router.get("/connections", response_model=Page)
def list_connections(
    db: DbSession,
    _: DirectoryRead,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: Annotated[str | None, Query(max_length=255)] = None,
    enabled: bool | None = None,
    sort: str = Query("name"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> Page:
    """Paginated connection list (never includes secrets or the CA PEM)."""
    stmt = select(DirectoryConnection)
    count_stmt = select(func.count()).select_from(DirectoryConnection)
    if q:
        pattern = f"%{q}%"
        criteria = or_(
            DirectoryConnection.name.ilike(pattern),
            DirectoryConnection.host.ilike(pattern),
            DirectoryConnection.domain_dns.ilike(pattern),
        )
        stmt = stmt.where(criteria)
        count_stmt = count_stmt.where(criteria)
    if enabled is not None:
        stmt = stmt.where(DirectoryConnection.enabled.is_(enabled))
        count_stmt = count_stmt.where(DirectoryConnection.enabled.is_(enabled))
    stmt = _apply_sort(
        stmt, sort=sort, order=order, allowlist=_CONNECTION_SORTS,
        tiebreak=DirectoryConnection.id,
    )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).all()
    stats = _run_stats(db, [row.id for row in rows])
    items: list[ConnectionSummaryOut] = []
    for row in rows:
        out = ConnectionSummaryOut.model_validate(row)
        out.has_custom_ca = row.tls_ca_pem is not None
        row_stats = stats.get(row.id, {})
        out.last_run_status = row_stats.get("last_run_status")
        out.last_run_started_at = row_stats.get("last_run_started_at")
        out.last_success_at = row_stats.get("last_success_at")
        items.append(out)
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.post(
    "/connections",
    response_model=ConnectionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_connection(
    db: DbSession,
    request: Request,
    payload: ConnectionCreate,
    actor: DirectoryWrite,
) -> ConnectionOut:
    row = connection_service.create_connection(
        db, payload, actor=actor, request=request
    )
    return _connection_out(db, row)


@router.get("/connections/{connection_id}", response_model=ConnectionOut)
def get_connection(
    db: DbSession,
    connection_id: uuid.UUID,
    _: DirectoryRead,
) -> ConnectionOut:
    row = _connection_or_404(db, connection_id)
    return _connection_out(db, row)


@router.patch("/connections/{connection_id}", response_model=ConnectionOut)
def update_connection(
    db: DbSession,
    request: Request,
    connection_id: uuid.UUID,
    payload: ConnectionUpdate,
    actor: DirectoryWrite,
) -> ConnectionOut:
    row = _connection_or_404(db, connection_id)
    connection_service.update_connection(
        db, row, payload, actor=actor, request=request
    )
    return _connection_out(db, row)


@router.delete(
    "/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_connection(
    db: DbSession,
    request: Request,
    connection_id: uuid.UUID,
    actor: DirectoryWrite,
) -> None:
    row = _connection_or_404(db, connection_id)
    connection_service.delete_connection(db, row, actor=actor, request=request)


@router.post("/connections/{connection_id}/test", response_model=ConnectionTestOut)
def test_connection(
    db: DbSession,
    request: Request,
    connection_id: uuid.UUID,
    actor: DirectorySyncPerm,
) -> ConnectionTestOut:
    """TLS probe + bind + rootDSE + search-base check (sanitized result)."""
    row = _connection_or_404(db, connection_id)
    result = connection_service.test_connection(
        db, row, actor=actor, request=request
    )
    return ConnectionTestOut(**result)


@router.post(
    "/connections/{connection_id}/sync",
    response_model=SyncRunOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_sync(
    db: DbSession,
    request: Request,
    connection_id: uuid.UUID,
    actor: DirectorySyncPerm,
) -> SyncRunOut:
    """Enqueue a manual sync. 409 when one is already running."""
    row = _connection_or_404(db, connection_id)
    run = connection_service.trigger_sync(
        db, row, trigger=SYNC_TRIGGER_MANUAL, actor=actor, request=request
    )
    return SyncRunOut.model_validate(run)


# --- Domains -----------------------------------------------------------------


@router.get("/domains", response_model=Page)
def list_domains(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("domain_dns"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> Page:
    _connection_or_404(db, connection_id)
    stmt = select(DirectoryDomain).where(
        DirectoryDomain.connection_id == connection_id
    )
    count_stmt = select(func.count()).select_from(DirectoryDomain).where(
        DirectoryDomain.connection_id == connection_id
    )
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "domain_dns": DirectoryDomain.domain_dns,
            "last_synced_at": DirectoryDomain.last_synced_at,
            "last_seen_at": DirectoryDomain.last_seen_at,
        },
        tiebreak=DirectoryDomain.id,
    )
    return _page(
        db, stmt, count_stmt, page=page, page_size=page_size, out=DomainOut
    )


# --- Organizational units ----------------------------------------------------


@router.get("/ous", response_model=Page)
def list_ous(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    q: Annotated[str | None, Query(max_length=255)] = None,
    parent_dn: Annotated[str | None, Query(max_length=1024)] = None,
    include_missing: bool = False,
    sort: str = Query("name"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> Page:
    """OU list; ``parent_dn`` narrows to one tree level for the UI."""
    _connection_or_404(db, connection_id)
    criteria = [DirectoryOrganizationalUnit.connection_id == connection_id]
    if not include_missing:
        criteria.append(DirectoryOrganizationalUnit.missing_since.is_(None))
    if q:
        pattern = f"%{q}%"
        criteria.append(
            or_(
                DirectoryOrganizationalUnit.name.ilike(pattern),
                DirectoryOrganizationalUnit.distinguished_name.ilike(pattern),
            )
        )
    if parent_dn is not None:
        criteria.append(DirectoryOrganizationalUnit.parent_dn == parent_dn)
    stmt = select(DirectoryOrganizationalUnit).where(*criteria)
    count_stmt = select(func.count()).select_from(
        DirectoryOrganizationalUnit
    ).where(*criteria)
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "name": DirectoryOrganizationalUnit.name,
            "distinguished_name": DirectoryOrganizationalUnit.distinguished_name,
            "last_seen_at": DirectoryOrganizationalUnit.last_seen_at,
        },
        tiebreak=DirectoryOrganizationalUnit.id,
    )
    return _page(
        db, stmt, count_stmt, page=page, page_size=page_size,
        out=OrganizationalUnitOut,
    )


@router.get("/ous/{ou_id}", response_model=OrganizationalUnitDetailOut)
def get_ou(
    db: DbSession,
    ou_id: uuid.UUID,
    _: DirectoryRead,
    connection_id: uuid.UUID,
) -> OrganizationalUnitDetailOut:
    row = _scoped_or_404(
        db, DirectoryOrganizationalUnit, ou_id, connection_id
    )
    out = OrganizationalUnitDetailOut.model_validate(row)

    def in_ou(model: Any) -> Any:
        # Direct children only: DN ends with ",<ou_dn>" AND carries exactly
        # one RDN more than the OU itself (no deep descendants).
        commas = row.distinguished_name.count(",")
        return and_(
            model.distinguished_name.endswith(
                f",{row.distinguished_name}", autoescape=True
            ),
            func.length(model.distinguished_name)
            - func.length(func.replace(model.distinguished_name, ",", ""))
            == commas + 1,
        )

    def count(model: Any) -> int:
        return int(
            db.scalar(
                select(func.count())
                .select_from(model)
                .where(model.connection_id == connection_id, in_ou(model))
            )
            or 0
        )

    out.child_ous = count(DirectoryOrganizationalUnit)
    out.users = count(DirectoryUser)
    out.groups = count(DirectoryGroup)
    out.computers = count(DirectoryComputer)
    return out


# --- Users -------------------------------------------------------------------


@router.get("/users", response_model=Page)
def list_users(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: Annotated[str | None, Query(max_length=255)] = None,
    enabled: bool | None = None,
    include_missing: bool = False,
    sort: str = Query("sam_account_name"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> Page:
    _connection_or_404(db, connection_id)
    criteria = [DirectoryUser.connection_id == connection_id]
    if not include_missing:
        criteria.append(DirectoryUser.missing_since.is_(None))
    if enabled is not None:
        criteria.append(DirectoryUser.enabled.is_(enabled))
    if q:
        pattern = f"%{q}%"
        criteria.append(
            or_(
                DirectoryUser.sam_account_name.ilike(pattern),
                DirectoryUser.display_name.ilike(pattern),
                DirectoryUser.user_principal_name.ilike(pattern),
                DirectoryUser.email.ilike(pattern),
            )
        )
    stmt = select(DirectoryUser).where(*criteria)
    count_stmt = select(func.count()).select_from(DirectoryUser).where(*criteria)
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "sam_account_name": DirectoryUser.sam_account_name,
            "display_name": DirectoryUser.display_name,
            "email": DirectoryUser.email,
            "last_logon_at": DirectoryUser.last_logon_at,
            "ad_created_at": DirectoryUser.ad_created_at,
            "distinguished_name": DirectoryUser.distinguished_name,
        },
        tiebreak=DirectoryUser.id,
    )
    return _page(db, stmt, count_stmt, page=page, page_size=page_size, out=DirectoryUserOut)


@router.get("/users/{user_id}", response_model=DirectoryUserOut)
def get_user(
    db: DbSession,
    user_id: uuid.UUID,
    _: DirectoryRead,
    connection_id: uuid.UUID,
) -> DirectoryUserOut:
    row = _scoped_or_404(db, DirectoryUser, user_id, connection_id)
    return DirectoryUserOut.model_validate(row)


# --- Groups ------------------------------------------------------------------


@router.get("/groups", response_model=Page)
def list_groups(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: Annotated[str | None, Query(max_length=255)] = None,
    scope: Annotated[
        str | None, Query(pattern="^(global|domain_local|universal)$")
    ] = None,
    category: Annotated[str | None, Query(pattern="^(security|distribution)$")] = None,
    include_missing: bool = False,
    sort: str = Query("name"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> Page:
    _connection_or_404(db, connection_id)
    criteria = [DirectoryGroup.connection_id == connection_id]
    if not include_missing:
        criteria.append(DirectoryGroup.missing_since.is_(None))
    if scope is not None:
        criteria.append(DirectoryGroup.scope == scope)
    if category is not None:
        criteria.append(DirectoryGroup.category == category)
    if q:
        pattern = f"%{q}%"
        criteria.append(
            or_(
                DirectoryGroup.name.ilike(pattern),
                DirectoryGroup.description.ilike(pattern),
            )
        )
    stmt = select(DirectoryGroup).where(*criteria)
    count_stmt = select(func.count()).select_from(DirectoryGroup).where(*criteria)
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "name": DirectoryGroup.name,
            "last_seen_at": DirectoryGroup.last_seen_at,
            "scope": DirectoryGroup.scope,
            "category": DirectoryGroup.category,
        },
        tiebreak=DirectoryGroup.id,
    )
    return _page(db, stmt, count_stmt, page=page, page_size=page_size, out=DirectoryGroupOut)


@router.get("/groups/{group_id}", response_model=DirectoryGroupDetailOut)
def get_group(
    db: DbSession,
    group_id: uuid.UUID,
    _: DirectoryRead,
    connection_id: uuid.UUID,
) -> DirectoryGroupDetailOut:
    row = _scoped_or_404(db, DirectoryGroup, group_id, connection_id)
    out = DirectoryGroupDetailOut.model_validate(row)
    out.member_count = int(
        db.scalar(
            select(func.count())
            .select_from(DirectoryGroupMembership)
            .where(DirectoryGroupMembership.group_id == row.id)
        )
        or 0
    )
    return out


@router.get("/groups/{group_id}/members", response_model=Page)
def list_group_members(
    db: DbSession,
    group_id: uuid.UUID,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> Page:
    """Members of one group; the PAGE's members are resolved in three
    batched queries (never one query per member)."""
    group = _scoped_or_404(db, DirectoryGroup, group_id, connection_id)
    stmt = (
        select(DirectoryGroupMembership)
        .where(DirectoryGroupMembership.group_id == group.id)
        .order_by(DirectoryGroupMembership.member_dn, DirectoryGroupMembership.id)
    )
    count_stmt = (
        select(func.count())
        .select_from(DirectoryGroupMembership)
        .where(DirectoryGroupMembership.group_id == group.id)
    )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).all()

    # Batch-resolve this page against the local mirror.
    dns = [row.member_dn for row in rows]
    resolved: dict[str, tuple[uuid.UUID, str, str]] = {}
    if dns:
        for model, member_type, name_col in (
            (DirectoryUser, "user", DirectoryUser.sam_account_name),
            (DirectoryGroup, "group", DirectoryGroup.name),
            (DirectoryComputer, "computer", DirectoryComputer.name),
        ):
            matches = db.execute(
                select(model.id, model.distinguished_name, name_col).where(
                    model.connection_id == connection_id,
                    model.distinguished_name.in_(dns),
                )
            ).all()
            for local_id, dn, display in matches:
                resolved[dn] = (local_id, member_type, display)

    items: list[GroupMemberOut] = []
    for row in rows:
        hit = resolved.get(row.member_dn)
        items.append(
            GroupMemberOut(
                member_type=row.member_type,
                member_dn=row.member_dn,
                member_object_guid=row.member_object_guid,
                resolved=hit is not None and hit[1] == row.member_type,
                local_id=hit[0] if hit and hit[1] == row.member_type else None,
                display_name=hit[2] if hit and hit[1] == row.member_type else None,
            )
        )
    return Page(items=items, total=total, page=page, page_size=page_size)


# --- Computers ----------------------------------------------------------------


@router.get("/computers", response_model=Page)
def list_computers(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: Annotated[str | None, Query(max_length=255)] = None,
    recon_status: Annotated[
        str | None, Query(pattern="^(matched|needs_review|unmatched|rejected)$")
    ] = None,
    include_missing: bool = False,
    sort: str = Query("name"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> Page:
    """Computer list with reconciliation status (one batch join, no N+1)."""
    _connection_or_404(db, connection_id)
    criteria = [DirectoryComputer.connection_id == connection_id]
    if not include_missing:
        criteria.append(DirectoryComputer.missing_since.is_(None))
    if q:
        pattern = f"%{q}%"
        criteria.append(
            or_(
                DirectoryComputer.name.ilike(pattern),
                DirectoryComputer.dns_hostname.ilike(pattern),
                DirectoryComputer.os.ilike(pattern),
            )
        )
    stmt = select(DirectoryComputer).where(*criteria)
    count_stmt = select(func.count()).select_from(DirectoryComputer).where(
        *criteria
    )
    if recon_status is not None:
        stmt = stmt.where(
            DirectoryComputer.id.in_(
                select(DirectoryReconciliation.computer_id).where(
                    DirectoryReconciliation.connection_id == connection_id,
                    DirectoryReconciliation.status == recon_status,
                )
            )
        )
        count_stmt = count_stmt.where(
            DirectoryComputer.id.in_(
                select(DirectoryReconciliation.computer_id).where(
                    DirectoryReconciliation.connection_id == connection_id,
                    DirectoryReconciliation.status == recon_status,
                )
            )
        )
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "name": DirectoryComputer.name,
            "dns_hostname": DirectoryComputer.dns_hostname,
            "os": DirectoryComputer.os,
            "last_logon_at": DirectoryComputer.last_logon_at,
            "ad_changed_at": DirectoryComputer.ad_changed_at,
        },
        tiebreak=DirectoryComputer.id,
    )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).all()

    recon_by_computer: dict[uuid.UUID, DirectoryReconciliation] = {}
    if rows:
        recon_rows = db.scalars(
            select(DirectoryReconciliation).where(
                DirectoryReconciliation.computer_id.in_([r.id for r in rows])
            )
        ).all()
        recon_by_computer = {r.computer_id: r for r in recon_rows}

    items: list[DirectoryComputerOut] = []
    for row in rows:
        out = DirectoryComputerOut.model_validate(row)
        recon = recon_by_computer.get(row.id)
        if recon is not None:
            out.recon_status = recon.status
            out.recon_method = recon.method
            out.recon_confidence = recon.confidence
            out.recon_endpoint_id = recon.endpoint_id
        items.append(out)
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/computers/{computer_id}", response_model=DirectoryComputerDetailOut)
def get_computer(
    db: DbSession,
    computer_id: uuid.UUID,
    _: DirectoryRead,
    connection_id: uuid.UUID,
) -> DirectoryComputerDetailOut:
    row = _scoped_or_404(db, DirectoryComputer, computer_id, connection_id)
    out = DirectoryComputerDetailOut.model_validate(row)
    recon = db.scalar(
        select(DirectoryReconciliation).where(
            DirectoryReconciliation.computer_id == row.id
        )
    )
    if recon is not None:
        out.recon_status = recon.status
        out.recon_method = recon.method
        out.recon_confidence = recon.confidence
        out.recon_endpoint_id = recon.endpoint_id
        out.recon_candidates = [uuid.UUID(str(c)) for c in (recon.candidates or [])]
        out.recon_reviewed_at = recon.reviewed_at
    return out


# --- Reconciliation ----------------------------------------------------------


@router.get("/reconciliations", response_model=Page)
def list_reconciliations(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID | None = None,
    status_filter: Annotated[
        str | None, Query(alias="status", pattern="^(matched|needs_review|unmatched|rejected)$")
    ] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("updated_at"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> Page:
    """Reconciliation queue with display names resolved in-batch."""
    criteria = []
    if connection_id is not None:
        criteria.append(DirectoryReconciliation.connection_id == connection_id)
    if status_filter is not None:
        criteria.append(DirectoryReconciliation.status == status_filter)
    stmt = select(DirectoryReconciliation)
    count_stmt = select(func.count()).select_from(DirectoryReconciliation)
    if criteria:
        stmt = stmt.where(*criteria)
        count_stmt = count_stmt.where(*criteria)
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "status": DirectoryReconciliation.status,
            "updated_at": DirectoryReconciliation.updated_at,
            "confidence": DirectoryReconciliation.confidence,
        },
        tiebreak=DirectoryReconciliation.id,
    )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).all()

    computer_ids = [r.computer_id for r in rows]
    endpoint_ids = [r.endpoint_id for r in rows if r.endpoint_id is not None]
    computer_names: dict[uuid.UUID, str] = {}
    if computer_ids:
        computer_names = {
            row_id: name
            for row_id, name in db.execute(
                select(DirectoryComputer.id, DirectoryComputer.name).where(
                    DirectoryComputer.id.in_(computer_ids)
                )
            ).all()
        }
    endpoint_names: dict[uuid.UUID, str] = {}
    if endpoint_ids:
        endpoint_names = {
            row_id: hostname
            for row_id, hostname in db.execute(
                select(Endpoint.id, Endpoint.hostname).where(
                    Endpoint.id.in_(endpoint_ids)
                )
            ).all()
        }
    items: list[ReconciliationOut] = []
    for row in rows:
        out = ReconciliationOut.model_validate(row)
        out.computer_name = computer_names.get(row.computer_id)
        out.endpoint_hostname = (
            endpoint_names.get(row.endpoint_id) if row.endpoint_id else None
        )
        items.append(out)
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.post(
    "/computers/{computer_id}/match",
    response_model=ReconciliationOut,
    status_code=status.HTTP_201_CREATED,
)
def decide_match(
    db: DbSession,
    request: Request,
    computer_id: uuid.UUID,
    payload: MatchDecisionIn,
    actor: DirectoryWrite,
) -> ReconciliationOut:
    """Manual match/reject decision — audited, never overwritten by syncs."""
    computer = db.get(DirectoryComputer, computer_id)
    if computer is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND,
            "Not found",
            "The requested directory object does not exist.",
        )
    if payload.decision == "match":
        if payload.endpoint_id is None:
            raise AppError(
                status.HTTP_400_BAD_REQUEST,
                "endpoint_id required",
                "A confirmed match requires an explicit endpoint id.",
            )
        endpoint = db.get(Endpoint, payload.endpoint_id)
        if endpoint is None:
            raise AppError(
                status.HTTP_404_NOT_FOUND,
                "Endpoint not found",
                "The endpoint does not exist.",
            )
        if endpoint.status == ENDPOINT_REVOKED:
            raise AppError(
                status.HTTP_400_BAD_REQUEST,
                "Endpoint revoked",
                "Revoked endpoints cannot be matched.",
            )
        new_status = "matched"
        endpoint_id: uuid.UUID | None = endpoint.id
        confidence = CONFIDENCE_HIGH
    else:
        new_status = "rejected"
        endpoint_id = None
        confidence = CONFIDENCE_LOW

    recon = db.scalar(
        select(DirectoryReconciliation).where(
            DirectoryReconciliation.computer_id == computer.id
        )
    )
    if recon is None:
        recon = DirectoryReconciliation(
            connection_id=computer.connection_id,
            computer_id=computer.id,
            endpoint_id=endpoint_id,
            method=RECON_MANUAL,
            confidence=confidence,
            status=new_status,
        )
        db.add(recon)
    else:
        recon.method = RECON_MANUAL
        recon.confidence = confidence
        recon.status = new_status
        recon.endpoint_id = endpoint_id
    recon.reviewed_by = actor.id
    recon.reviewed_at = datetime.now(UTC)
    db.flush()

    _record_audit(
        db,
        event_type="directory.reconciliation.decided",
        outcome="success",
        request=request,
        actor=actor,
        target=str(computer.id),
        detail={
            "computer": computer.name,
            "decision": payload.decision,
            "endpoint_id": str(endpoint_id) if endpoint_id else None,
        },
    )
    out = ReconciliationOut.model_validate(recon)
    out.computer_name = computer.name
    matched_endpoint = db.get(Endpoint, endpoint_id) if endpoint_id else None
    out.endpoint_hostname = matched_endpoint.hostname if matched_endpoint else None
    return out


# --- Sync history -------------------------------------------------------------


@router.get("/sync-runs", response_model=Page)
def list_sync_runs(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID | None = None,
    run_status: Annotated[
        str | None, Query(alias="status", pattern="^(running|success|failed)$")
    ] = None,
    trigger: Annotated[str | None, Query(pattern="^(manual|scheduled)$")] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("started_at"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> Page:
    criteria = []
    if connection_id is not None:
        criteria.append(DirectorySyncRun.connection_id == connection_id)
    if run_status is not None:
        criteria.append(DirectorySyncRun.status == run_status)
    if trigger is not None:
        criteria.append(DirectorySyncRun.trigger == trigger)
    stmt = select(DirectorySyncRun)
    count_stmt = select(func.count()).select_from(DirectorySyncRun)
    if criteria:
        stmt = stmt.where(*criteria)
        count_stmt = count_stmt.where(*criteria)
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "started_at": DirectorySyncRun.started_at,
            "duration_ms": DirectorySyncRun.duration_ms,
            "status": DirectorySyncRun.status,
        },
        tiebreak=DirectorySyncRun.id,
    )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).all()
    return Page(
        items=[SyncRunOut.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/sync-runs/{run_id}", response_model=SyncRunDetailOut)
def get_sync_run(
    db: DbSession,
    run_id: uuid.UUID,
    _: DirectoryRead,
) -> SyncRunDetailOut:
    row = db.get(DirectorySyncRun, run_id)
    if row is None:
        raise AppError(
            status.HTTP_404_NOT_FOUND,
            "Sync run not found",
            "The sync run does not exist.",
        )
    return SyncRunDetailOut.model_validate(row)


# --- Findings (Phase 3.2.2) ---------------------------------------------------


_FINDING_SORTS = {
    "first_seen_at": DirectoryFinding.first_seen_at,
    "last_seen_at": DirectoryFinding.last_seen_at,
    "updated_at": DirectoryFinding.updated_at,
    "severity": DirectoryFinding.severity,
    "status": DirectoryFinding.status,
    "rule_key": DirectoryFinding.rule_key,
}


@router.get("/findings", response_model=Page)
def list_findings(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    subject_type: Annotated[
        str | None, Query(pattern=_SUBJECT_TYPE_PATTERN)
    ] = None,
    access: Annotated[str | None, Query(pattern=_ACCESS_PATTERN)] = None,
    finding_status: Annotated[
        str | None, Query(alias="status", pattern=_FINDING_STATUS_PATTERN)
    ] = None,
    severity: Annotated[str | None, Query(pattern=_SEVERITY_PATTERN)] = None,
    rule_key: Annotated[str | None, Query(pattern=_RULE_KEY_PATTERN)] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("updated_at"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> Page:
    """Findings across connections with enum-safe filters.

    Every filter value is validated against the model constants via a
    pattern derived from them (``_SUBJECT_TYPE_PATTERN`` et al.), so the
    API can never accept a status/severity the DB CHECK would reject.
    """
    _connection_or_404(db, connection_id)
    criteria = [DirectoryFinding.connection_id == connection_id]
    if subject_type is not None:
        criteria.append(DirectoryFinding.subject_type == subject_type)
    if access is not None:
        criteria.append(DirectoryFinding.access == access)
    if finding_status is not None:
        criteria.append(DirectoryFinding.status == finding_status)
    if severity is not None:
        criteria.append(DirectoryFinding.severity == severity)
    if rule_key is not None:
        criteria.append(DirectoryFinding.rule_key == rule_key)
    stmt = select(DirectoryFinding)
    count_stmt = select(func.count()).select_from(DirectoryFinding)
    if criteria:
        stmt = stmt.where(*criteria)
        count_stmt = count_stmt.where(*criteria)
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist=_FINDING_SORTS,
        tiebreak=DirectoryFinding.id,
    )
    return _page(
        db, stmt, count_stmt,
        page=page, page_size=page_size, out=FindingOut,
    )


@router.get("/findings/summary", response_model=FindingSummaryOut)
def findings_summary(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
) -> FindingSummaryOut:
    """Counts by status/severity/rule/subject + visibility verdict.

    ``connection_id`` is required: the visibility verdict is a
    connection-level fact, never a cross-connection rollup.
    """
    _connection_or_404(db, connection_id)
    return FindingSummaryOut.model_validate(
        insights.findings_summary(db, connection_id)
    )


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    db: DbSession,
    finding_id: uuid.UUID,
    _: DirectoryRead,
    connection_id: uuid.UUID,
) -> FindingOut:
    """Full evidence for one finding, scoped to ``connection_id``.

    A finding id belonging to another connection answers 404 — ids are
    never accepted across connections.
    """
    row = _scoped_or_404(db, DirectoryFinding, finding_id, connection_id)
    return FindingOut.model_validate(row)


def _transition(
    db: Session,
    request: Request,
    actor: User,
    finding_id: uuid.UUID,
    connection_id: uuid.UUID,
    action: str,
) -> FindingOut:
    """Shared lifecycle handler: scope-check, transition, return fresh row.

    Transition rules live in ``services.directory.insights`` (never in
    route handlers); an illegal transition raises ``AppError(400)``
    BEFORE any mutation, so the request session rolls back with zero
    writes and zero audit rows.
    """
    row = _scoped_or_404(db, DirectoryFinding, finding_id, connection_id)
    if action == "ack":
        row = insights.acknowledge_finding(db, row, actor=actor, request=request)
    elif action == "suppress":
        row = insights.suppress_finding(db, row, actor=actor, request=request)
    else:
        row = insights.reopen_finding(db, row, actor=actor, request=request)
    db.flush()
    return FindingOut.model_validate(row)


@router.post("/findings/{finding_id}/ack", response_model=FindingOut)
def ack_finding(
    db: DbSession,
    request: Request,
    finding_id: uuid.UUID,
    payload_connection_id: Annotated[uuid.UUID, Query(alias="connection_id")],
    actor: DirectoryWrite,
) -> FindingOut:
    """``open -> acknowledged`` (idempotent; suppressed/resolved → 400)."""
    return _transition(
        db, request, actor, finding_id, payload_connection_id, "ack"
    )


@router.post("/findings/{finding_id}/suppress", response_model=FindingOut)
def suppress_finding(
    db: DbSession,
    request: Request,
    finding_id: uuid.UUID,
    payload_connection_id: Annotated[uuid.UUID, Query(alias="connection_id")],
    actor: DirectoryWrite,
) -> FindingOut:
    """``open|acknowledged -> suppressed`` (terminal for recomputation)."""
    return _transition(
        db, request, actor, finding_id, payload_connection_id, "suppress"
    )


@router.post("/findings/{finding_id}/reopen", response_model=FindingOut)
def reopen_finding(
    db: DbSession,
    request: Request,
    finding_id: uuid.UUID,
    payload_connection_id: Annotated[uuid.UUID, Query(alias="connection_id")],
    actor: DirectoryWrite,
) -> FindingOut:
    """Back to ``open`` from resolved/suppressed/acknowledged."""
    return _transition(
        db, request, actor, finding_id, payload_connection_id, "reopen"
    )


# --- Directory health (Phase 3.2.2) --------------------------------------------


@router.get("/health", response_model=DirectoryHealthOut)
def directory_health(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
) -> DirectoryHealthOut:
    """Health of one directory connection.

    The newest run is reported REGARDLESS of status (an older success
    never backfills a newer failure); missing run ⇒ incomplete
    inventory with all nine PIPELINE categories listed as missing.
    Visibility comes from ``insights.privilege_visibility`` — the same
    function the engine uses, never a second implementation.
    """
    _connection_or_404(db, connection_id)
    newest = insights.newest_sync_run(db, connection_id)
    visibility = insights.privilege_visibility(db, connection_id)

    if newest is None:
        missing = list(insights.INVENTORY_CATEGORIES)
        run_out: SyncRunHealthOut | None = None
    else:
        missing = (
            []
            if visibility["inventory_complete"]
            else insights.missing_categories(newest.category_results)
        )
        run_out = SyncRunHealthOut(
            id=newest.id,
            status=newest.status,
            trigger=newest.trigger,
            started_at=newest.started_at,
            finished_at=newest.finished_at,
            duration_ms=newest.duration_ms,
            category_results=(
                newest.category_results
                if isinstance(newest.category_results, dict)
                else {}
            ),
        )

    connection = db.get(DirectoryConnection, connection_id)
    assert connection is not None  # _connection_or_404 above
    last_success = db.scalar(
        select(func.max(DirectorySyncRun.finished_at)).where(
            DirectorySyncRun.connection_id == connection_id,
            DirectorySyncRun.status == SYNC_SUCCESS,
        )
    )
    interval = connection.sync_interval_minutes
    sync_overdue = last_success is None or (
        datetime.now(UTC) - last_success > timedelta(minutes=interval)
    )

    return DirectoryHealthOut(
        connection_id=connection_id,
        inventory_complete=bool(visibility["inventory_complete"]),
        missing_categories=missing,
        newest_run=run_out,
        privilege_visibility=visibility["privilege_visibility"],
        visibility_reasons=visibility["visibility_reasons"],
        findings=FindingSummaryOut.model_validate(
            insights.findings_summary(db, connection_id)
        ),
        sync_freshness=SyncFreshnessOut(
            last_success_at=last_success,
            newest_run_started_at=newest.started_at if newest else None,
            sync_interval_minutes=interval,
            sync_overdue=sync_overdue,
        ),
    )


# --- Correlation gaps (Phase 3.2.2) --------------------------------------------


@router.get("/correlation/gaps", response_model=Page)
def correlation_gaps(
    db: DbSession,
    _: DirectoryRead,
    connection_id: uuid.UUID,
    gap_type: Annotated[
        str | None,
        Query(pattern="^(never_reconciled|unmatched|ambiguous)$"),
    ] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("name"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> Page:
    """AD computers without a resolved endpoint correlation.

    Gap = no reconciliation row (``never_reconciled``), an ``unmatched``
    row with no endpoint, or an ambiguous ``needs_review`` row. Matched
    and manually ``rejected`` rows are deliberate decisions and are NOT
    gaps.
    """
    _connection_or_404(db, connection_id)
    gap_criteria = [
        DirectoryComputer.connection_id == connection_id,
        or_(
            DirectoryReconciliation.id.is_(None),
            DirectoryReconciliation.status == RECON_UNMATCHED,
            DirectoryReconciliation.status == RECON_NEEDS_REVIEW,
        ),
    ]
    if gap_type == "never_reconciled":
        gap_criteria.append(DirectoryReconciliation.id.is_(None))
    elif gap_type == "unmatched":
        gap_criteria.append(
            DirectoryReconciliation.status == RECON_UNMATCHED
        )
    elif gap_type == "ambiguous":
        gap_criteria.append(
            DirectoryReconciliation.status == RECON_NEEDS_REVIEW
        )

    stmt = (
        select(DirectoryComputer)
        .outerjoin(
            DirectoryReconciliation,
            DirectoryReconciliation.computer_id == DirectoryComputer.id,
        )
        .where(*gap_criteria)
    )
    count_stmt = (
        select(func.count())
        .select_from(DirectoryComputer)
        .outerjoin(
            DirectoryReconciliation,
            DirectoryReconciliation.computer_id == DirectoryComputer.id,
        )
        .where(*gap_criteria)
    )
    stmt = _apply_sort(
        stmt, sort=sort, order=order,
        allowlist={
            "name": DirectoryComputer.name,
            "last_seen_at": DirectoryComputer.last_seen_at,
        },
        tiebreak=DirectoryComputer.id,
    )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).all()

    recons = {
        r.computer_id: r
        for r in db.scalars(
            select(DirectoryReconciliation).where(
                DirectoryReconciliation.computer_id.in_(
                    [c.id for c in rows] or [uuid.UUID(int=0)]
                )
            )
        ).all()
    }
    items: list[CorrelationGapOut] = []
    for computer in rows:
        recon = recons.get(computer.id)
        if recon is None:
            gap = "never_reconciled"
            raw_candidates: list = []
        else:
            gap = (
                "ambiguous"
                if recon.status == RECON_NEEDS_REVIEW
                else "unmatched"
            )
            raw_candidates = recon.candidates or []
        items.append(
            CorrelationGapOut(
                computer_id=computer.id,
                computer_name=computer.name,
                dns_hostname=computer.dns_hostname,
                distinguished_name=computer.distinguished_name,
                object_guid=computer.object_guid,
                gap_type=gap,
                recon_status=recon.status if recon else None,
                recon_method=recon.method if recon else None,
                recon_confidence=recon.confidence if recon else None,
                candidates=[uuid.UUID(str(c)) for c in raw_candidates],
                reviewed_at=recon.reviewed_at if recon else None,
            )
        )
    return Page(items=items, total=total, page=page, page_size=page_size)
