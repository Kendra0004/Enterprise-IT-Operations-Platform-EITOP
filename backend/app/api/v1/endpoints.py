"""Endpoint administration: enrollment tokens, listing, groups, revocation.

RBAC: ``endpoints:read`` for reads, ``endpoints:write`` for mutations.
No response ever contains agent credential material (rotation is the sole
issuance moment and returns the new secret exactly once).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DbSession, require_permissions
from app.core.exceptions import AppError
from app.models import (
    ENDPOINT_ACTIVE,
    ENDPOINT_REVOKED,
    Endpoint,
    EndpointCredential,
    EndpointFact,
    EndpointGroup,
    EndpointSoftware,
    EnrollmentToken,
    User,
)
from app.schemas.auth import Page
from app.schemas.endpoints import (
    CredentialRotateOut,
    EndpointDetailOut,
    EndpointOut,
    EndpointRevokeOut,
    EnrollmentTokenCreate,
    EnrollmentTokenCreatedOut,
    EnrollmentTokenOut,
    FactOut,
    GroupCreate,
    GroupOut,
    MetadataOut,
)
from app.services.auth_service import _record_audit
from app.services.endpoint_service import (
    create_enrollment_token,
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
        str | None, Query(alias="status", pattern="^(active|revoked)$")
    ] = None,
    group_id: uuid.UUID | None = None,
    q: Annotated[str | None, Query(max_length=255)] = None,
    sort: str = Query("enrolled_at"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> Page:
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

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(direction, Endpoint.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [_to_out(e) for e in rows]
    return Page(items=items, total=total, page=page, page_size=page_size)


def _to_out(endpoint: Endpoint) -> EndpointOut:
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
    )


@router.get("/endpoints/{endpoint_id}", response_model=EndpointDetailOut)
def get_endpoint(
    endpoint_id: uuid.UUID, db: DbSession, _: EndpointsRead
) -> EndpointDetailOut:
    endpoint = _get_endpoint(db, endpoint_id)
    base = _to_out(endpoint)
    meta = endpoint.metadata_row
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
