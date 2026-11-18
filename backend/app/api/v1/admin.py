"""User administration endpoints (admin-only) and audit log reader."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select

from app.api.deps import DbSession, require_permissions
from app.core.exceptions import AppError
from app.core.security import hash_password
from app.models import AuditLog, Role, User
from app.schemas.auth import AuditLogOut, Page, RoleOut, UserCreate, UserOut
from app.services.auth_service import _record_audit

router = APIRouter(tags=["administration"])

AdminRead = Annotated[User, Depends(require_permissions("admin:read"))]
AdminWrite = Annotated[User, Depends(require_permissions("admin:write"))]
AuditRead = Annotated[User, Depends(require_permissions("audit:read"))]


@router.get("/users", response_model=Page, status_code=status.HTTP_200_OK)
def list_users(
    db: DbSession,
    _: AdminRead,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> Page:
    total = db.scalar(select(func.count()).select_from(User)) or 0
    rows = db.scalars(
        select(User).order_by(User.created_at).offset((page - 1) * page_size).limit(page_size)
    ).all()
    items = [
        UserOut(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            is_active=u.is_active,
            roles=u.role_names,
            created_at=u.created_at,
        )
        for u in rows
    ]
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    db: DbSession,
    admin: AdminWrite,
) -> UserOut:
    email = payload.email.lower()
    existing = db.scalar(select(User).where(User.email == email))
    if existing is not None:
        raise AppError(
            status.HTTP_409_CONFLICT, "User already exists", email
        )

    roles = []
    if payload.roles:
        roles = list(db.scalars(select(Role).where(Role.name.in_(payload.roles))).all())
        found = {r.name for r in roles}
        missing = set(payload.roles) - found
        if missing:
            raise AppError(
                status.HTTP_400_BAD_REQUEST,
                "Unknown role",
                f"Role(s) not found: {', '.join(sorted(missing))}",
            )

    user = User(
        email=email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        is_active=True,
        roles=roles,
    )
    db.add(user)
    db.flush()
    _record_audit(
        db,
        event_type="user.created",
        outcome="success",
        request=request,
        actor=admin,
        target=email,
        detail={"roles": payload.roles},
    )
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user.role_names,
        created_at=user.created_at,
    )


@router.get("/roles", response_model=list[RoleOut], status_code=status.HTTP_200_OK)
def list_roles(
    db: DbSession,
    _: AdminRead,
) -> list[RoleOut]:
    rows = db.scalars(select(Role).order_by(Role.name)).all()
    return [
        RoleOut(
            name=r.name,
            description=r.description,
            permissions=sorted(p.name for p in r.permissions),
        )
        for r in rows
    ]


@router.get(
    "/audit-logs", response_model=Page, status_code=status.HTTP_200_OK
)
def list_audit_logs(
    db: DbSession,
    _: AuditRead,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    event_type: str | None = Query(None, max_length=64),
    outcome: str | None = Query(None, max_length=16),
) -> Page:
    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)
        count_stmt = count_stmt.where(AuditLog.event_type == event_type)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
        count_stmt = count_stmt.where(AuditLog.outcome == outcome)

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [
        AuditLogOut(
            id=r.id,
            event_type=r.event_type,
            actor_email=r.actor_email,
            target=r.target,
            outcome=r.outcome,
            ip_address=r.ip_address,
            created_at=r.created_at,
        )
        for r in rows
    ]
    return Page(items=items, total=total, page=page, page_size=page_size)


__all__ = ["router"]
