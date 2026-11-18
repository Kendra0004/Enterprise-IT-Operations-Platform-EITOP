"""Authentication service: login, refresh rotation, logout.

Refresh token rotation rules:
- Every refresh issues a new token and revokes the old one (replaced_by).
- Presenting an already-revoked token revokes the whole family
  (token-reuse detection → possible theft).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    sha256_hex,
    verify_password,
)
from app.models import AuditLog, RefreshToken, User
from app.schemas.auth import TokenResponse


def _record_audit(
    db: Session,
    *,
    event_type: str,
    outcome: str,
    request: Request | None = None,
    actor: User | None = None,
    actor_email: str | None = None,
    target: str | None = None,
    detail: dict | None = None,
) -> None:
    """Append an audit entry. Never receives passwords or raw tokens."""
    ip = None
    ua = None
    if request is not None:
        ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
            request.client.host if request.client else None
        )
        ua = request.headers.get("user-agent")
    db.add(
        AuditLog(
            event_type=event_type,
            actor_user_id=actor.id if actor else None,
            actor_email=actor_email or (actor.email if actor else None),
            target=target,
            outcome=outcome,
            ip_address=ip,
            user_agent=ua,
            detail=json.dumps(detail) if detail else None,
        )
    )


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.email == email.lower()))
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def _issue_tokens(db: Session, user: User, family_id: uuid.UUID) -> TokenResponse:
    settings = get_settings()
    access, expires_in = create_access_token(user.id, user.email)
    raw_refresh, digest = generate_refresh_token()
    refresh_exp = timedelta(days=settings.refresh_token_expire_days)
    token_row = RefreshToken(
        user_id=user.id,
        token_hash=digest,
        family_id=family_id,
        expires_at=datetime.now(UTC) + refresh_exp,
    )
    db.add(token_row)
    db.flush()
    return TokenResponse(
        access_token=access,
        expires_in=expires_in,
        refresh_token=raw_refresh,
        refresh_expires_in=int(refresh_exp.total_seconds()),
    )


def login(
    db: Session, request: Request, email: str, password: str
) -> TokenResponse:
    user = authenticate_user(db, email, password)
    if user is None:
        _record_audit(
            db,
            event_type="auth.login.failure",
            outcome="failure",
            request=request,
            actor_email=email.lower(),
            detail={"reason": "invalid_credentials"},
        )
        # Commit the failure audit before raising: get_db() rolls back on
        # exceptions, and security events must not be lost.
        db.commit()
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid credentials",
            "Email or password is incorrect.",
        )
    tokens = _issue_tokens(db, user, family_id=uuid.uuid4())
    _record_audit(
        db,
        event_type="auth.login.success",
        outcome="success",
        request=request,
        actor=user,
    )
    return tokens


def refresh(db: Session, request: Request, raw_token: str) -> TokenResponse:
    digest = sha256_hex(raw_token)
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == digest))
    if row is None:
        _record_audit(
            db,
            event_type="auth.refresh.reuse",
            outcome="failure",
            request=request,
            detail={"reason": "unknown_token"},
        )
        db.commit()  # persist audit before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Invalid refresh token", "Token not found."
        )

    now = datetime.now(UTC)
    if row.revoked_at is not None:
        # Reuse of a rotated token → assume theft, kill the whole family.
        for sibling in db.scalars(
            select(RefreshToken).where(
                RefreshToken.family_id == row.family_id,
                RefreshToken.revoked_at.is_(None),
            )
        ):
            sibling.revoked_at = now
        _record_audit(
            db,
            event_type="auth.refresh.reuse",
            outcome="failure",
            request=request,
            target=row.user_id.hex,
            detail={"family_id": str(row.family_id)},
        )
        db.commit()  # persist revocation + audit before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Token reuse detected",
            "Session revoked for security reasons.",
        )

    if row.expires_at <= now:
        row.revoked_at = now
        db.commit()  # persist revocation before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Token expired", "Refresh token expired."
        )

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Invalid session", "Account unavailable."
        )

    # Rotate: revoke old, issue new in the same family.
    tokens = _issue_tokens(db, user, family_id=row.family_id)
    new_row = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == sha256_hex(tokens.refresh_token)
        )
    )
    row.revoked_at = now
    row.replaced_by = new_row.id if new_row else None
    _record_audit(
        db,
        event_type="auth.refresh.success",
        outcome="success",
        request=request,
        actor=user,
    )
    return tokens


def logout(db: Session, request: Request, raw_token: str, user: User | None) -> None:
    """Revoke the presented refresh token (and its family) if it exists."""
    digest = sha256_hex(raw_token)
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == digest))
    if row is not None and row.revoked_at is None:
        now = datetime.now(UTC)
        for sibling in db.scalars(
            select(RefreshToken).where(
                RefreshToken.family_id == row.family_id,
                RefreshToken.revoked_at.is_(None),
            )
        ):
            sibling.revoked_at = now
    _record_audit(
        db,
        event_type="auth.logout",
        outcome="success",
        request=request,
        actor=user,
        target=row.user_id.hex if row else None,
    )


__all__ = [
    "_record_audit",
    "authenticate_user",
    "hash_password",
    "login",
    "logout",
    "refresh",
]
