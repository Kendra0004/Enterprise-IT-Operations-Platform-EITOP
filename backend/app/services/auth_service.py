"""Authentication service: login, refresh rotation, logout.

Refresh token rules (transport):
- Raw refresh tokens exist only in the HttpOnly ``eitop_refresh`` cookie and
  in this process's response — never in a JSON body, never in localStorage.
- Only the SHA-256 digest is stored server-side.

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
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.rate_limit import client_ip
from app.core.security import (
    create_access_token,
    dummy_password_hash,
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
        # Shared trusted-proxy resolution (same helper the rate limiter
        # uses) — a spoofed X-Forwarded-For must not forge audit IPs.
        ip = client_ip(request) if request.client else None
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
    """Verify credentials with constant work regardless of account existence.

    Unknown or inactive accounts still consume one full Argon2 verification
    (against a dummy hash) so response timing cannot be used for account
    enumeration.
    """
    user = db.scalar(select(User).where(User.email == email.lower()))
    if user is None or not user.is_active:
        verify_password(password, dummy_password_hash())
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def _issue_tokens(
    db: Session, user: User, family_id: uuid.UUID
) -> tuple[TokenResponse, str]:
    """Create a new token pair. Returns ``(response, raw_refresh_token)``.

    The raw refresh token is handed to the caller ONLY so it can be placed
    in an HttpOnly cookie; it is never put in the response body.
    """
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
    response = TokenResponse(
        access_token=access,
        expires_in=expires_in,
        refresh_expires_in=int(refresh_exp.total_seconds()),
    )
    return response, raw_refresh


def login(
    db: Session, request: Request, email: str, password: str
) -> tuple[TokenResponse, str]:
    """Returns ``(token_response, raw_refresh_token)`` for cookie placement."""
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
    tokens, raw_refresh = _issue_tokens(db, user, family_id=uuid.uuid4())
    _record_audit(
        db,
        event_type="auth.login.success",
        outcome="success",
        request=request,
        actor=user,
    )
    return tokens, raw_refresh


def _revoke_family(db: Session, family_id: uuid.UUID, now: datetime) -> None:
    """Atomically revoke every still-live token in a family.

    Single UPDATE statement (Phase 6 audit A4): the previous Python loop
    read a snapshot first, so a token committed by a concurrent refresh
    after the read escaped revocation.
    """
    db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
        .execution_options(synchronize_session=False)
    )


def refresh(
    db: Session, request: Request, raw_token: str
) -> tuple[TokenResponse, str]:
    """Rotate the cookie-borne refresh token.

    Returns ``(token_response, new_raw_refresh_token)``.
    """
    settings = get_settings()
    if not raw_token:
        _record_audit(
            db,
            event_type="auth.refresh.failure",
            outcome="failure",
            request=request,
            detail={"reason": "missing_cookie"},
        )
        db.commit()  # persist audit before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            "No refresh token cookie present.",
        )

    digest = sha256_hex(raw_token)
    # Row lock: serializes concurrent refreshes presenting the same cookie
    # (Phase 6 audit A1). Without it two parallel requests can both rotate
    # (two live tokens, lineage broken) or the loser lands after the winner
    # commits and misreads rotation as theft.
    row = db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == digest)
        .with_for_update()
    )
    if row is None:
        _record_audit(
            db,
            event_type="auth.refresh.failure",
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
        _revoke_family(db, row.family_id, now)
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
        _record_audit(
            db,
            event_type="auth.refresh.failure",
            outcome="failure",
            request=request,
            target=row.user_id.hex,
            detail={"reason": "expired"},
        )
        db.commit()  # persist revocation + audit before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Token expired", "Refresh token expired."
        )

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        # Disabled/deleted account: kill the family and audit the attempt.
        _revoke_family(db, row.family_id, now)
        _record_audit(
            db,
            event_type="auth.refresh.failure",
            outcome="failure",
            request=request,
            target=row.user_id.hex,
            detail={"reason": "account_unavailable"},
        )
        db.commit()  # persist revocation + audit before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Invalid session", "Account unavailable."
        )

    # Absolute session cap (Phase 6 audit A9): rotation must not extend a
    # stolen refresh token forever — a family dies once it is older than
    # refresh_token_expire_days regardless of how often it rotates.
    family_started = db.scalar(
        select(func.min(RefreshToken.created_at)).where(
            RefreshToken.family_id == row.family_id
        )
    )
    if family_started is not None and now - family_started >= timedelta(
        days=settings.refresh_token_expire_days
    ):
        _revoke_family(db, row.family_id, now)
        _record_audit(
            db,
            event_type="auth.refresh.failure",
            outcome="failure",
            request=request,
            target=row.user_id.hex,
            detail={"reason": "session_absolute_expiry"},
        )
        db.commit()  # persist revocation + audit before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Session expired",
            "Session reached its maximum lifetime; sign in again.",
        )

    # Rotate: revoke old, issue new in the same family.
    tokens, new_raw = _issue_tokens(db, user, family_id=row.family_id)
    new_row = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == sha256_hex(new_raw)
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
    return tokens, new_raw


def logout(db: Session, request: Request, raw_token: str, user: User | None) -> None:
    """Revoke the presented refresh-token family and audit the event.

    Phase 6 audit A2/A3:
    - The refresh cookie is the authority for revocation, so logout works
      even when the access JWT has already expired (previously a 401 left
      the session alive on a shared machine).
    - When an access token IS present, its user must own the cookie's
      family; otherwise the request is rejected instead of revoking a
      session that does not belong to the caller.
    """
    digest = sha256_hex(raw_token) if raw_token else None
    row = None
    if digest:
        # Lock the row so a concurrent refresh cannot slip a new token
        # past this revocation (Phase 6 audit A4).
        row = db.scalar(
            select(RefreshToken)
            .where(RefreshToken.token_hash == digest)
            .with_for_update()
        )
    if row is not None and user is not None and row.user_id != user.id:
        # Cookie belongs to a different account than the presented JWT:
        # refuse rather than kill someone else's session.
        _record_audit(
            db,
            event_type="auth.logout",
            outcome="failure",
            request=request,
            actor=user,
            target=row.user_id.hex,
            detail={"reason": "cookie_user_mismatch"},
        )
        db.commit()  # persist the audit before rollback-on-raise
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid session",
            "Refresh cookie does not match the authenticated user.",
        )
    if row is not None and row.revoked_at is None:
        _revoke_family(db, row.family_id, datetime.now(UTC))
    _record_audit(
        db,
        event_type="auth.logout",
        outcome="success",
        request=request,
        actor=user,
        target=row.user_id.hex if row else (user.id.hex if user else None),
    )


__all__ = [
    "_record_audit",
    "authenticate_user",
    "hash_password",
    "login",
    "logout",
    "refresh",
]
