"""Authentication endpoints: login, refresh, logout, current user."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import CurrentUser, DbSession
from app.core.exceptions import AppError
from app.core.rate_limit import login_rate_limit, refresh_rate_limit
from app.models import User
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    MeOut,
    RefreshRequest,
    TokenResponse,
    UserOut,
)
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user.role_names,
        created_at=user.created_at,
    )


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def login(
    payload: LoginRequest,
    request: Request,
    db: DbSession,
    _: None = Depends(login_rate_limit),
) -> TokenResponse:
    """Exchange credentials for access + refresh tokens."""
    return auth_service.login(db, request, payload.email, payload.password)


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def refresh(
    payload: RefreshRequest,
    request: Request,
    db: DbSession,
    _: None = Depends(refresh_rate_limit),
) -> TokenResponse:
    """Rotate a refresh token for a new token pair."""
    return auth_service.refresh(db, request, payload.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: LogoutRequest,
    request: Request,
    db: DbSession,
    user: CurrentUser,
) -> None:
    """Revoke the caller's refresh token family."""
    auth_service.logout(db, request, payload.refresh_token, user)


@router.get("/me", response_model=MeOut, status_code=status.HTTP_200_OK)
def me(user: CurrentUser) -> MeOut:
    """Return the authenticated user with roles and permissions."""
    out = _user_out(user)
    return MeOut(**out.model_dump(), permissions=sorted(user.permissions))


__all__ = ["AppError", "router"]
