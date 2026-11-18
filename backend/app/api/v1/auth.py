"""Authentication endpoints: login, refresh, logout, current user.

Refresh tokens are transported exclusively via the HttpOnly
``eitop_refresh`` cookie (path-scoped to this router's prefix). No endpoint
returns a raw refresh token in a JSON body.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import CurrentUser, DbSession
from app.core.rate_limit import login_rate_limit, refresh_rate_limit
from app.core.security import (
    REFRESH_COOKIE_NAME,
    clear_refresh_cookie,
    set_refresh_cookie,
)
from app.models import User
from app.schemas.auth import LoginRequest, MeOut, TokenResponse, UserOut
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
    response: Response,
    db: DbSession,
    _: None = Depends(login_rate_limit),
) -> TokenResponse:
    """Exchange credentials for an access token + HttpOnly refresh cookie."""
    tokens, raw_refresh = auth_service.login(db, request, payload.email, payload.password)
    set_refresh_cookie(response, raw_refresh, tokens.refresh_expires_in)
    return tokens


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def refresh(
    request: Request,
    response: Response,
    db: DbSession,
    _: None = Depends(refresh_rate_limit),
) -> TokenResponse:
    """Rotate the refresh token held in the HttpOnly cookie."""
    raw = request.cookies.get(REFRESH_COOKIE_NAME, "")
    tokens, new_raw = auth_service.refresh(db, request, raw)
    set_refresh_cookie(response, new_raw, tokens.refresh_expires_in)
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: DbSession,
    user: CurrentUser,
) -> None:
    """Revoke the caller's refresh token family and clear the cookie."""
    raw = request.cookies.get(REFRESH_COOKIE_NAME, "")
    auth_service.logout(db, request, raw, user)
    clear_refresh_cookie(response)


@router.get("/me", response_model=MeOut, status_code=status.HTTP_200_OK)
def me(user: CurrentUser) -> MeOut:
    """Return the authenticated user with roles and permissions."""
    out = _user_out(user)
    return MeOut(**out.model_dump(), permissions=sorted(user.permissions))


__all__ = ["router"]
