"""FastAPI dependencies: current user, RBAC guard, audit context."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import AppError
from app.core.security import decode_access_token
from app.models import Endpoint, User
from app.services.endpoint_service import authenticate_agent

bearer_scheme = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    db: DbSession,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(bearer_scheme)
    ],
) -> User:
    """Resolve the authenticated user from a Bearer access token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            "Missing bearer access token.",
        )
    payload = decode_access_token(credentials.credentials)
    try:
        user_uuid = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Invalid token", "Bad subject claim."
        ) from exc

    user = db.get(User, user_uuid)
    if user is None or not user.is_active:
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid session",
            "User not found or deactivated.",
        )
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_endpoint(
    db: DbSession,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(bearer_scheme)
    ],
    request: Request,
) -> Endpoint:
    """Resolve the authenticated endpoint from an agent credential.

    Agent identity is entirely separate from user identity: a user JWT is
    rejected here (agent credentials carry the ``eitop_ep_`` prefix) and an
    agent credential is rejected on user routes. Authorization is fixed by
    the credential's endpoint binding — nothing in the request can retarget it.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AppError(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            "Missing endpoint credential.",
        )
    endpoint, _cred = authenticate_agent(
        db, credentials.credentials, request=request
    )
    return endpoint


CurrentEndpoint = Annotated[Endpoint, Depends(get_current_endpoint)]


def require_permissions(*required: str) -> Callable[[User], User]:
    """RBAC dependency factory: user must hold ALL listed permissions.

    Usage: ``user: Annotated[User, Depends(require_permissions("users:write"))]``
    """

    def guard(user: CurrentUser) -> User:
        user_perms = user.permissions
        missing = [p for p in required if p not in user_perms]
        if missing:
            raise AppError(
                status.HTTP_403_FORBIDDEN,
                "Forbidden",
                f"Missing permission(s): {', '.join(sorted(missing))}",
            )
        return user

    return guard


def user_or_404(db: Session, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise AppError(status.HTTP_404_NOT_FOUND, "User not found", str(user_id))
    return user


__all__ = [
    "CurrentEndpoint",
    "CurrentUser",
    "DbSession",
    "get_current_endpoint",
    "get_current_user",
    "require_permissions",
    "user_or_404",
]
