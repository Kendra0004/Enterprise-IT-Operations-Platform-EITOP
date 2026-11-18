"""Pydantic request/response schemas for auth and users."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    """Token pair for the caller.

    The refresh token is intentionally NOT part of the body: it is delivered
    exclusively through an HttpOnly ``Set-Cookie`` header so JavaScript (and
    therefore XSS) can never read it.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_expires_in: int


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(default="", max_length=255)
    roles: list[str] = Field(default_factory=list)  # role names


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str
    is_active: bool
    roles: list[str]
    created_at: datetime


class RoleOut(BaseModel):
    name: str
    description: str
    permissions: list[str]


class MeOut(UserOut):
    permissions: list[str]


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event_type: str
    actor_email: str | None
    target: str | None
    outcome: str
    ip_address: str | None
    created_at: datetime


class Page(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
