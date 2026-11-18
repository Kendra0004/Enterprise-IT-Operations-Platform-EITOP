"""Password hashing (Argon2id) and JWT issuing/validation.

Security properties:
- Passwords hashed with Argon2id via argon2-cffi; plaintext never persisted.
- Access tokens are short-lived HS256 JWTs signed with ``SECRET_KEY``.
- Refresh tokens are opaque random strings; only their SHA-256 digest is
  stored server-side (see services/token_service.py) so a DB leak does not
  expose usable tokens.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Response, status

from app.core.config import get_settings
from app.core.exceptions import AppError

# Argon2id parameters: OWASP baseline (19 MiB memory, t=2, p=1).
_hasher = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "eitop"
ACCESS_TOKEN_TYPE = "access"

# Refresh tokens travel ONLY in an HttpOnly cookie (never in a response body
# and never in localStorage) so injected scripts cannot exfiltrate them.
REFRESH_COOKIE_NAME = "eitop_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"
# Non-secret presence hint so the SPA can decide whether to probe /auth/me
# on load. Knowing "a session might exist" grants an attacker nothing.
SESSION_HINT_KEY = "eitop.session"

# Lazily-built dummy hash: unknown/inactive logins still pay one full Argon2
# verification so response timing does not reveal whether an account exists.
_DUMMY_HASH: str | None = None


def hash_password(plaintext: str) -> str:
    """Hash a password with Argon2id. Never log or return the plaintext."""
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Constant-time-ish password verification; False on any mismatch."""
    try:
        return _hasher.verify(hashed, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """True when stored hash params are below current policy."""
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


def dummy_password_hash() -> str:
    """Return (building once) a hash of a random secret for timing-equalized
    failed logins. The secret is ephemeral and never used to authenticate."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
    return _DUMMY_HASH


def create_access_token(user_id: uuid.UUID, email: str) -> tuple[str, int]:
    """Create a signed access JWT. Returns (token, expires_in_seconds)."""
    settings = get_settings()
    now = datetime.now(UTC)
    expires_in = settings.access_token_expire_minutes * 60
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": ACCESS_TOKEN_TYPE,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)
    return token, expires_in


def decode_access_token(token: str) -> dict:
    """Validate an access JWT. Raises AppError(401) when invalid/expired."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
        )
    except jwt.ExpiredSignatureError as exc:
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Token expired", "Access token has expired."
        ) from exc
    except jwt.PyJWTError as exc:
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Invalid token", "Access token is invalid."
        ) from exc
    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise AppError(
            status.HTTP_401_UNAUTHORIZED, "Invalid token", "Wrong token type."
        )
    return payload


def generate_refresh_token() -> tuple[str, str]:
    """Generate an opaque refresh token and its storage digest.

    Returns ``(raw_token, digest)``. Only ``digest`` is persisted.
    """
    raw = secrets.token_urlsafe(48)
    return raw, sha256_hex(raw)


def set_refresh_cookie(response: Response, raw_token: str, max_age: int) -> None:
    """Attach the refresh token as an HttpOnly cookie.

    - ``HttpOnly``: unreadable from JavaScript (XSS cannot exfiltrate it).
    - ``SameSite=Lax``: not sent on cross-site POSTs (CSRF mitigation).
    - ``Secure``: set only in production (dev/demo runs over plain HTTP).
    - ``Path=/api/v1/auth``: cookie is only ever sent to auth endpoints.
    """
    settings = get_settings()
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=raw_token,
        max_age=max_age,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
    )


def clear_refresh_cookie(response: Response) -> None:
    """Expire the refresh cookie (same attributes used when setting it)."""
    settings = get_settings()
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
    )


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
