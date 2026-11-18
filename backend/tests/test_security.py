"""Password hashing and JWT unit tests (no external services needed)."""

from __future__ import annotations

import uuid

import pytest
from app.core.exceptions import AppError
from app.core.security import (
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_password,
    needs_rehash,
    sha256_hex,
    verify_password,
)

PASSWORD = "Sup3r$ecret-Passw0rd!"


def test_password_hash_is_argon2_and_not_plaintext():
    h = hash_password(PASSWORD)
    assert h.startswith("$argon2")
    assert PASSWORD not in h
    # Unique salt → different hash each time
    assert hash_password(PASSWORD) != h


def test_verify_password_roundtrip():
    h = hash_password(PASSWORD)
    assert verify_password(PASSWORD, h) is True
    assert verify_password("wrong-password", h) is False


def test_verify_rejects_garbage_hash():
    assert verify_password(PASSWORD, "not-a-hash") is False


def test_needs_rehash_false_for_fresh_hash():
    assert needs_rehash(hash_password(PASSWORD)) is False


def test_access_token_roundtrip():
    uid = uuid.uuid4()
    token, expires_in = create_access_token(uid, "a@b.test")
    assert expires_in > 0
    payload = decode_access_token(token)
    assert payload["sub"] == str(uid)
    assert payload["email"] == "a@b.test"
    assert payload["type"] == "access"
    assert payload["iss"] == "eitop"


def test_decode_rejects_garbage():
    with pytest.raises(AppError) as exc:
        decode_access_token("garbage.token.here")
    assert exc.value.status == 401


def test_decode_rejects_refresh_type_as_access():
    import jwt as pyjwt
    from app.core.config import get_settings

    bad = pyjwt.encode(
        {"sub": str(uuid.uuid4()), "type": "refresh", "iss": "eitop"},
        get_settings().secret_key,
        algorithm="HS256",
    )
    with pytest.raises(AppError):
        decode_access_token(bad)


def test_decode_rejects_wrong_signature():
    import jwt as pyjwt

    token = pyjwt.encode(
        {"sub": str(uuid.uuid4()), "type": "access", "iss": "eitop"},
        "attacker-key-not-the-real-one",
        algorithm="HS256",
    )
    with pytest.raises(AppError):
        decode_access_token(token)


def test_refresh_token_opaque_and_hashed():
    raw1, digest1 = generate_refresh_token()
    raw2, digest2 = generate_refresh_token()
    assert raw1 != raw2
    assert digest1 != digest2
    assert len(digest1) == 64
    # Raw token must never equal stored digest
    assert raw1 != digest1
    assert sha256_hex(raw1) == digest1
