"""Encryption-at-rest for directory bind passwords (Phase 3.1).

Design (documented in docs/directory/active-directory.md):
- Key derivation: HKDF-SHA256 over the existing ``SECRET_KEY`` with info
  string ``eitop-directory-credential-v1`` — no new environment variable.
- Cipher: Fernet (AES-128-CBC + HMAC-SHA256), authenticated.
- Consequences (documented): rotating ``SECRET_KEY`` makes stored bind
  passwords undecryptable — operators must re-enter them via PATCH.
- Decryption happens ONLY inside the LDAP client at bind time. Ciphertext
  is never returned by any API response, never logged, never audited.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings
from app.services.directory.errors import CredentialDecryptionError

_INFO = b"eitop-directory-credential-v1"


def _fernet() -> Fernet:
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO,
    ).derive(get_settings().secret_key.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_password(raw: str) -> str:
    """Encrypt a bind password for storage. Returns a Fernet token str."""
    if not raw:
        raise ValueError("bind password must not be empty")
    return _fernet().encrypt(raw.encode("utf-8")).decode("ascii")


def decrypt_password(token: str) -> str:
    """Decrypt a stored bind password.

    Raises ``CredentialDecryptionError`` when the token is invalid or was
    encrypted under a different SECRET_KEY (static message — the cipher
    error text is never surfaced).
    """
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        raise CredentialDecryptionError(
            "Stored directory credential could not be decrypted "
            "(SECRET_KEY changed or data corrupted)."
        ) from None


__all__ = ["decrypt_password", "encrypt_password"]
