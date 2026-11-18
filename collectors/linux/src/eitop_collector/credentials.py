"""Endpoint credential persistence with restrictive file permissions.

Rules enforced here:
- Credentials are written with mode 0600 into a 0700 directory.
- Loading REFUSES files readable/writable by group or other (a credential
  on a world-readable file is treated as compromised).
- The credential never appears in log output from this module.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path


class CredentialError(Exception):
    """Credential file missing, corrupt, or insecurely permissioned."""


@dataclass(frozen=True)
class StoredCredential:
    endpoint_id: str
    credential: str


def save_credentials(path: str | Path, endpoint_id: str, credential: str) -> None:
    """Persist the credential atomically with 0600 permissions."""
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(target.parent, 0o700)  # ignore: write below still applies 0600

    payload = json.dumps({"endpoint_id": endpoint_id, "credential": credential})
    tmp = target.with_name(target.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, target)
    os.chmod(target, 0o600)


def load_credentials(path: str | Path) -> StoredCredential:
    """Load credentials, refusing insecure file permissions."""
    target = Path(path)
    if not target.is_file():
        raise CredentialError(
            f"Credential file not found: {target} — run enrollment first."
        )

    mode = stat.S_IMODE(target.stat().st_mode)
    if mode & 0o077:
        raise CredentialError(
            f"Credential file {target} has insecure permissions "
            f"{oct(mode)}; run: chmod 600 {target}"
        )

    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        endpoint_id = data["endpoint_id"]
        credential = data["credential"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise CredentialError(f"Credential file {target} is unreadable: {exc}") from exc

    if not isinstance(endpoint_id, str) or not isinstance(credential, str):
        raise CredentialError(f"Credential file {target} has invalid content.")
    return StoredCredential(endpoint_id=endpoint_id, credential=credential)


def clear_credentials(path: str | Path) -> None:
    """Remove the credential file (used on revocation / re-enrollment)."""
    Path(path).unlink(missing_ok=True)
