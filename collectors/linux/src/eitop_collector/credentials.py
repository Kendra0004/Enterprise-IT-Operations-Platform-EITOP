"""Endpoint credential persistence with restrictive file permissions.

Rules enforced here:
- Credentials are written with mode 0600 into a directory we created
  with 0700 (an existing directory is never re-chmodded — chmod'ing a
  shared parent like /var/lib would be catastrophic; Phase 6 audit L4).
- Writes go through an exclusive, uniquely named temp file (O_EXCL via
  mkstemp) so a planted symlink/regular file at a predictable name can
  never be written through (Phase 6 audit L5).
- Loading REFUSES files readable/writable by group or other, files not
  owned by the current effective user, and (L5) anything replaced by a
  different principal between save and load.
- The credential never appears in log output from this module.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
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
    parent = target.parent
    created_dir = not parent.exists()
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created_dir:
        # mkdir's mode is masked by umask — force 0700. Only directories
        # THIS call created are touched (L4): chmod'ing a pre-existing
        # shared parent would break unrelated files or be silently
        # swallowed, and neither is our call to make.
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)

    payload = json.dumps({"endpoint_id": endpoint_id, "credential": credential})
    # mkstemp = O_CREAT|O_EXCL|O_WRONLY + 0600 + random name in the target
    # directory: no predictable .tmp to pre-create or symlink (L5).
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=parent
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, target)
    except Exception:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise
    with contextlib.suppress(OSError):
        os.chmod(target, 0o600)


def load_credentials(path: str | Path) -> StoredCredential:
    """Load credentials, refusing insecure file permissions."""
    target = Path(path)
    if not target.is_file():
        raise CredentialError(
            f"Credential file not found: {target} — run enrollment first."
        )

    info = target.stat()
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise CredentialError(
            f"Credential file {target} has insecure permissions "
            f"{oct(mode)}; run: chmod 600 {target}"
        )
    if info.st_uid != os.geteuid():
        # Owned by another principal: even with a 0600 mode we cannot
        # trust content we did not write (planted file / privilege drop
        # mismatch). Fail closed (Phase 6 audit L5).
        raise CredentialError(
            f"Credential file {target} is owned by uid {info.st_uid}, "
            f"not the current user (uid {os.geteuid()}); remove it and "
            "re-enroll."
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
