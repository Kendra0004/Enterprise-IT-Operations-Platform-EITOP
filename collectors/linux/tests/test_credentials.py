"""Credential file tests: permissions, roundtrip, refusal of insecure files."""

from __future__ import annotations

import json
import stat

import pytest

from eitop_collector.credentials import (
    CredentialError,
    clear_credentials,
    load_credentials,
    save_credentials,
)


def test_save_creates_0600_file_in_0700_dir(tmp_path):
    cred_file = tmp_path / "state" / "credentials.json"
    save_credentials(cred_file, "ep-123", "eitop_ep_secret")

    mode = stat.S_IMODE(cred_file.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"
    dir_mode = stat.S_IMODE(cred_file.parent.stat().st_mode)
    assert dir_mode == 0o700, f"expected 0700 dir, got {oct(dir_mode)}"
    assert not cred_file.with_name("credentials.json.tmp").exists()


def test_roundtrip(tmp_path):
    cred_file = tmp_path / "credentials.json"
    save_credentials(cred_file, "ep-abc", "eitop_ep_value")
    stored = load_credentials(cred_file)
    assert stored.endpoint_id == "ep-abc"
    assert stored.credential == "eitop_ep_value"


def test_insecure_permissions_refused(tmp_path):
    cred_file = tmp_path / "credentials.json"
    save_credentials(cred_file, "ep-1", "eitop_ep_value")
    cred_file.chmod(0o644)  # simulate tampering / misconfiguration

    with pytest.raises(CredentialError) as exc:
        load_credentials(cred_file)
    assert "insecure permissions" in str(exc.value)


def test_group_readable_refused(tmp_path):
    cred_file = tmp_path / "credentials.json"
    save_credentials(cred_file, "ep-1", "eitop_ep_value")
    cred_file.chmod(0o640)
    with pytest.raises(CredentialError):
        load_credentials(cred_file)


def test_missing_file_raises(tmp_path):
    with pytest.raises(CredentialError) as exc:
        load_credentials(tmp_path / "nope.json")
    assert "not found" in str(exc.value)


def test_corrupt_json_raises(tmp_path):
    cred_file = tmp_path / "credentials.json"
    cred_file.write_text("{not json")
    cred_file.chmod(0o600)
    with pytest.raises(CredentialError):
        load_credentials(cred_file)


def test_missing_keys_raise(tmp_path):
    cred_file = tmp_path / "credentials.json"
    cred_file.write_text(json.dumps({"endpoint_id": "ep-1"}))
    cred_file.chmod(0o600)
    with pytest.raises(CredentialError):
        load_credentials(cred_file)


def test_clear_credentials(tmp_path):
    cred_file = tmp_path / "credentials.json"
    save_credentials(cred_file, "ep-1", "eitop_ep_value")
    clear_credentials(cred_file)
    assert not cred_file.exists()
    clear_credentials(cred_file)  # idempotent


def test_overwrite_rotates_in_place(tmp_path):
    cred_file = tmp_path / "credentials.json"
    save_credentials(cred_file, "ep-1", "eitop_ep_old")
    save_credentials(cred_file, "ep-1", "eitop_ep_new")
    assert load_credentials(cred_file).credential == "eitop_ep_new"
    assert stat.S_IMODE(cred_file.stat().st_mode) == 0o600


# --- Phase 6 audit L4/L5 ----------------------------------------------------


def test_preexisting_parent_dir_is_never_chmodded(tmp_path):
    """L4: save_credentials may only chmod a directory IT created —
    touching a shared parent (e.g. /var/lib) would be catastrophic."""
    import os as _os

    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    _os.chmod(shared, 0o755)
    cred_file = shared / "credentials.json"

    save_credentials(cred_file, "ep-1", "eitop_ep_value")

    dir_mode = stat.S_IMODE(shared.stat().st_mode)
    assert dir_mode == 0o755, f"pre-existing dir must stay untouched, got {oct(dir_mode)}"
    assert stat.S_IMODE(cred_file.stat().st_mode) == 0o600


def test_planted_predictable_tmp_is_not_touched(tmp_path):
    """L5: the old fixed '<name>.tmp' could be pre-planted (symlink or
    regular file) and written through. mkstemp names are random+exclusive,
    so a planted file at the predictable name stays untouched."""
    cred_file = tmp_path / "credentials.json"
    planted = tmp_path / "credentials.json.tmp"
    planted.write_text("attacker-planted-content")

    save_credentials(cred_file, "ep-1", "eitop_ep_value")

    assert planted.read_text() == "attacker-planted-content"
    assert load_credentials(cred_file).credential == "eitop_ep_value"


def test_save_leaves_no_temp_residue(tmp_path):
    cred_file = tmp_path / "state" / "credentials.json"
    save_credentials(cred_file, "ep-1", "eitop_ep_value")
    leftovers = [p for p in cred_file.parent.iterdir() if p.name != "credentials.json"]
    assert leftovers == []


def test_load_refuses_file_owned_by_other_user(tmp_path, monkeypatch):
    """L5: content we did not write is never trusted, even at mode 0600."""
    cred_file = tmp_path / "credentials.json"
    save_credentials(cred_file, "ep-1", "eitop_ep_value")

    monkeypatch.setattr(
        "eitop_collector.credentials.os.geteuid", lambda: 99999
    )
    with pytest.raises(CredentialError) as exc:
        load_credentials(cred_file)
    assert "owned by uid" in str(exc.value)
