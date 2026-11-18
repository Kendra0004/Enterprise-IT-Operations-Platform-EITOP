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
