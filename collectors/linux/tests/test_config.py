"""Configuration tests: TOML parsing, validation, env overrides."""

from __future__ import annotations

import pytest

from eitop_collector.config import CollectorConfig, ConfigError, load_config

VALID_TOML = """\
[collector]
server_url = "http://localhost:8080"
interval_seconds = 120
heartbeat_interval_seconds = 30
timeout_seconds = 15
max_retries = 3
credential_file = "/tmp/creds.json"
"""


def test_load_valid_config(tmp_path):
    p = tmp_path / "collector.toml"
    p.write_text(VALID_TOML)
    cfg = load_config(p)
    assert cfg.server_url == "http://localhost:8080"
    assert cfg.interval_seconds == 120
    assert cfg.heartbeat_interval_seconds == 30
    assert cfg.max_retries == 3
    assert cfg.credential_file == "/tmp/creds.json"


def test_missing_config_raises(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(tmp_path / "nope.toml")
    assert "No config file found" in str(exc.value)


def test_invalid_toml_raises(tmp_path):
    p = tmp_path / "collector.toml"
    p.write_text("[collector\nserver_url = ")
    with pytest.raises(ConfigError):
        load_config(p)


def test_missing_server_url_raises(tmp_path):
    p = tmp_path / "collector.toml"
    p.write_text("[collector]\ninterval_seconds = 60\n")
    with pytest.raises(ConfigError) as exc:
        load_config(p)
    assert "server_url" in str(exc.value)


def test_missing_collector_section_raises(tmp_path):
    p = tmp_path / "collector.toml"
    p.write_text("[other]\nfoo = 1\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_interval_too_small_rejected():
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="https://x", interval_seconds=5)


def test_non_http_scheme_rejected():
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="ftp://files.example")
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="file:///etc/passwd")


def test_bad_retries_rejected():
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="https://x", max_retries=0)
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="https://x", max_retries=99)


def test_server_url_trailing_slash_normalized():
    cfg = CollectorConfig(server_url="https://host:8080/")
    assert cfg.server_url == "https://host:8080"


def test_env_server_url_override(tmp_path, monkeypatch):
    p = tmp_path / "collector.toml"
    p.write_text(VALID_TOML)
    monkeypatch.setenv("EITOP_SERVER_URL", "https://prod.example:8443")
    cfg = load_config(p)
    assert cfg.server_url == "https://prod.example:8443"


# --- Phase 6 audit L1: https everywhere except loopback --------------------


def test_remote_plaintext_http_rejected():
    with pytest.raises(ConfigError, match="https"):
        CollectorConfig(server_url="http://server.example:8080")
    with pytest.raises(ConfigError, match="https"):
        CollectorConfig(server_url="http://10.0.0.5")


def test_loopback_http_allowed():
    for url in (
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://127.8.9.7",
        "http://[::1]:8000",
    ):
        assert CollectorConfig(server_url=url).server_url == url.rstrip("/")


def test_env_override_also_enforces_https(tmp_path, monkeypatch):
    p = tmp_path / "collector.toml"
    p.write_text(VALID_TOML)
    monkeypatch.setenv("EITOP_SERVER_URL", "http://remote.example")
    with pytest.raises(ConfigError, match="https"):
        load_config(p)


# --- Phase 6 audit L7: userinfo never reaches an error message -------------


def test_userinfo_is_redacted_in_errors():
    with pytest.raises(ConfigError) as exc:
        CollectorConfig(server_url="ftp://alice:hunter2@files.example")
    assert "hunter2" not in str(exc.value)
    assert "***:***@" in str(exc.value)

    with pytest.raises(ConfigError) as exc:
        CollectorConfig(server_url="http://alice:hunter2@remote.example")
    assert "hunter2" not in str(exc.value)


# --- Phase 6 audit L2: group/other-writable config is refused --------------


def test_group_writable_config_rejected(tmp_path):
    p = tmp_path / "collector.toml"
    p.write_text(VALID_TOML)
    p.chmod(0o666)
    with pytest.raises(ConfigError, match="writable by group/other"):
        load_config(p)


def test_world_writable_config_rejected(tmp_path):
    p = tmp_path / "collector.toml"
    p.write_text(VALID_TOML)
    p.chmod(0o622)
    with pytest.raises(ConfigError, match="writable by group/other"):
        load_config(p)


def test_readonly_config_accepted(tmp_path):
    p = tmp_path / "collector.toml"
    p.write_text(VALID_TOML)
    p.chmod(0o644)
    assert load_config(p).server_url == "http://localhost:8080"


def test_env_config_path(tmp_path, monkeypatch):
    p = tmp_path / "from-env.toml"
    p.write_text(VALID_TOML)
    monkeypatch.setenv("EITOP_CONFIG", str(p))
    monkeypatch.delenv("EITOP_SERVER_URL", raising=False)
    cfg = load_config()
    assert cfg.interval_seconds == 120
