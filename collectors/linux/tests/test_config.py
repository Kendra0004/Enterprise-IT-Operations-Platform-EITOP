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
        CollectorConfig(server_url="http://x", interval_seconds=5)


def test_non_http_scheme_rejected():
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="ftp://files.example")
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="file:///etc/passwd")


def test_bad_retries_rejected():
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="http://x", max_retries=0)
    with pytest.raises(ConfigError):
        CollectorConfig(server_url="http://x", max_retries=99)


def test_server_url_trailing_slash_normalized():
    cfg = CollectorConfig(server_url="http://host:8080/")
    assert cfg.server_url == "http://host:8080"


def test_env_server_url_override(tmp_path, monkeypatch):
    p = tmp_path / "collector.toml"
    p.write_text(VALID_TOML)
    monkeypatch.setenv("EITOP_SERVER_URL", "https://prod.example:8443")
    cfg = load_config(p)
    assert cfg.server_url == "https://prod.example:8443"


def test_env_config_path(tmp_path, monkeypatch):
    p = tmp_path / "from-env.toml"
    p.write_text(VALID_TOML)
    monkeypatch.setenv("EITOP_CONFIG", str(p))
    monkeypatch.delenv("EITOP_SERVER_URL", raising=False)
    cfg = load_config()
    assert cfg.interval_seconds == 120
