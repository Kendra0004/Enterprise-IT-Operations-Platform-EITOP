"""Collector configuration: TOML file + environment overrides.

No secrets live here — the enrollment token comes from the environment,
stdin or an interactive prompt; the issued credential is persisted
separately with restrictive permissions (see credentials.py).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_PATHS = (
    "/etc/eitop/collector.toml",
    "./collector.toml",
)


class ConfigError(Exception):
    """Invalid or missing configuration."""


@dataclass(frozen=True)
class CollectorConfig:
    server_url: str
    interval_seconds: int = 300
    heartbeat_interval_seconds: int = 60
    timeout_seconds: float = 30.0
    max_retries: int = 5
    credential_file: str = "/var/lib/eitop/credentials.json"

    def __post_init__(self) -> None:
        url = self.server_url.rstrip("/")
        if not url.startswith(("http://", "https://")):
            raise ConfigError(f"server_url must be http(s), got: {url!r}")
        if self.interval_seconds < 10:
            raise ConfigError("interval_seconds must be >= 10")
        if self.heartbeat_interval_seconds < 10:
            raise ConfigError("heartbeat_interval_seconds must be >= 10")
        if self.timeout_seconds <= 0:
            raise ConfigError("timeout_seconds must be > 0")
        if not 1 <= self.max_retries <= 10:
            raise ConfigError("max_retries must be between 1 and 10")
        object.__setattr__(self, "server_url", url)


def load_config(path: str | Path | None = None) -> CollectorConfig:
    """Load configuration from TOML.

    Resolution order: explicit path → EITOP_CONFIG env → default paths.
    ``EITOP_SERVER_URL`` overrides the file value (container-friendly).
    """
    candidates: list[Path] = []
    if path is not None:
        candidates.append(Path(path))
    env_path = os.environ.get("EITOP_CONFIG")
    if env_path:
        candidates.append(Path(env_path))

    chosen: Path | None = None
    for candidate in candidates:
        if candidate.is_file():
            chosen = candidate
            break
    if chosen is None and path is None and env_path is None:
        for candidate in DEFAULT_CONFIG_PATHS:
            if candidate.is_file():
                chosen = Path(candidate)
                break
    if chosen is None:
        raise ConfigError(
            "No config file found. Pass --config, set EITOP_CONFIG, or create "
            "/etc/eitop/collector.toml (see config.example.toml)."
        )

    try:
        with chosen.open("rb") as fh:
            raw = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read config {chosen}: {exc}") from exc

    section = raw.get("collector")
    if not isinstance(section, dict):
        raise ConfigError(f"{chosen}: missing [collector] section")

    server_url = os.environ.get("EITOP_SERVER_URL") or section.get("server_url")
    if not server_url:
        raise ConfigError(f"{chosen}: collector.server_url is required")

    try:
        return CollectorConfig(
            server_url=server_url,
            interval_seconds=int(section.get("interval_seconds", 300)),
            heartbeat_interval_seconds=int(
                section.get("heartbeat_interval_seconds", 60)
            ),
            timeout_seconds=float(section.get("timeout_seconds", 30)),
            max_retries=int(section.get("max_retries", 5)),
            credential_file=str(
                section.get("credential_file", "/var/lib/eitop/credentials.json")
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{chosen}: invalid value: {exc}") from exc
