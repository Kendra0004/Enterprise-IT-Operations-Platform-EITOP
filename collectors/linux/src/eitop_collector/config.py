"""Collector configuration: TOML file + environment overrides.

No secrets live here — the enrollment token comes from the environment,
stdin or an interactive prompt; the issued credential is persisted
separately with restrictive permissions (see credentials.py).
"""

from __future__ import annotations

import ipaddress
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_CONFIG_PATHS = (
    "/etc/eitop/collector.toml",
    "./collector.toml",
)


class ConfigError(Exception):
    """Invalid or missing configuration."""


def is_loopback_host(host: str | None) -> bool:
    """True for localhost / 127.0.0.0/8 / ::1 — the only hosts allowed
    to speak plaintext http (Phase 6 audit L1)."""
    if not host:
        return False
    name = host.lower().strip("[]")
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def validate_server_url(url: str) -> str:
    """Enforce the transport policy: https everywhere except loopback.

    The collector sends the endpoint credential as a bearer token — over
    plain http to a remote host that credential is sniffable in transit.
    Returns the normalized URL (trailing slash stripped).
    """
    normalized = url.rstrip("/")
    parsed = urlsplit(normalized)
    if parsed.scheme not in ("http", "https"):
        raise ConfigError(f"server_url must be http(s), got: {redact_url(url)!r}")
    if parsed.scheme == "http" and not is_loopback_host(parsed.hostname):
        raise ConfigError(
            "server_url must use https for non-loopback hosts "
            f"(plaintext http is only allowed for localhost): {redact_url(url)!r}"
        )
    return normalized


def redact_url(url: str) -> str:
    """Strip userinfo (user:password@) before a URL can reach a log or an
    error message (Phase 6 audit L7)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    if parts.username or parts.password:
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return f"{parts.scheme}://***:***@{host}"
    return url


@dataclass(frozen=True)
class CollectorConfig:
    server_url: str
    interval_seconds: int = 300
    heartbeat_interval_seconds: int = 60
    timeout_seconds: float = 30.0
    max_retries: int = 5
    credential_file: str = "/var/lib/eitop/credentials.json"

    def __post_init__(self) -> None:
        url = validate_server_url(self.server_url)
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

    # Phase 6 audit L2: the config carries server_url (where credentials
    # get sent) — a group/other-writable file lets any local user retarget
    # enrollment and harvest the issued credential. Refuse to load it.
    try:
        mode = stat.S_IMODE(chosen.stat().st_mode)
    except OSError as exc:
        raise ConfigError(f"Cannot stat config {chosen}: {exc}") from exc
    if mode & 0o022:
        raise ConfigError(
            f"Config {chosen} is writable by group/other "
            f"({oct(mode)}); run: chmod 644 {chosen}"
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
