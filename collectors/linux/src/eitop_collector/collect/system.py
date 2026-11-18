"""System information collection: /etc/os-release, platform, socket, uptime.

All functions accept injectable paths for testability and degrade gracefully
when a source is unavailable (no exceptions for missing optional data).
"""

from __future__ import annotations

import platform
import socket
from pathlib import Path

OS_RELEASE_PATH = "/etc/os-release"
PROC_UPTIME_PATH = "/proc/uptime"


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release(5) KEY=VALUE lines (no shell evaluation)."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip matching surrounding quotes (single or double).
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key] = value
    return result


def read_os_release(path: str | Path = OS_RELEASE_PATH) -> dict[str, str]:
    try:
        return parse_os_release(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}


def read_uptime_seconds(path: str | Path = PROC_UPTIME_PATH) -> int | None:
    """Seconds since boot from /proc/uptime (first field)."""
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
        return int(float(raw.split()[0]))
    except (OSError, IndexError, ValueError):
        return None


def collect_system(
    *,
    os_release_path: str | Path = OS_RELEASE_PATH,
    uptime_path: str | Path = PROC_UPTIME_PATH,
    hostname: str | None = None,
    fqdn: str | None = None,
) -> dict:
    """Collect the system block for inventory/enrollment payloads."""
    release = read_os_release(os_release_path)
    uname = platform.uname()

    if hostname is None:
        try:
            hostname = socket.gethostname()
        except OSError:
            hostname = uname.node or "unknown"
    if fqdn is None:
        if hostname is not None and hostname != uname.node:
            # Hostname was caller-supplied: don't leak resolver results.
            fqdn = hostname
        else:
            try:
                fqdn = socket.getfqdn()
            except OSError:
                fqdn = hostname

    distribution = release.get("ID")
    distribution_version = release.get("VERSION_ID")
    pretty = release.get("PRETTY_NAME")

    return {
        "hostname": hostname,
        "fqdn": fqdn if fqdn and fqdn != "localhost" else hostname,
        "os": "linux",
        "distribution": distribution,
        "distribution_version": distribution_version,
        "os_version": pretty,
        "os_arch": uname.machine or None,
        "kernel": uname.release or None,
        "uptime_seconds": read_uptime_seconds(uptime_path),
    }
