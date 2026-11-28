"""Installed package inventory via native package managers.

- Debian/Ubuntu: dpkg-query -W
- Fedora/RHEL:   rpm -qa
- Otherwise:     empty list (reported as manager "unknown" upstream)

Safety: subprocess is invoked with an argument LIST (never shell=True),
a timeout, and captured output. The child's PATH is pinned to the
standard system directories and loader hijack variables (LD_PRELOAD &
co) are dropped (Phase 6 audit L6) — a collector that often runs as root
must never execute whatever a caller-controlled PATH points at. Missing
commands or failures degrade to an empty list with a warning — collection
never crashes the agent.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = 60  # seconds
# Backend accepts up to 20000 package rows per submission.
MAX_PACKAGES = 19000

# The only PATH the collector trusts for package-manager binaries.
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Environment keys that would let a crafted parent environment hijack the
# child process (dynamic loader, interpreter overrides).
_UNSAFE_ENV_PREFIXES = ("LD_", "DYLD_")


def _safe_which(name: str) -> str | None:
    """Resolve a binary against SAFE_PATH only — never the ambient PATH."""
    return shutil.which(name, path=SAFE_PATH)


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = SAFE_PATH
    for key in [k for k in env if k.startswith(_UNSAFE_ENV_PREFIXES)]:
        del env[key]
    return env


def detect_package_manager(which=_safe_which) -> str | None:
    if which("dpkg-query"):
        return "dpkg"
    if which("rpm"):
        return "rpm"
    return None


def _run(argv: list[str]) -> str | None:
    """Run a command safely; None on missing binary, timeout or failure."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell, pinned PATH
            argv,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
            env=_child_env(),
        )
    except (FileNotFoundError, OSError):
        logger.warning("package_command_missing cmd=%s", argv[0])
        return None
    except subprocess.TimeoutExpired:
        logger.warning("package_command_timeout cmd=%s", argv[0])
        return None
    if proc.returncode != 0:
        logger.warning(
            "package_command_failed cmd=%s rc=%d", argv[0], proc.returncode
        )
        return None
    return proc.stdout


def _parse_tab_lines(output: str) -> list[dict]:
    packages: list[dict] = []
    for line in output.splitlines():
        if "\t" not in line:
            continue
        name, _, version = line.partition("\t")
        name = name.strip()
        version = version.strip()
        if name:
            packages.append({"name": name, "version": version})
    return packages


def collect_dpkg() -> list[dict]:
    output = _run(
        ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]
    )
    if output is None:
        return []
    return _parse_tab_lines(output)


def collect_rpm() -> list[dict]:
    output = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    if output is None:
        return []
    return _parse_tab_lines(output)


def collect_packages(
    which=shutil.which, manager: str | None = None
) -> tuple[list[dict], str]:
    """Return (packages, package_manager). Never raises for missing tools."""
    manager = manager or detect_package_manager(which)
    if manager == "dpkg":
        packages = collect_dpkg()
    elif manager == "rpm":
        packages = collect_rpm()
    else:
        return [], "unknown"

    if len(packages) > MAX_PACKAGES:
        logger.warning(
            "package_truncation count=%d max=%d", len(packages), MAX_PACKAGES
        )
        packages = packages[:MAX_PACKAGES]
    for pkg in packages:
        pkg["package_manager"] = manager
    return packages, manager
