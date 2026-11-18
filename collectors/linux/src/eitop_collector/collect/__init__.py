"""Modular collection functions → structured inventory payload."""

from __future__ import annotations

from eitop_collector import __version__
from eitop_collector.collect.hardware import collect_hardware
from eitop_collector.collect.network import collect_network
from eitop_collector.collect.packages import collect_packages
from eitop_collector.collect.system import collect_system

__all__ = [
    "collect_all",
    "collect_hardware",
    "collect_network",
    "collect_packages",
    "collect_system",
]


def collect_all(
    *,
    os_release_path="/etc/os-release",
    uptime_path="/proc/uptime",
    cpuinfo_path="/proc/cpuinfo",
    meminfo_path="/proc/meminfo",
    dmi_dir="/sys/class/dmi/id",
) -> dict:
    """Build the complete inventory submission payload.

    Shape matches the backend ``AgentInventoryRequest`` exactly (extra
    fields are rejected server-side, so this mapping is the contract).
    """
    system = collect_system(
        os_release_path=os_release_path, uptime_path=uptime_path
    )
    hardware = collect_hardware(
        cpuinfo_path=cpuinfo_path, meminfo_path=meminfo_path, dmi_dir=dmi_dir
    )
    filesystems = hardware.pop("_filesystems", [])
    network = collect_network()
    packages, _manager = collect_packages()

    return {
        "system": system,
        "hardware": hardware,
        "network": network,
        "filesystems": filesystems,
        "packages": packages,
        "facts": {
            "collector.version": __version__,
            "collector.python": _python_version(),
        },
    }


def _python_version() -> str:
    import sys

    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def enroll_payload(token: str, *, os_release_path="/etc/os-release") -> dict:
    """Build the enrollment request body from live system data."""
    system = collect_system(os_release_path=os_release_path)
    return {
        "token": token,
        "hostname": system["hostname"],
        "fqdn": system["fqdn"],
        "os": system["os"],
        "os_version": system["os_version"],
        "os_arch": system["os_arch"],
        "kernel_version": system["kernel"],
        "agent_version": __version__,
    }
