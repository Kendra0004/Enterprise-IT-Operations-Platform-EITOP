"""Hardware collection: CPU, memory, disks, DMI (manufacturer/model/serial).

Sources: /proc/cpuinfo, /proc/meminfo, psutil (disks), /sys/class/dmi/id.
DMI files are typically root-only — values are None when unreadable
(serial number is "when available" by design).
"""

from __future__ import annotations

import os
from pathlib import Path

DMI_DIR = "/sys/class/dmi/id"
CPUINFO_PATH = "/proc/cpuinfo"
MEMINFO_PATH = "/proc/meminfo"


def _read_text(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def collect_cpu(cpuinfo_path: str | Path = CPUINFO_PATH) -> dict:
    """CPU model and core count from /proc/cpuinfo."""
    text = _read_text(cpuinfo_path)
    model: str | None = None
    core_count = 0
    if text:
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key in ("model name", "hardware", "cpu model") and model is None:
                model = value or None
            if key == "processor":
                # One "processor : N" line per logical CPU
                core_count += 1
    if not core_count:
        core_count = os.cpu_count() or 0
    return {"cpu_model": model, "cpu_cores": core_count or None}


def collect_memory(meminfo_path: str | Path = MEMINFO_PATH) -> int | None:
    """Total physical memory in bytes from /proc/meminfo MemTotal."""
    text = _read_text(meminfo_path)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024  # kB → bytes
    return None


def collect_disks() -> tuple[int | None, list[dict]]:
    """Total disk capacity (bytes) and per-filesystem usage.

    Uses psutil; falls back to os.statvfs over /proc/mounts if unavailable.
    Virtual filesystems (proc, sysfs, tmpfs, ...) are skipped.
    """
    try:
        import psutil
    except ImportError:
        return _disks_via_statvfs()

    total = 0
    filesystems: list[dict] = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        return _disks_via_statvfs()

    seen: set[str] = set()
    for part in partitions:
        if part.mountpoint in seen:
            continue
        seen.add(part.mountpoint)
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        total += usage.total
        filesystems.append(
            {
                "mount": part.mountpoint,
                "fstype": part.fstype or "",
                "total_bytes": int(usage.total),
                "used_bytes": int(usage.used),
            }
        )
    return (total or None), filesystems


def _disks_via_statvfs() -> tuple[int | None, list[dict]]:
    total = 0
    filesystems: list[dict] = []
    try:
        mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, []
    skip = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
            "overlay", "securityfs", "debugfs", "tracefs", "fusectl", "configfs",
            "bpf", "nsfs", "mqueue", "hugetlbfs", "ramfs", "squashfs"}
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] in skip:
            continue
        mount = parts[1]
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        total += st.f_blocks * st.f_frsize
        filesystems.append(
            {
                "mount": mount,
                "fstype": parts[2],
                "total_bytes": st.f_blocks * st.f_frsize,
                "used_bytes": (st.f_blocks - st.f_bfree) * st.f_frsize,
            }
        )
    return (total or None), filesystems


def collect_dmi(dmi_dir: str | Path = DMI_DIR) -> dict:
    """Manufacturer/model/serial from DMI (root-only files degrade to None)."""
    base = Path(dmi_dir)

    def value(name: str) -> str | None:
        raw = _read_text(base / name)
        if raw is None:
            return None
        raw = raw.strip()
        # Common placeholder values in VMs / non-root reads
        if not raw or raw.lower() in ("none", "unknown", "to be filled by o.e.m."):
            return None
        return raw

    return {
        "manufacturer": value("sys_vendor"),
        "model": value("product_name"),
        "serial_number": value("product_serial"),
    }


def collect_hardware(
    *,
    cpuinfo_path: str | Path = CPUINFO_PATH,
    meminfo_path: str | Path = MEMINFO_PATH,
    dmi_dir: str | Path = DMI_DIR,
) -> dict:
    """Assemble the hardware block (matches backend HardwareReport)."""
    cpu = collect_cpu(cpuinfo_path)
    memory = collect_memory(meminfo_path)
    disk_total, filesystems = collect_disks()
    dmi = collect_dmi(dmi_dir)
    return {
        "manufacturer": dmi["manufacturer"],
        "model": dmi["model"],
        "serial_number": dmi["serial_number"],
        "cpu_model": cpu["cpu_model"],
        "cpu_cores": cpu["cpu_cores"],
        "memory_bytes": memory,
        "disk_bytes": disk_total,
        "_filesystems": filesystems,
    }
