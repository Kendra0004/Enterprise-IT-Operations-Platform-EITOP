"""Network interface collection: names, MAC and IP addresses, link state.

Uses psutil when available with a /sys/class/net fallback. Loopback is
included for completeness but flagged (is_up) so downstream filtering is
possible.
"""

from __future__ import annotations

from pathlib import Path

SYS_NET = "/sys/class/net"
_SKIP_PREFIX = ("lo",)  # loopback reported but never used for identity


def _collect_from_sysfs(base: str | Path = SYS_NET) -> list[dict]:
    interfaces: list[dict] = []
    try:
        entries = sorted(Path(base).iterdir())
    except OSError:
        return interfaces
    for entry in entries:
        name = entry.name

        def read(field: str, entry=entry) -> str | None:  # bind loop var
            try:
                return (entry / field).read_text(encoding="utf-8").strip()
            except OSError:
                return None

        mac = read("address")
        is_up = (read("operstate") or "") == "up"
        ipv4: list[str] = []
        ipv6: list[str] = []
        # Addresses require netlink/proc parsing; sysfs only gives MAC/state.
        # The full address list is filled from /proc/net or psutil upstream.
        interfaces.append(
            {
                "name": name,
                "mac": mac if mac and mac != "00:00:00:00:00:00" else None,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "is_up": is_up,
            }
        )
    return interfaces


def collect_network() -> dict:
    """Return the network block (matches backend NetworkReport)."""
    interfaces: list[dict] = []
    try:
        import psutil
    except ImportError:
        interfaces = _collect_from_sysfs()
    else:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception:
            interfaces = _collect_from_sysfs()
        else:
            for name in sorted(addrs):
                ipv4: list[str] = []
                ipv6: list[str] = []
                mac: str | None = None
                for addr in addrs[name]:
                    family_name = getattr(addr.family, "name", str(addr.family))
                    if family_name == "AF_PACKET":
                        mac = addr.address or None
                    elif family_name == "AF_INET":
                        if addr.address:
                            ipv4.append(addr.address)
                    elif family_name == "AF_INET6" and addr.address:
                        ipv6.append(addr.address.split("%")[0])
                is_up = bool(stats.get(name) and stats[name].isup)
                interfaces.append(
                    {
                        "name": name,
                        "mac": mac if mac and mac != "00:00:00:00:00:00" else None,
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "is_up": is_up,
                    }
                )

    ip_addresses: list[str] = []
    mac_addresses: list[str] = []
    for iface in interfaces:
        ip_addresses.extend(iface["ipv4"])
        ip_addresses.extend(iface["ipv6"])
        if iface["mac"]:
            mac_addresses.append(iface["mac"])

    return {
        "interfaces": interfaces,
        "ip_addresses": sorted(set(ip_addresses)),
        "mac_addresses": sorted(set(mac_addresses)),
    }


def is_loopback(name: str) -> bool:
    return name in _SKIP_PREFIX
