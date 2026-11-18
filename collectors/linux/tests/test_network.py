"""Network collection tests using mocked psutil (no real interfaces needed)."""

from __future__ import annotations

import sys
import types

import pytest

from eitop_collector.collect import network as net


class _Addr:
    def __init__(self, family: str, address: str) -> None:
        self.family = types.SimpleNamespace(name=family)
        self.address = address


class _Stat:
    def __init__(self, isup: bool) -> None:
        self.isup = isup


@pytest.fixture()
def fake_psutil(monkeypatch):
    """Inject a fake psutil module (tests must not require it installed)."""
    addrs = {
        "eth0": [
            _Addr("AF_PACKET", "52:54:00:12:34:56"),
            _Addr("AF_INET", "192.0.2.10"),
            _Addr("AF_INET6", "2001:db8::10%eth0"),
        ],
        "lo": [
            _Addr("AF_PACKET", "00:00:00:00:00:00"),
            _Addr("AF_INET", "127.0.0.1"),
        ],
        "eth1": [
            _Addr("AF_PACKET", "52:54:00:aa:bb:cc"),
            _Addr("AF_INET", "198.51.100.7"),
        ],
    }
    stats = {"eth0": _Stat(True), "lo": _Stat(True), "eth1": _Stat(False)}
    mod = types.ModuleType("psutil")
    mod.net_if_addrs = lambda: addrs
    mod.net_if_stats = lambda: stats
    monkeypatch.setitem(sys.modules, "psutil", mod)
    return addrs


def test_collect_network_structure(fake_psutil):
    got = net.collect_network()
    assert {"interfaces", "ip_addresses", "mac_addresses"} <= set(got)

    by_name = {i["name"]: i for i in got["interfaces"]}
    assert by_name["eth0"]["is_up"] is True
    assert by_name["eth1"]["is_up"] is False
    assert by_name["eth0"]["mac"] == "52:54:00:12:34:56"
    assert "192.0.2.10" in by_name["eth0"]["ipv4"]
    assert "2001:db8::10" in by_name["eth0"]["ipv6"]  # zone id stripped

    # Loopback MAC (all-zeros) is not reported as a real MAC
    assert by_name["lo"]["mac"] is None
    assert "127.0.0.1" in got["ip_addresses"]
    assert "52:54:00:aa:bb:cc" in got["mac_addresses"]


def test_collect_network_deduplicates(fake_psutil):
    got = net.collect_network()
    assert len(got["ip_addresses"]) == len(set(got["ip_addresses"]))
    assert len(got["mac_addresses"]) == len(set(got["mac_addresses"]))


def test_collect_network_without_psutil_uses_sysfs(monkeypatch):
    """Import failure falls back to /sys/class/net (still structured)."""
    monkeypatch.setitem(sys.modules, "psutil", None)
    got = net.collect_network()
    assert {"interfaces", "ip_addresses", "mac_addresses"} <= set(got)
    assert isinstance(got["interfaces"], list)
    for iface in got["interfaces"]:
        assert {"name", "mac", "ipv4", "ipv6", "is_up"} <= set(iface)


def test_is_loopback():
    assert net.is_loopback("lo")
    assert not net.is_loopback("eth0")
