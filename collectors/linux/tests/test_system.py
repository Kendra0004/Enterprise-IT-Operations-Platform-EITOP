"""System information tests (os-release, uptime, hostname handling)."""

from __future__ import annotations

from eitop_collector.collect.system import (
    collect_system,
    parse_os_release,
    read_os_release,
    read_uptime_seconds,
)

FAKE_OS_RELEASE = """\
# comment line
NAME="Ubuntu"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04.1 LTS"
VERSION_ID="24.04"
HOME_URL="https://www.ubuntu.com/"
"""


def test_parse_os_release_quotes_and_comments():
    parsed = parse_os_release(FAKE_OS_RELEASE)
    assert parsed["ID"] == "ubuntu"
    assert parsed["VERSION_ID"] == "24.04"
    assert parsed["PRETTY_NAME"] == "Ubuntu 24.04.1 LTS"
    assert "#" not in parsed


def test_parse_os_release_ignores_malformed_lines():
    parsed = parse_os_release("JUST_A_WORD\n\nKEY=value\n")
    assert parsed == {"KEY": "value"}


def test_read_os_release_missing_file_returns_empty(tmp_path):
    assert read_os_release(tmp_path / "nope") == {}


def test_read_uptime_seconds(tmp_path):
    p = tmp_path / "uptime"
    p.write_text("12345.67 890.12\n")
    assert read_uptime_seconds(p) == 12345
    assert read_uptime_seconds(tmp_path / "missing") is None


def test_read_uptime_seconds_garbage(tmp_path):
    p = tmp_path / "uptime"
    p.write_text("not-a-number\n")
    assert read_uptime_seconds(p) is None


def test_collect_system_uses_injected_sources(tmp_path):
    release = tmp_path / "os-release"
    release.write_text(FAKE_OS_RELEASE)
    uptime = tmp_path / "uptime"
    uptime.write_text("999.5 100.0\n")

    system = collect_system(
        os_release_path=release,
        uptime_path=uptime,
        hostname="web01",
        fqdn="web01.example.com",
    )
    assert system["hostname"] == "web01"
    assert system["fqdn"] == "web01.example.com"
    assert system["os"] == "linux"
    assert system["distribution"] == "ubuntu"
    assert system["distribution_version"] == "24.04"
    assert system["os_version"] == "Ubuntu 24.04.1 LTS"
    assert system["kernel"]  # from platform.uname()
    assert system["os_arch"]
    assert system["uptime_seconds"] == 999


def test_collect_system_degrades_without_sources(tmp_path):
    system = collect_system(
        os_release_path=tmp_path / "missing",
        uptime_path=tmp_path / "missing",
        hostname="h",
        fqdn=None,
    )
    assert system["distribution"] is None
    assert system["uptime_seconds"] is None
    assert system["fqdn"] == "h"  # falls back to hostname
    assert system["os"] == "linux"
