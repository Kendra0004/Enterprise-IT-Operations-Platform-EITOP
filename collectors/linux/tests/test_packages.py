"""Package inventory tests: safe subprocess use, parsing, graceful absence."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from eitop_collector.collect import packages as pkgs


def _fake_which(*names: str):
    def which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in names else None

    return which


def test_detect_package_manager_dpkg():
    assert pkgs.detect_package_manager(_fake_which("dpkg-query")) == "dpkg"


def test_detect_package_manager_rpm():
    assert pkgs.detect_package_manager(_fake_which("rpm")) == "rpm"


def test_detect_package_manager_none():
    assert pkgs.detect_package_manager(_fake_which()) is None


def test_dpkg_invocation_is_argv_list_no_shell(monkeypatch):
    """Subprocess must be an argv list with a timeout — never shell=True."""
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="curl\t8.5.0\n")

    monkeypatch.setattr(pkgs.subprocess, "run", fake_run)
    out = pkgs.collect_dpkg()

    assert captured["argv"] == [
        "dpkg-query",
        "-W",
        "-f",
        "${Package}\t${Version}\n",
    ]
    assert isinstance(captured["argv"], list)
    assert "shell" not in captured["kwargs"] or captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == pkgs.COMMAND_TIMEOUT
    assert captured["kwargs"]["capture_output"] is True
    assert out == [{"name": "curl", "version": "8.5.0"}]


def test_rpm_invocation_and_parsing(monkeypatch):
    def fake_run(argv, **kwargs):
        assert argv[0] == "rpm"
        return SimpleNamespace(
            returncode=0, stdout="bash\t5.2.21-2.fc40\nzlib\t1.3.1-1.fc40\n"
        )

    monkeypatch.setattr(pkgs.subprocess, "run", fake_run)
    out = pkgs.collect_rpm()
    assert out == [
        {"name": "bash", "version": "5.2.21-2.fc40"},
        {"name": "zlib", "version": "1.3.1-1.fc40"},
    ]


def test_missing_command_returns_empty(monkeypatch):
    def fake_run(argv, **kwargs):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(pkgs.subprocess, "run", fake_run)
    assert pkgs.collect_dpkg() == []


def test_timeout_returns_empty(monkeypatch):
    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv[0], timeout=kwargs["timeout"])

    monkeypatch.setattr(pkgs.subprocess, "run", fake_run)
    assert pkgs.collect_dpkg() == []


def test_nonzero_exit_returns_empty(monkeypatch):
    monkeypatch.setattr(
        pkgs.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="boom"),
    )
    assert pkgs.collect_dpkg() == []


def test_unknown_manager_returns_empty():
    out, manager = pkgs.collect_packages(which=_fake_which())
    assert out == []
    assert manager == "unknown"


def test_collect_packages_tags_manager(monkeypatch):
    monkeypatch.setattr(
        pkgs, "_run", lambda argv: "curl\t8.5.0\nopenssl\t3.0\n"
    )
    out, manager = pkgs.collect_packages(which=_fake_which("dpkg-query"))
    assert manager == "dpkg"
    assert all(p["package_manager"] == "dpkg" for p in out)
    assert len(out) == 2


def test_package_list_is_truncated(monkeypatch):
    big = "".join(f"pkg{i}\t1.0\n" for i in range(pkgs.MAX_PACKAGES + 500))
    monkeypatch.setattr(pkgs, "_run", lambda argv: big)
    out, _ = pkgs.collect_packages(which=_fake_which("dpkg-query"))
    assert len(out) == pkgs.MAX_PACKAGES
