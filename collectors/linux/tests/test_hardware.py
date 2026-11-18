"""Hardware collection tests: CPU, memory, DMI, disk handling.

Platform-dependent reads use injected fixture files; no root required.
"""

from __future__ import annotations

from eitop_collector.collect import hardware as hw

FAKE_CPUINFO = """\
processor\t: 0
model name\t: Common KVM processor
cpu cores\t: 4

processor\t: 1
model name\t: Common KVM processor
cpu cores\t: 4
"""

FAKE_MEMINFO = """\
MemTotal:        8388608 kB
MemFree:         1024000 kB
SwapTotal:              0 kB
"""


def test_collect_cpu_parses_model_and_cores(tmp_path):
    p = tmp_path / "cpuinfo"
    p.write_text(FAKE_CPUINFO.replace("\\t", "\t"))
    cpu = hw.collect_cpu(p)
    assert cpu["cpu_model"] == "Common KVM processor"
    assert cpu["cpu_cores"] == 2


def test_collect_cpu_missing_file_degrades(tmp_path):
    cpu = hw.collect_cpu(tmp_path / "missing")
    assert cpu["cpu_model"] is None
    assert cpu["cpu_cores"] is None or cpu["cpu_cores"] >= 1


def test_collect_memory_parses_total(tmp_path):
    p = tmp_path / "meminfo"
    p.write_text(FAKE_MEMINFO)
    assert hw.collect_memory(p) == 8388608 * 1024


def test_collect_memory_missing_or_garbage(tmp_path):
    assert hw.collect_memory(tmp_path / "missing") is None
    p = tmp_path / "meminfo"
    p.write_text("Nothing useful here\n")
    assert hw.collect_memory(p) is None


def test_collect_dmi_values_and_placeholders(tmp_path):
    dmi = tmp_path / "dmi"
    dmi.mkdir()
    (dmi / "sys_vendor").write_text("QEMU\n")
    (dmi / "product_name").write_text("Standard PC (Q35)\n")
    (dmi / "product_serial").write_text("To be filled by O.E.M.\n")
    got = hw.collect_dmi(dmi)
    assert got["manufacturer"] == "QEMU"
    assert got["model"] == "Standard PC (Q35)"
    # Placeholder serials are treated as unavailable
    assert got["serial_number"] is None


def test_collect_dmi_missing_dir(tmp_path):
    got = hw.collect_dmi(tmp_path / "nope")
    assert got == {"manufacturer": None, "model": None, "serial_number": None}


def test_collect_hardware_assembles_block(tmp_path, monkeypatch):
    cpuinfo = tmp_path / "cpuinfo"
    cpuinfo.write_text(FAKE_CPUINFO.replace("\\t", "\t"))
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(FAKE_MEMINFO)
    dmi = tmp_path / "dmi"
    dmi.mkdir()
    (dmi / "sys_vendor").write_text("Dell Inc.\n")
    (dmi / "product_name").write_text("PowerEdge R650\n")
    (dmi / "product_serial").write_text("ABC123\n")

    fake_fs = [
        {"mount": "/", "fstype": "ext4", "total_bytes": 100, "used_bytes": 40}
    ]
    monkeypatch.setattr(hw, "collect_disks", lambda: (100, fake_fs))

    block = hw.collect_hardware(
        cpuinfo_path=cpuinfo, meminfo_path=meminfo, dmi_dir=dmi
    )
    assert block["manufacturer"] == "Dell Inc."
    assert block["serial_number"] == "ABC123"
    assert block["cpu_cores"] == 2
    assert block["memory_bytes"] == 8388608 * 1024
    assert block["disk_bytes"] == 100
    assert block["_filesystems"] == fake_fs
    # Exactly the keys the backend accepts (after _filesystems is split out)
    allowed = {
        "manufacturer",
        "model",
        "serial_number",
        "cpu_model",
        "cpu_cores",
        "memory_bytes",
        "disk_bytes",
        "_filesystems",
    }
    assert set(block) == allowed


def test_collect_disks_returns_tuple_without_crash():
    total, filesystems = hw.collect_disks()
    assert total is None or total > 0
    assert isinstance(filesystems, list)
    for fs in filesystems:
        assert {"mount", "fstype", "total_bytes", "used_bytes"} <= set(fs)
