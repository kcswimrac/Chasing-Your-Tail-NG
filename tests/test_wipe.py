"""Panic wipe tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyt_platform.wipe import panic_wipe, wipe_inventory


def test_wipe_requires_confirm(tmp_path: Path):
    cfg = {
        "store": {"path": str(tmp_path / "cyt.db")},
        "status": {"file": str(tmp_path / "status.json")},
        "paths": {"log_dir": str(tmp_path / "logs"), "runtime_dir": str(tmp_path)},
    }
    with pytest.raises(ValueError):
        panic_wipe(cfg, confirm="")


def test_wipe_deletes_files(tmp_path: Path, monkeypatch):
    # The inventory scans cwd-relative batch-output dirs; isolate the cwd so
    # the wipe can only ever touch this test's tmp_path.
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "cyt.db"
    db.write_text("secret")
    status = tmp_path / "status.json"
    status.write_text("{}")
    cfg = {
        "store": {"path": str(db), "encryption": {}},
        "status": {"file": str(status)},
        "paths": {"log_dir": str(tmp_path / "logs"), "runtime_dir": str(tmp_path)},
    }
    assert db.is_file()
    result = panic_wipe(cfg, confirm="YES")
    assert result["deleted"] >= 1
    assert not db.exists()


def test_wipe_inventory_includes_debrief_files(tmp_path: Path, monkeypatch):
    """S8: end-of-day debriefs render evidence and entity keys — they are
    wipe-scoped like analyzer.log and the cyt_log_* sinks."""
    monkeypatch.chdir(tmp_path)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    debrief = log_dir / "debrief_2026-09-25.md"
    debrief.write_text("# CYT End-of-Day Debrief")
    cfg = {
        "store": {"path": str(tmp_path / "cyt.db")},
        "status": {"file": str(tmp_path / "status.json")},
        "paths": {"log_dir": str(log_dir), "runtime_dir": str(tmp_path)},
    }
    inventory = wipe_inventory(cfg)
    assert debrief in inventory

    result = panic_wipe(cfg, confirm="YES")
    assert result["deleted"] >= 1
    assert not debrief.exists()


def test_wipe_inventory_includes_batch_outputs_and_config_backup(
    tmp_path: Path, monkeypatch
):
    """S4 completeness: legacy batch-tool outputs (KML visualizations and
    surveillance reports — plaintext SSIDs/MACs) and any pre-hardening
    plaintext config_backup.json are wipe-scoped."""
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "surveillance_reports"
    reports.mkdir()
    report = reports / "session_report.md"
    report.write_text("# report")
    kmls = tmp_path / "kml_files"
    kmls.mkdir()
    track = kmls / "track.kml"
    track.write_text("<kml/>")
    backup = tmp_path / "config_backup.json"
    backup.write_text("{}")

    cfg = {
        "store": {"path": str(tmp_path / "cyt.db")},
        "status": {"file": str(tmp_path / "status.json")},
        "paths": {"log_dir": str(tmp_path / "logs"), "runtime_dir": str(tmp_path)},
    }
    inventory = wipe_inventory(cfg)
    assert report in inventory
    assert track in inventory
    assert backup in inventory

    result = panic_wipe(cfg, confirm="YES")
    assert result["deleted"] >= 3
    assert not report.exists()
    assert not track.exists()
    assert not backup.exists()
