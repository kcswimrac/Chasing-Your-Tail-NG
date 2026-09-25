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


def test_wipe_deletes_files(tmp_path: Path):
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


def test_wipe_inventory_includes_debrief_files(tmp_path: Path):
    """S8: end-of-day debriefs render evidence and entity keys — they are
    wipe-scoped like analyzer.log and the cyt_log_* sinks."""
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
