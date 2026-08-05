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
