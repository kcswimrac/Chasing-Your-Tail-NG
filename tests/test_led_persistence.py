"""D8 LED wear: file/hardware writes happen only when the LED mode changes."""

from __future__ import annotations

import json
import time
from pathlib import Path

from cyt_platform.led import run_led_loop, update_led_files


def read_led_json(runtime: Path) -> dict:
    return json.loads((runtime / "led.json").read_text(encoding="utf-8"))


def test_first_write_writes(tmp_path: Path):
    runtime = tmp_path / "run"
    assert update_led_files(runtime, "green", {"state": "clear"}) is True
    assert (runtime / "led.state").read_text().strip() == "green"


def test_unchanged_mode_writes_nothing(tmp_path: Path):
    runtime = tmp_path / "run"
    update_led_files(runtime, "green", {"state": "clear"})
    first = read_led_json(runtime)
    time.sleep(0.01)
    # Same mode on the next poll: no write, so updated_at must not move.
    assert update_led_files(runtime, "green", {"state": "clear"}) is False
    assert read_led_json(runtime) == first


def test_changed_mode_writes(tmp_path: Path):
    runtime = tmp_path / "run"
    update_led_files(runtime, "green", {"state": "clear"})
    time.sleep(0.01)
    assert update_led_files(runtime, "amber", {"state": "watch"}) is True
    assert (runtime / "led.state").read_text().strip() == "amber"
    assert read_led_json(runtime)["state"] == "watch"


def test_loop_skips_polling_churn(tmp_path: Path, capsys):
    """Two loop passes over an unchanged status produce one write."""
    status_path = tmp_path / "status.json"
    status_path.write_text(json.dumps({"state": "clear", "reason": "ok"}))
    runtime = tmp_path / "run"
    config = {
        "status": {"file": str(status_path)},
        "paths": {"runtime_dir": str(runtime)},
        "led": {},
    }
    assert run_led_loop(config, once=True) == 0
    first = read_led_json(runtime)
    assert "green" in capsys.readouterr().out  # first pass announces
    time.sleep(0.01)
    assert run_led_loop(config, once=True) == 0
    assert read_led_json(runtime) == first  # second pass: no rewrite
    assert capsys.readouterr().out == ""  # and no re-announce


def test_loop_announces_on_change(tmp_path: Path, capsys):
    status_path = tmp_path / "status.json"
    status_path.write_text(json.dumps({"state": "clear", "reason": "ok"}))
    runtime = tmp_path / "run"
    config = {
        "status": {"file": str(status_path)},
        "paths": {"runtime_dir": str(runtime)},
        "led": {},
    }
    run_led_loop(config, once=True)
    capsys.readouterr()
    status_path.write_text(json.dumps({"state": "alert", "reason": "follower"}))
    run_led_loop(config, once=True)
    out = capsys.readouterr().out
    assert "red_blink" in out
    assert (runtime / "led.state").read_text().strip() == "red_blink"
