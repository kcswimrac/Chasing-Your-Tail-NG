"""LED mapping tests."""

from pathlib import Path

from cyt_platform.led import state_to_led, write_led_files


def test_state_map():
    assert state_to_led("clear") == "green"
    assert state_to_led("watch") == "amber"
    assert state_to_led("alert") == "red_blink"
    assert state_to_led("fail") == "red_solid"


def test_write_led_files(tmp_path: Path):
    write_led_files(tmp_path, "amber", {"state": "watch", "reason": "x", "counts": {}})
    assert (tmp_path / "led.state").read_text().strip() == "amber"
    assert "watch" in (tmp_path / "led.json").read_text()
