"""
Glanceable LED / status consumer (P1).

Maps status.json state → LED mode and publishes:
  - data/run/led.state   plain text: green|amber|amber_blink|red_blink|red_solid|off
  - data/run/led.json   structured
  - console (optional)
  - optional sysfs or GPIO backends

S11: the LED displays the staleness-honoring state — a dead or parked
publisher reads ``fail`` (red_solid), never its last written state — and
``degraded`` has its own pattern (amber_blink), distinct from watch
(amber) and from "no status file" (off).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from cyt_platform.status import effective_state

logger = logging.getLogger(__name__)

STATE_MAP = {
    "clear": "green",
    "watch": "amber",
    "degraded": "amber_blink",
    "alert": "red_blink",
    "fail": "red_solid",
}


def state_to_led(state: str) -> str:
    return STATE_MAP.get(state, "off")


def read_status(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def write_led_files(runtime_dir: Path, led: str, snapshot: Optional[dict]) -> None:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    state_path = runtime_dir / "led.state"
    json_path = runtime_dir / "led.json"
    state_path.write_text(led + "\n", encoding="utf-8")
    payload = {
        "led": led,
        "state": (snapshot or {}).get("state"),
        "reason": (snapshot or {}).get("reason"),
        "updated_at": time.time(),
        "counts": (snapshot or {}).get("counts"),
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def update_led_files(runtime_dir: Path, led: str, snapshot: Optional[dict]) -> bool:
    """Write LED files only when the LED mode actually changed.

    D8 LED wear: led.state lives on flash on deployed units; rewriting it
    every poll cycle wears the storage for zero information. Returns True
    when files were (re)written.
    """
    state_path = runtime_dir / "led.state"
    try:
        previous = state_path.read_text(encoding="utf-8").strip()
    except OSError:
        previous = None
    if previous == led:
        return False
    write_led_files(runtime_dir, led, snapshot)
    return True


def apply_sysfs(led: str, sysfs_path: Optional[str]) -> None:
    """Best-effort brightness write for a single-color sysfs LED."""
    if not sysfs_path:
        return
    # Map multi-color to on/off intensity for mono LED
    brightness = {
        "green": "1",
        "amber": "1",
        "amber_blink": "1",
        "red_blink": "1",
        "red_solid": "1",
        "off": "0",
    }.get(led, "0")
    try:
        Path(sysfs_path).write_text(brightness)
    except OSError as e:
        logger.debug("sysfs LED write failed: %s", e)


def apply_gpio(led: str, gpio_cfg: dict) -> None:
    """Optional RPi.GPIO / gpiozero — soft-fail if unavailable."""
    if not gpio_cfg or not gpio_cfg.get("enabled"):
        return
    pin = gpio_cfg.get("pin")
    if pin is None:
        return
    try:
        import RPi.GPIO as GPIO  # type: ignore
    except ImportError:
        logger.debug("RPi.GPIO not available")
        return
    try:
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(int(pin), GPIO.OUT)
        on = led in ("green", "amber", "amber_blink", "red_blink", "red_solid")
        GPIO.output(int(pin), GPIO.HIGH if on else GPIO.LOW)
    except Exception as e:
        logger.debug("GPIO LED failed: %s", e)


def ansi_line(led: str, state: str, reason: str) -> str:
    colors = {
        "green": "\033[32m",
        "amber": "\033[33m",
        "amber_blink": "\033[33;1m",
        "red_blink": "\033[31m",
        "red_solid": "\033[31;1m",
        "off": "\033[90m",
    }
    reset = "\033[0m"
    c = colors.get(led, "")
    return f"{c}● {led:10} {state or '?':6} {reason or ''}{reset}"


def run_led_loop(
    config: dict,
    *,
    once: bool = False,
    interval: float = 1.0,
    console: bool = True,
) -> int:
    status_cfg = config.get("status") or {}
    status_path = Path(status_cfg.get("file") or "data/run/status.json")
    stale_seconds = float(status_cfg.get("stale_seconds") or 150)
    runtime = Path((config.get("paths") or {}).get("runtime_dir") or "data/run")
    led_cfg = config.get("led") or {}
    sysfs = led_cfg.get("sysfs_brightness")
    gpio_cfg = led_cfg.get("gpio") or {}

    while True:
        snap = read_status(status_path)
        if snap is None:
            led = "off"
            state, reason = "unknown", "no_status"
        else:
            # S11: a stale snapshot is a dead or parked publisher — display
            # fail, never the last written state. The wall clock is correct
            # here: the LED is a consumer, not detection logic.
            state, reason = effective_state(
                snap, now=time.time(), stale_seconds=stale_seconds
            )
            led = state_to_led(state)
            # led.json describes what the LED is displaying: the effective
            # (staleness-honoring) state, not the raw snapshot's.
            snap = {**snap, "state": state, "reason": reason}

        # D8: file writes and hardware blips happen only on LED state change.
        if update_led_files(runtime, led, snap):
            apply_sysfs(led, sysfs)
            apply_gpio(led, gpio_cfg)
            if console:
                print(ansi_line(led, state, reason), flush=True)

        if once:
            return 0
        time.sleep(interval)
