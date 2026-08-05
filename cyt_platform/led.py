"""
Glanceable LED / status consumer (P1).

Maps status.json state → LED mode and publishes:
  - data/run/led.state   plain text: green|amber|red_blink|red_solid|off
  - data/run/led.json   structured
  - console (optional)
  - optional sysfs or GPIO backends
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

STATE_MAP = {
    "clear": "green",
    "watch": "amber",
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


def apply_sysfs(led: str, sysfs_path: Optional[str]) -> None:
    """Best-effort brightness write for a single-color sysfs LED."""
    if not sysfs_path:
        return
    # Map multi-color to on/off intensity for mono LED
    brightness = {
        "green": "1",
        "amber": "1",
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
        on = led in ("green", "amber", "red_blink", "red_solid")
        GPIO.output(int(pin), GPIO.HIGH if on else GPIO.LOW)
    except Exception as e:
        logger.debug("GPIO LED failed: %s", e)


def ansi_line(led: str, state: str, reason: str) -> str:
    colors = {
        "green": "\033[32m",
        "amber": "\033[33m",
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
    status_path = Path((config.get("status") or {}).get("file") or "data/run/status.json")
    runtime = Path((config.get("paths") or {}).get("runtime_dir") or "data/run")
    led_cfg = config.get("led") or {}
    sysfs = led_cfg.get("sysfs_brightness")
    gpio_cfg = led_cfg.get("gpio") or {}

    last_led = None
    while True:
        snap = read_status(status_path)
        if snap is None:
            led = "off"
            state, reason = "unknown", "no_status"
        else:
            state = snap.get("state") or "unknown"
            reason = snap.get("reason") or ""
            led = state_to_led(state)

        write_led_files(runtime, led, snap)
        apply_sysfs(led, sysfs)
        apply_gpio(led, gpio_cfg)

        if console and led != last_led:
            print(ansi_line(led, state, reason), flush=True)
            last_led = led

        if once:
            return 0
        time.sleep(interval)
