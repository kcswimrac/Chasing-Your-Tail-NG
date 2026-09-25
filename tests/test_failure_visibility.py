"""B5 + S11: failure visibility — a blind detector or a dead status
publisher can never read as "clear".

Paths pinned here:

- B5 window matcher: an exception in ``process_current_activity`` (or the
  list-refresh half, ``rotate_tracking_lists``) registers ``detector:window``
  in the shared health registry, and a published status reads ``degraded``.
- B5 device feed: a failing ``get_devices_by_time_range`` pull registers
  ``device_feed`` and the cycle neither runs nor clears IE/BLE health.
- S11 staleness: consumers (LED, CLI) display a snapshot older than
  ``stale_seconds`` — by ``updated_at`` or ``last_ok`` — as ``fail``, and
  ``degraded`` has its own LED pattern.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

from cyt_platform.cli import status_report
from cyt_platform.health import ComponentFailureRegistry
from cyt_platform.led import run_led_loop, state_to_led
from cyt_platform.rf_plugins import RFPluginRunner
from cyt_platform.secure_main_logic import SecureCYTMonitor
from cyt_platform.status import StatusEngine, effective_state
from cyt_platform.store import CytStore

STALE_SECONDS = 150


class FakeWindowDb:
    """Kismet DB double: separate faults for the cycle read and the
    list-refresh reads (they hit different Kismet tables)."""

    def __init__(self, devices_error=None, list_error=None):
        self.devices_error = devices_error
        self.list_error = list_error

    def get_devices_by_time_range(self, since, until=None):
        if self.devices_error:
            raise self.devices_error
        return []

    def get_mac_addresses_by_time_range(self, since, until=None):
        if self.list_error:
            raise self.list_error
        return []

    def get_probe_requests_by_time_range(self, since, until=None):
        if self.list_error:
            raise self.list_error
        return []


def _monitor(registry: ComponentFailureRegistry) -> SecureCYTMonitor:
    return SecureCYTMonitor({}, [], [], io.StringIO(), registry=registry)


def _runner(store: CytStore, registry: ComponentFailureRegistry) -> RFPluginRunner:
    # IE and BLE on (their platform defaults), everything else off — the
    # device pull is the shared input this file is about.
    config = {
        "rf": {"deauth_enabled": False, "rogue_enabled": False},
        "gps_fusion": {"enabled": False},
    }
    return RFPluginRunner(store, config, registry=registry)


# --- B5: window matcher --------------------------------------------------


def test_window_matcher_failure_is_registered():
    reg = ComponentFailureRegistry()
    mon = _monitor(reg)
    mon.process_current_activity(
        FakeWindowDb(devices_error=RuntimeError("database disk image is malformed"))
    )
    assert "detector:window" in reg.failures()
    assert "process" in reg.failures()["detector:window"]
    # The service loop must still survive: the exception is registered and
    # logged, not propagated.
    mon.process_current_activity(FakeWindowDb())
    assert "detector:window" not in reg.failures()


def test_rotate_failure_stays_visible_while_process_succeeds():
    reg = ComponentFailureRegistry()
    mon = _monitor(reg)
    mon.process_current_activity(FakeWindowDb())
    assert "detector:window" not in reg.failures()

    mon.rotate_tracking_lists(
        FakeWindowDb(list_error=RuntimeError("no such column: devmac"))
    )
    assert "detector:window" in reg.failures()
    assert "rotate" in reg.failures()["detector:window"]

    # process and rotate read different tables: a healthy cycle read must
    # not clear the rotate half's failure.
    mon.process_current_activity(FakeWindowDb())
    assert "detector:window" in reg.failures()

    # Explicit recovery: a clean rotate clears it.
    mon.rotate_tracking_lists(FakeWindowDb())
    assert "detector:window" not in reg.failures()


def test_window_matcher_failure_degrades_published_status(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    try:
        reg = ComponentFailureRegistry()
        mon = _monitor(reg)
        mon.process_current_activity(
            FakeWindowDb(devices_error=RuntimeError("database disk image is malformed"))
        )
        engine = StatusEngine(
            store,
            {
                "status": {
                    "file": str(tmp_path / "run" / "status.json"),
                    "hold_seconds": 300,
                    "stale_seconds": STALE_SECONDS,
                    "deaf_seconds": 180,
                }
            },
        )
        store.begin_session()
        snap = engine.publish(
            cycle=1,
            db_label="x.kismet",
            freshness=None,
            consecutive_fails=0,
            component_registry=reg,
        )
        assert snap["state"] == "degraded"
        assert "detector:window" in snap["reason"]
        assert snap["components"]["detector:window"]["ok"] is False
    finally:
        store.close()


# --- B5: device feed -----------------------------------------------------


def test_device_pull_failure_registers_device_feed_and_spares_ie_ble(
    tmp_path: Path,
):
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    try:
        reg = ComponentFailureRegistry()
        runner = _runner(store, reg)
        # Seed real IE/BLE failures: the buggy path would clear them on the
        # empty substituted list.
        reg.record_failure("detector:ie", "seeded", ts=1.0)
        reg.record_failure("detector:ble", "seeded", ts=1.0)

        class BoomPullDb:
            def get_devices_by_time_range(self, since, until=None):
                raise RuntimeError("no such column: devmac")

        stats = runner.run_cycle(BoomPullDb(), "unused.kismet", now=1000.0)
        assert "device_feed" in stats["detector_failures"]
        assert "devmac" in stats["detector_failures"]["device_feed"]
        # The failed cycle must not clear IE/BLE health.
        assert stats["detector_failures"]["detector:ie"] == "seeded"
        assert stats["detector_failures"]["detector:ble"] == "seeded"

        class EmptyPullDb:
            def get_devices_by_time_range(self, since, until=None):
                return []

        # Recovery: a clean pull clears the feed and IE/BLE run again.
        stats = runner.run_cycle(EmptyPullDb(), "unused.kismet", now=1060.0)
        assert "device_feed" not in stats["detector_failures"]
        assert "detector:ie" not in stats["detector_failures"]
        assert "detector:ble" not in stats["detector_failures"]
    finally:
        store.close()


# --- S11: consumer-side staleness ----------------------------------------


def test_effective_state_fresh_snapshot_passthrough():
    snap = {"state": "clear", "reason": "healthy", "updated_at": 1000.0, "last_ok": 1000.0}
    assert effective_state(snap, now=1100.0, stale_seconds=STALE_SECONDS) == (
        "clear",
        "healthy",
    )


def test_effective_state_stale_updated_at_reads_fail():
    snap = {"state": "clear", "reason": "healthy", "updated_at": 100.0, "last_ok": 100.0}
    state, reason = effective_state(snap, now=1000.0, stale_seconds=STALE_SECONDS)
    assert state == "fail"
    assert "status_stale" in reason and "updated_at" in reason


def test_effective_state_stale_last_ok_reads_fail():
    # Publisher alive but no good cycle for a long time: the state it
    # wrote (watch) must not be displayed as current.
    snap = {
        "state": "watch",
        "reason": "open_watch_incidents",
        "updated_at": 1000.0,
        "last_ok": 100.0,
    }
    state, reason = effective_state(snap, now=1000.0, stale_seconds=STALE_SECONDS)
    assert state == "fail"
    assert "last_ok" in reason


def test_effective_state_fail_keeps_own_reason():
    snap = {"state": "fail", "reason": "analyzer_error", "updated_at": 100.0}
    assert effective_state(snap, now=1000.0, stale_seconds=STALE_SECONDS) == (
        "fail",
        "analyzer_error",
    )


def test_effective_state_untimestamped_snapshot_unchanged():
    snap = {"state": "clear", "reason": "healthy"}
    assert effective_state(snap, now=1000.0, stale_seconds=STALE_SECONDS) == (
        "clear",
        "healthy",
    )


def _led_config(status_path: Path, runtime_dir: Path) -> dict:
    return {
        "status": {"file": str(status_path), "stale_seconds": STALE_SECONDS},
        "paths": {"runtime_dir": str(runtime_dir)},
    }


def _write_status(path: Path, state: str, updated_at: float, last_ok: float) -> None:
    path.write_text(
        json.dumps(
            {"state": state, "reason": "x", "updated_at": updated_at, "last_ok": last_ok}
        ),
        encoding="utf-8",
    )


def test_led_shows_fail_for_stale_snapshot(tmp_path: Path):
    status_path = tmp_path / "status.json"
    old = time.time() - 3 * 86400  # the 3-day-old clear file lights green today
    _write_status(status_path, "clear", old, old)
    runtime = tmp_path / "run"

    run_led_loop(_led_config(status_path, runtime), once=True, console=False)

    assert (runtime / "led.state").read_text().strip() == "red_solid"
    assert json.loads((runtime / "led.json").read_text())["state"] == "fail"


def test_led_shows_green_for_fresh_snapshot(tmp_path: Path):
    status_path = tmp_path / "status.json"
    now = time.time()
    _write_status(status_path, "clear", now, now)
    runtime = tmp_path / "run"

    run_led_loop(_led_config(status_path, runtime), once=True, console=False)

    assert (runtime / "led.state").read_text().strip() == "green"


def test_led_degraded_has_its_own_pattern(tmp_path: Path):
    status_path = tmp_path / "status.json"
    now = time.time()
    _write_status(status_path, "degraded", now, now)
    runtime = tmp_path / "run"

    run_led_loop(_led_config(status_path, runtime), once=True, console=False)

    led = (runtime / "led.state").read_text().strip()
    assert led == "amber_blink"
    # and it is distinct from both watch (amber) and no-file (off)
    assert led not in (state_to_led("watch"), state_to_led("no-such-state"))


def test_cli_status_stale_snapshot_reads_fail(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    try:
        status_path = tmp_path / "status.json"
        old = time.time() - 3 * 86400
        _write_status(status_path, "clear", old, old)
        config = {
            "status": {
                "file": str(status_path),
                "stale_seconds": STALE_SECONDS,
                "hold_seconds": 300,
            }
        }
        report = status_report(config, store)
        assert report["state"] == "fail"
        assert "status_stale" in report["reason"]
    finally:
        store.close()


def test_cli_status_fresh_snapshot_passthrough(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    try:
        status_path = tmp_path / "status.json"
        now = time.time()
        _write_status(status_path, "clear", now, now)
        config = {
            "status": {
                "file": str(status_path),
                "stale_seconds": STALE_SECONDS,
                "hold_seconds": 300,
            }
        }
        report = status_report(config, store)
        assert report["state"] == "clear"
        assert report["reason"] == "x"
    finally:
        store.close()
