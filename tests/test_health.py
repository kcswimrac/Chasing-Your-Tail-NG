"""D6 health: per-component failure registry -> status composition.

The registry is the one place components report failures; these tests pin
its contract (idempotent failing_since, explicit recovery, sorted rendering)
and the composition rule the platform exists for: a failing component can
never read as "clear" — clear means "no threat", and a blind sensor cannot
know that.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from cyt_platform.health import (
    ComponentFailureRegistry,
    gps_dropout_reason,
)
from cyt_platform.rf_plugins import RFPluginRunner
from cyt_platform.status import StatusEngine, compose_state
from cyt_platform.store import CytStore


def disabled_rf_config():
    return {
        "rf": {"deauth_enabled": False, "rogue_enabled": False},
        "ie_fingerprint": {"enabled": False},
        "ble_tracker": {"enabled": False},
        "gps_fusion": {"enabled": False},
    }


class BoomDetector:
    """Detector whose scan always raises (the runner must register it)."""

    last_scan_error = None

    def scan_kismet_db(self, db_path, now=None):
        raise RuntimeError("boom")

    def analyze_attacks(self):
        return []


@pytest.fixture
def status_env(tmp_path: Path):
    status_path = tmp_path / "run" / "status.json"
    s = CytStore.open({"path": str(tmp_path / "cyt.db")})
    config = {
        "status": {
            "file": str(status_path),
            "hold_seconds": 300,
            "stale_seconds": 150,
            "deaf_seconds": 180,
            "deaf_is_fail": True,
            "quiet_is_watch": False,
        }
    }
    yield s, StatusEngine(s, config), status_path
    s.close()


def publish_kwargs(now: float) -> dict:
    return {
        "cycle": 1,
        "db_label": "x.kismet",
        "freshness": {
            "max_last_time": now,
            "recent_device_count": 3,
            "age_s": 5,
        },
        "consecutive_fails": 0,
    }


# --- registry contract ----------------------------------------------------------


def test_registry_records_and_clears_failures():
    reg = ComponentFailureRegistry()
    assert reg.failures() == {}
    assert not reg.is_failing("detector:deauth")

    reg.record_failure("detector:deauth", "RuntimeError: boom", ts=100.0)
    assert reg.is_failing("detector:deauth")
    assert reg.failures() == {"detector:deauth": "RuntimeError: boom"}
    assert reg.failing_since("detector:deauth") == 100.0

    reg.record_success("detector:deauth", ts=200.0)
    assert not reg.is_failing("detector:deauth")
    assert reg.failures() == {}
    assert reg.failing_since("detector:deauth") is None
    assert reg.last_ok("detector:deauth") == 200.0


def test_registry_pins_failing_since_and_refreshes_reason():
    reg = ComponentFailureRegistry()
    reg.record_failure("gps", "dropout", ts=100.0)
    reg.record_failure("gps", "no_fix", ts=500.0)
    # First failing cycle pins failing_since; later reports refresh the
    # reason but must not launder the outage duration.
    assert reg.failing_since("gps") == 100.0
    assert reg.failures()["gps"] == "no_fix"


def test_registry_failures_map_is_sorted():
    reg = ComponentFailureRegistry()
    for name in ("detector:rogue", "detector:deauth", "gps"):
        reg.record_failure(name, "x", ts=1.0)
    assert list(reg.failures()) == ["detector:deauth", "detector:rogue", "gps"]


def test_registry_components_rendering():
    reg = ComponentFailureRegistry()
    reg.record_failure("detector:deauth", "scan_error", ts=100.0)
    reg.record_success("gps", ts=150.0)

    rendered = reg.components()
    assert rendered["detector:deauth"] == {
        "ok": False,
        "reason": "scan_error",
        "failing_since": 100.0,
    }
    assert rendered["gps"] == {"ok": True, "last_ok": 150.0}
    # Components that never reported stay absent — the status engine owns
    # the core components it composes itself.
    assert "analyzer" not in rendered


# --- compose_state ladder (shared with StatusEngine.publish) --------------------


def ladder(**overrides):
    """compose_state with the healthy-baseline inputs, overridable."""
    kw = dict(
        component_fail=False,
        deaf_fail_is_fail=False,
        analyzer_err=False,
        kismet_db_ok=True,
        fail_reason=None,
        threat_level=0,
        quiet_watch=False,
        detector_failures={},
    )
    kw.update(overrides)
    return compose_state(**kw)


def test_compose_state_priority_ladder():
    assert ladder() == ("clear", "healthy")
    assert ladder(
        detector_failures={"detector:deauth": "x"}
    ) == ("degraded", "detector_failures: detector:deauth")
    assert ladder(threat_level=1)[0] == "watch"
    assert ladder(threat_level=2)[0] == "alert"
    assert ladder(component_fail=True, threat_level=2)[0] == "fail"
    assert ladder(deaf_fail_is_fail=True)[0] == "fail"


def test_compose_state_fail_reasons_are_preserved():
    assert ladder(component_fail=True, analyzer_err=True)[1] == "analyzer_error"
    assert ladder(component_fail=True, kismet_db_ok=False)[1] == "kismet_db"
    assert ladder(component_fail=True)[1] == "component_fail"
    assert ladder(deaf_fail_is_fail=True)[1] == "deaf"
    assert ladder(component_fail=True, fail_reason="custom")[1] == "custom"


# --- registry -> status composition ---------------------------------------------


def test_status_registry_degrades_with_component_health(status_env):
    store, engine, status_path = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)

    reg = ComponentFailureRegistry()
    reg.record_failure("detector:deauth", "RuntimeError: boom", ts=time.time())
    snap = engine.publish(
        component_registry=reg, **publish_kwargs(time.time())
    )
    assert snap["state"] == "degraded"
    assert snap["state"] != "clear"
    assert snap["reason"].startswith("detector_failures")
    assert "detector:deauth" in snap["reason"]
    # Per-component health renders next to the core components.
    assert snap["components"]["detector:deauth"]["ok"] is False
    assert snap["components"]["detector:deauth"]["reason"] == "RuntimeError: boom"
    assert "failing_since" in snap["components"]["detector:deauth"]
    # The aggregate detectors component stays derived from the same map.
    assert snap["components"]["detectors"]["ok"] is False
    assert snap["components"]["detectors"]["failed"] == {
        "detector:deauth": "RuntimeError: boom"
    }
    on_disk = json.loads(status_path.read_text())
    assert on_disk["state"] == "degraded"
    assert on_disk["components"]["detector:deauth"]["ok"] is False


def test_status_registry_recovery_returns_clear(status_env):
    store, engine, _ = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)

    reg = ComponentFailureRegistry()
    now = time.time()
    reg.record_failure("detector:rogue", "RuntimeError: x", ts=now)
    snap = engine.publish(component_registry=reg, **publish_kwargs(now))
    assert snap["state"] == "degraded"

    reg.record_success("detector:rogue", ts=now + 1)
    snap = engine.publish(
        component_registry=reg, **publish_kwargs(time.time())
    )
    assert snap["state"] == "clear"
    assert snap["components"]["detector:rogue"]["ok"] is True
    assert snap["components"]["detector:rogue"]["last_ok"] == now + 1


def test_registry_never_clobbers_core_components(status_env):
    store, engine, _ = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)

    reg = ComponentFailureRegistry()
    reg.record_success("analyzer", ts=time.time())  # hostile/incorrect usage
    snap = engine.publish(component_registry=reg, **publish_kwargs(time.time()))
    # The engine's own analyzer composition wins.
    assert snap["components"]["analyzer"]["ok"] is True
    assert snap["components"]["analyzer"]["detail"] == "cycle 1"


def test_runner_failure_registry_degrades_status_end_to_end(tmp_path, status_env):
    """Integration: a detector raising mid-run must reach status through the
    shared registry as degraded — never clean, never "no threat"."""
    store, engine, _ = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)

    registry = ComponentFailureRegistry()
    runner = RFPluginRunner(
        store, disabled_rf_config(), registry=registry
    )
    runner.deauth = BoomDetector()
    stats = runner.run_cycle(kdb=None, db_path="unused")
    assert "detector:deauth" in stats["detector_failures"]

    snap = engine.publish(
        detector_failures=stats.get("detector_failures"),
        component_registry=registry,
        **publish_kwargs(time.time()),
    )
    assert snap["state"] == "degraded"
    assert snap["components"]["detector:deauth"]["ok"] is False
    on_disk = json.loads((status_env[2]).read_text())
    assert on_disk["state"] == "degraded"


# --- GPS dropout (pure classifier) -----------------------------------------------


def test_gps_dropout_never_seen_fix_is_no_fix():
    assert (
        gps_dropout_reason(
            last_fix_ts=None, now=1000.0, dropout_seconds=900.0
        )
        == "no_fix"
    )


def test_gps_dropout_never_seen_within_min_cycles_stays_warm():
    assert (
        gps_dropout_reason(
            last_fix_ts=None,
            now=1000.0,
            dropout_seconds=900.0,
            min_cycles_before_dropout=3,
            cycles_seen=1,
        )
        is None
    )
    assert (
        gps_dropout_reason(
            last_fix_ts=None,
            now=1000.0,
            dropout_seconds=900.0,
            min_cycles_before_dropout=3,
            cycles_seen=3,
        )
        == "no_fix"
    )


def test_gps_dropout_fresh_fix_is_healthy():
    assert (
        gps_dropout_reason(last_fix_ts=990.0, now=1000.0, dropout_seconds=900.0)
        is None
    )


def test_gps_dropout_stale_fix_is_dropout():
    assert (
        gps_dropout_reason(last_fix_ts=90.0, now=1000.0, dropout_seconds=900.0)
        == "dropout"
    )


def test_gps_dropout_backwards_clock_reads_fresh():
    assert (
        gps_dropout_reason(last_fix_ts=2000.0, now=1000.0, dropout_seconds=900.0)
        is None
    )


def test_gps_dropout_rejects_nonpositive_window():
    with pytest.raises(ValueError):
        gps_dropout_reason(last_fix_ts=None, now=1000.0, dropout_seconds=0.0)


# --- GPS dropout through the runner ----------------------------------------------


class FakeGps:
    """Scriptable stand-in for LiveGpsFusion (dropouts return None fixes)."""

    def __init__(self, fixes=None):
        self.fixes = list(fixes or [])
        self.last_fix = None

    def ingest_kismet(self, kdb, recent_window_s=120.0, now=None):
        if self.fixes:
            self.last_fix = self.fixes.pop(0)
            return self.last_fix
        return None

    def score_cotravel(self, now=None, obs_index=None):
        return []


def gps_runner(store, **gps_cfg):
    config = disabled_rf_config()
    config["gps_fusion"] = {"enabled": True, **gps_cfg}
    runner = RFPluginRunner(store, config)
    runner.gps = FakeGps()
    return runner


def test_runner_surfaces_gps_never_seen_as_failure(tmp_path):
    store = CytStore.open({"path": str(tmp_path / "g1.db")})
    runner = gps_runner(store)
    stats = runner.run_cycle(kdb=None, db_path="unused", now=1000.0)
    # A dead GPS feed is its own degraded component, not silence.
    assert stats["detector_failures"]["gps"] == "no_fix"
    assert runner.failures()["gps"] == "no_fix"
    assert runner.registry.failing_since("gps") == 1000.0
    store.close()


def test_runner_gps_dropout_after_stale_fix(tmp_path):
    from cyt_platform.gps_live import GpsFix

    store = CytStore.open({"path": str(tmp_path / "g2.db")})
    runner = gps_runner(store)
    runner.gps.fixes = [GpsFix(lat=45.5, lon=-122.6, ts=1000.0)]

    stats = runner.run_cycle(kdb=None, db_path="unused", now=1000.0)
    assert "gps" not in stats["detector_failures"]  # fresh fix: healthy

    # Dropout within the grace window stays healthy (tunnel/cold start).
    stats = runner.run_cycle(kdb=None, db_path="unused", now=1100.0)
    assert "gps" not in stats["detector_failures"]

    # Past the window: the feed is dead and status must see it.
    stats = runner.run_cycle(kdb=None, db_path="unused", now=1901.0)
    assert stats["detector_failures"]["gps"] == "dropout"
    # failing_since pins on the first DECLARED failure: the grace-window
    # cycle (1100) was healthy by contract, so the outage starts there.
    assert runner.registry.failing_since("gps") == 1901.0
    assert runner.registry.last_ok("gps") == 1100.0
    store.close()


def test_runner_gps_dropout_survives_restart_via_runtime_state(tmp_path):
    """The in-memory last fix dies with the process; the persisted runtime
    last fix must still age out, or a restart resets the outage clock."""
    store = CytStore.open({"path": str(tmp_path / "g3.db")})
    store.set_runtime(
        "last_gps", json.dumps({"lat": 45.5, "lon": -122.6, "ts": 100.0})
    )
    runner = gps_runner(store)
    stats = runner.run_cycle(kdb=None, db_path="unused", now=1001.0)
    assert stats["detector_failures"]["gps"] == "dropout"
    store.close()


def test_runner_gps_dropout_min_cycles_grace(tmp_path):
    store = CytStore.open({"path": str(tmp_path / "g4.db")})
    runner = gps_runner(store, dropout_min_cycles=2)
    stats = runner.run_cycle(kdb=None, db_path="unused", now=1000.0)
    assert "gps" not in stats["detector_failures"]  # cycle 1: grace
    stats = runner.run_cycle(kdb=None, db_path="unused", now=1100.0)
    assert stats["detector_failures"]["gps"] == "no_fix"  # cycle 2: blind
    store.close()


def test_status_renders_gps_dropout_component(tmp_path, status_env):
    """Acceptance: GPS dropout surfaces as its own degraded component."""
    store, engine, status_path = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)

    registry = ComponentFailureRegistry()
    runner = gps_runner(store)
    runner.registry = registry
    stats = runner.run_cycle(kdb=None, db_path="unused", now=1000.0)
    assert stats["detector_failures"]["gps"] == "no_fix"

    snap = engine.publish(
        component_registry=registry, **publish_kwargs(1000.0)
    )
    assert snap["state"] == "degraded"
    gps_component = snap["components"]["gps"]
    assert gps_component["ok"] is False
    assert gps_component["reason"] == "no_fix"
    on_disk = json.loads(status_path.read_text())
    assert on_disk["state"] == "degraded"
    assert on_disk["components"]["gps"]["ok"] is False
