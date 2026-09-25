"""P0 reliability: read-only capture opens, restart watermark, failure-visible status."""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from cyt_platform import deauth_detector, rogue_ap_detector
from cyt_platform.kismet_ro import connect_readonly
from cyt_platform.rf_plugins import (
    DEAUTH_WATERMARK_KEY,
    ROGUE_WATERMARK_KEY,
    RFPluginRunner,
    _runtime_watermark_loader,
    _runtime_watermark_saver,
)
from cyt_platform.status import StatusEngine
from cyt_platform.store import CytStore


def make_kismet_db(
    tmp_path: Path,
    alert_ts: int,
    alert_header: str = "DEAUTH",
    alert_text: str = "deauth flood detected",
) -> Path:
    """Minimal Kismet-shaped capture DB with one alert row."""
    db = tmp_path / "capture.kismet"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE alerts (ts_sec INTEGER, header TEXT, json TEXT)")
    conn.execute(
        """CREATE TABLE devices
           (devmac TEXT, type TEXT, device TEXT, last_time INTEGER)"""
    )
    conn.execute(
        "INSERT INTO alerts VALUES (?, ?, ?)",
        (
            alert_ts,
            alert_header,
            json.dumps(
                {
                    "kismet.alert.header": alert_header,
                    "kismet.alert.text": alert_text,
                    "kismet.alert.source_mac": "AA:BB:CC:DD:EE:01",
                    "kismet.alert.dest_mac": "AA:BB:CC:DD:EE:02",
                    "kismet.alert.channel": 6,
                }
            ),
        ),
    )
    conn.commit()
    conn.close()
    return db


def add_deauth_alert(db: Path, alert_ts: int, src: str) -> None:
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO alerts VALUES (?, ?, ?)",
        (
            alert_ts,
            "DEAUTH",
            json.dumps(
                {
                    "kismet.alert.header": "DEAUTH",
                    "kismet.alert.text": "deauth flood detected",
                    "kismet.alert.source_mac": src,
                    "kismet.alert.dest_mac": "AA:BB:CC:DD:EE:02",
                }
            ),
        ),
    )
    conn.commit()
    conn.close()


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


# --- read-only capture opens -------------------------------------------------


def test_connect_readonly_reads_but_never_writes(tmp_path):
    db = make_kismet_db(tmp_path, alert_ts=int(time.time()) - 60)
    conn = connect_readonly(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM alerts")
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO alerts VALUES (1, 'x', '{}')")
    finally:
        conn.close()
    # The write attempts must not have mutated the capture data.
    conn2 = sqlite3.connect(str(db))
    assert conn2.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    conn2.close()


def test_connect_readonly_never_creates_missing_capture_file(tmp_path):
    missing = tmp_path / "absent.kismet"
    with pytest.raises(sqlite3.OperationalError):
        connect_readonly(str(missing))
    # A plain read-write connect would have silently created the file.
    assert not missing.exists()


def test_deauth_detector_opens_capture_readonly(tmp_path, monkeypatch):
    db = make_kismet_db(tmp_path, alert_ts=int(time.time()) - 60)
    real = deauth_detector.connect_readonly
    opened = []

    def spy(path, timeout=30.0):
        opened.append(path)
        return real(path, timeout)

    monkeypatch.setattr(deauth_detector, "connect_readonly", spy)
    det = deauth_detector.DeauthDetector({})
    det.scan_kismet_db(str(db))
    assert opened == [str(db)]


def test_rogue_detector_opens_capture_readonly(tmp_path, monkeypatch):
    db = make_kismet_db(tmp_path, alert_ts=int(time.time()) - 60)
    real = rogue_ap_detector.connect_readonly
    opened = []

    def spy(path, timeout=30.0):
        opened.append(path)
        return real(path, timeout)

    monkeypatch.setattr(rogue_ap_detector, "connect_readonly", spy)
    det = rogue_ap_detector.RogueAPDetector({})
    det.scan_kismet_db(str(db))
    assert opened == [str(db)]


# --- restart watermark --------------------------------------------------------


def wired_loader_saver(store):
    return (
        _runtime_watermark_loader(store, DEAUTH_WATERMARK_KEY),
        _runtime_watermark_saver(store, DEAUTH_WATERMARK_KEY),
    )


def test_restart_does_not_refile_processed_alerts(tmp_path):
    now = int(time.time())
    db = make_kismet_db(tmp_path, alert_ts=now - 600)
    store = CytStore.open({"path": str(tmp_path / "wm.db")})
    loader, saver = wired_loader_saver(store)

    # Session 1: alert processed, watermark durably past it.
    det1 = deauth_detector.DeauthDetector(
        {}, watermark_loader=loader, watermark_saver=saver
    )
    events1 = det1.scan_kismet_db(str(db))
    assert [e.timestamp for e in events1] == [float(now - 600)]
    wm1 = float(store.get_runtime(DEAUTH_WATERMARK_KEY))
    assert wm1 == float(now - 600 + 1)

    # Restart: brand-new detector, same persisted watermark — the historical
    # alert must not be re-emitted as fresh.
    det2 = deauth_detector.DeauthDetector(
        {}, watermark_loader=loader, watermark_saver=saver
    )
    assert det2.last_scan_time == wm1
    assert det2.scan_kismet_db(str(db)) == []

    # A genuinely new alert after the watermark is caught exactly once.
    add_deauth_alert(db, now + 5, src="AA:BB:CC:DD:EE:09")
    events3 = det2.scan_kismet_db(str(db))
    assert [e.timestamp for e in events3] == [float(now + 5)]
    assert float(store.get_runtime(DEAUTH_WATERMARK_KEY)) == float(now + 6)
    store.close()


def test_restart_does_not_refile_processed_rogue_alerts(tmp_path):
    now = int(time.time())
    db = make_kismet_db(
        tmp_path,
        alert_ts=now - 300,
        alert_header="APSPOOF",
        alert_text="AP spoof detected",  # matches rogue ap_keywords
    )
    store = CytStore.open({"path": str(tmp_path / "wm2.db")})
    loader = _runtime_watermark_loader(store, ROGUE_WATERMARK_KEY)
    saver = _runtime_watermark_saver(store, ROGUE_WATERMARK_KEY)

    det1 = rogue_ap_detector.RogueAPDetector(
        {}, watermark_loader=loader, watermark_saver=saver
    )
    assert len(det1.scan_kismet_db(str(db))) == 1
    assert float(store.get_runtime(ROGUE_WATERMARK_KEY)) == float(now - 300 + 1)

    det2 = rogue_ap_detector.RogueAPDetector(
        {}, watermark_loader=loader, watermark_saver=saver
    )
    assert det2.scan_kismet_db(str(db)) == []
    store.close()


def test_first_run_against_old_capture_does_not_flood(tmp_path):
    # No watermark at all: look-back is bounded by the catch-up window, so a
    # service start against an old capture DB never replays days of history.
    now = int(time.time())
    db = make_kismet_db(tmp_path, alert_ts=now - 7200)  # 2h old
    det = deauth_detector.DeauthDetector({})
    assert det.scan_kismet_db(str(db)) == []


def test_long_outage_does_not_replay_unbounded_history(tmp_path):
    # Watermark exists but is older than the catch-up window (service was
    # down): reads stay bounded, never the full alerts table.
    now = int(time.time())
    db = make_kismet_db(tmp_path, alert_ts=now - 7200)
    det = deauth_detector.DeauthDetector(
        {}, watermark_loader=lambda: float(now - 7200 + 1)
    )
    assert det.scan_kismet_db(str(db)) == []


def test_failed_scan_does_not_advance_watermark(tmp_path):
    db = make_kismet_db(tmp_path, alert_ts=int(time.time()) - 60)
    saves = []
    det = deauth_detector.DeauthDetector(
        {}, watermark_saver=lambda ts: saves.append(ts)
    )
    # First scan processes the alert and persists the watermark.
    assert len(det.scan_kismet_db(str(db))) == 1
    wm = det.last_scan_time
    assert saves == [wm]
    # Second scan fails (missing file): error recorded, watermark unchanged,
    # no further watermark persistence.
    det.scan_kismet_db(str(tmp_path / "missing.kismet"))
    assert det.last_scan_error is not None
    assert det.last_scan_time == wm
    assert saves == [wm]


# --- failure-visible status ---------------------------------------------------


def disabled_rf_config():
    return {
        "rf": {"deauth_enabled": False, "rogue_enabled": False},
        "ie_fingerprint": {"enabled": False},
        "ble_tracker": {"enabled": False},
        "gps_fusion": {"enabled": False},
    }


class BoomDetector:
    last_scan_error = None

    def scan_kismet_db(self, db_path, now=None):
        raise RuntimeError("boom")

    def analyze_attacks(self):
        return []


class SwallowingDetector:
    """Mimics a detector that logs an internal error and returns no data."""

    last_scan_error = "kismet_db_error: database disk image is malformed"

    def scan_kismet_db(self, db_path, now=None):
        return []

    def analyze_attacks(self):
        return []


class HealthyDetector:
    last_scan_error = None

    def scan_kismet_db(self, db_path, now=None):
        return []

    def analyze_attacks(self):
        return []


def test_runner_records_raising_detector(tmp_path):
    runner = RFPluginRunner(
        CytStore.open({"path": str(tmp_path / "r.db")}), disabled_rf_config()
    )
    runner.deauth = BoomDetector()
    stats = runner.run_cycle(kdb=None, db_path="unused")
    assert "detector:deauth" in stats["detector_failures"]
    assert "RuntimeError" in stats["detector_failures"]["detector:deauth"]
    runner.store.close()


def test_runner_records_swallowed_scan_error(tmp_path):
    runner = RFPluginRunner(
        CytStore.open({"path": str(tmp_path / "r2.db")}), disabled_rf_config()
    )
    runner.deauth = SwallowingDetector()
    stats = runner.run_cycle(kdb=None, db_path="unused")
    assert (
        stats["detector_failures"]["detector:deauth"]
        == "kismet_db_error: database disk image is malformed"
    )
    runner.store.close()


def test_runner_records_import_failure_and_clears_on_recovery(tmp_path, monkeypatch):
    store = CytStore.open({"path": str(tmp_path / "r3.db")})
    config = disabled_rf_config()
    config["rf"]["deauth_enabled"] = True
    monkeypatch.setitem(sys.modules, "cyt_platform.deauth_detector", None)
    runner = RFPluginRunner(store, config)
    assert "detector:deauth" in runner.failures()
    stats = runner.run_cycle(kdb=None, db_path="unused")
    assert "detector:deauth" in stats["detector_failures"]

    # Recovery: a working detector clears the failure so status can return
    # to non-degraded on the next cycle.
    runner.deauth = HealthyDetector()
    stats = runner.run_cycle(kdb=None, db_path="unused")
    assert "detector:deauth" not in stats["detector_failures"]
    store.close()


def test_status_degraded_while_detector_failing(status_env):
    store, engine, status_path = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    snap = engine.publish(
        detector_failures={"detector:deauth": "RuntimeError: boom"},
        **publish_kwargs(time.time()),
    )
    assert snap["state"] == "degraded"
    assert snap["state"] != "clear"
    assert snap["reason"].startswith("detector_failures")
    assert "detector:deauth" in snap["reason"]
    assert snap["components"]["detectors"]["ok"] is False
    assert snap["components"]["detectors"]["failed"] == {
        "detector:deauth": "RuntimeError: boom"
    }
    # Snapshot on disk must carry the degraded state too.
    on_disk = json.loads(status_path.read_text())
    assert on_disk["state"] == "degraded"
    assert on_disk["components"]["detectors"]["ok"] is False


def test_status_no_failures_still_clear(status_env):
    store, engine, _ = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    snap = engine.publish(**publish_kwargs(time.time()))
    assert snap["state"] == "clear"
    assert snap["components"]["detectors"]["ok"] is True


def test_threat_states_outrank_degraded(status_env):
    store, engine, _ = status_env
    sid = store.begin_session()
    now = time.time()
    with store.transaction():
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:DD:EE:42",
            window_label="15-20",
            severity="alert",
            session_id=sid,
            observed_at=now,
            summary="a",
        )
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    snap = engine.publish(
        detector_failures={"detector:rogue": "RuntimeError: x"},
        **publish_kwargs(now),
    )
    assert snap["state"] == "alert"


def test_failing_detector_pipeline_ends_degraded(tmp_path, status_env):
    # Integration: RFPluginRunner failure map -> StatusEngine publish.
    runner = RFPluginRunner(
        CytStore.open({"path": str(tmp_path / "r4.db")}), disabled_rf_config()
    )
    runner.deauth = BoomDetector()
    stats = runner.run_cycle(kdb=None, db_path="unused")
    runner.store.close()

    store, engine, _ = status_env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    snap = engine.publish(
        detector_failures=stats["detector_failures"],
        **publish_kwargs(time.time()),
    )
    assert snap["state"] == "degraded"
    assert "detector:deauth" in snap["components"]["detectors"]["failed"]