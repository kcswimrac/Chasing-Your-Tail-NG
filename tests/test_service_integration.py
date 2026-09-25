"""S18: the service loop runs the real cycle path end to end.

These tests execute ``service.run(max_cycles=N)`` against a fixture Kismet
capture DB. They are the acceptance gate for the B1/B2 bundle — the
production wiring the adversarial review found entirely untested:

(a) a single ``mac_reappear`` in the 15-20 minute window cannot produce
    ``state == "alert"`` — the lifecycle, not the static window map,
    owns severity;
(b) a single BLE tracker advertisement cannot either — even though its
    detector row carries static severity ``alert``, the published state
    ignores detector-owned severity (the B2 proof);
(c) a restart mid-stream continues the same phenomenon incident key
    instead of duplicating incidents.

Every test asserts a ``ph:`` phenomenon row exists: without the B1 wiring
the detector row would drive status to alert and fail these tests, so a
vacuous pass (engine silently skipped) is impossible.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from cyt_platform.service import run
from cyt_platform.store import CytStore

WINDOW_MAC = "AA:BB:CC:11:22:33"
TILE_MAC = "DD:DD:DD:DD:DD:02"


def _write_capture_db(path: Path, now: float, mac: str | None, tile: bool) -> Path:
    """Minimal Kismet-shaped capture DB with the requested device rows."""
    db = path / "capture.kismet"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE devices (devmac TEXT, type TEXT, device TEXT, last_time INTEGER)"
    )
    conn.execute("CREATE TABLE alerts (ts_sec INTEGER, header TEXT, json TEXT)")
    if mac is not None:
        # Two snapshots of one MAC, as a real capture records: the older
        # one feeds the 15-20 minute window list at init, the current one
        # is what the activity scan sees — one reappearance.
        conn.execute(
            "INSERT INTO devices VALUES (?, ?, ?, ?)",
            (mac, "Wi-Fi device", json.dumps({}), int(now - 17 * 60)),
        )
        conn.execute(
            "INSERT INTO devices VALUES (?, ?, ?, ?)",
            (mac, "Wi-Fi device", json.dumps({}), int(now)),
        )
    if tile:
        conn.execute(
            "INSERT INTO devices VALUES (?, ?, ?, ?)",
            (
                TILE_MAC,
                "BTLE",
                json.dumps({"kismet.device.base.commonname": "Tile"}),
                int(now),
            ),
        )
    conn.commit()
    conn.close()
    return db


def _write_config(tmp: Path, db: Path) -> Path:
    cfg = {
        "store": {"path": str(tmp / "cyt.db")},
        "paths": {
            "kismet_logs": str(db),
            "log_dir": str(tmp / "logs"),
        },
        "status": {"file": str(tmp / "run" / "status.json")},
        "timing": {"check_interval": 0.05, "list_update_interval": 5},
        "push": {"enabled": False},
        "baseline": {"enabled": False},
        "service": {"kismet_proc_check": False},
    }
    cfg_path = tmp / "config.json"
    cfg_path.write_text(json.dumps(cfg))
    return cfg_path


def _incident_rows(store_path: Path):
    store = CytStore.open({"path": str(store_path)})
    try:
        return store.conn.execute(
            "SELECT incident_key, event_type, severity, lifecycle_state "
            "FROM incidents ORDER BY incident_key"
        ).fetchall()
    finally:
        store.close()


def _snapshot(status_path: Path) -> dict:
    return json.loads(status_path.read_text())


def _run_service(tmp: Path, mac: str | None, tile: bool) -> None:
    now = time.time()
    db = _write_capture_db(tmp, now, mac, tile)
    cfg_path = _write_config(tmp, db)
    assert run(str(cfg_path), max_cycles=1) == 0


def test_single_mac_reappear_cannot_alert(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_service(tmp, mac=WINDOW_MAC, tile=False)

    snap = _snapshot(tmp / "run" / "status.json")
    assert snap["state"] != "alert"

    rows = _incident_rows(tmp / "cyt.db")
    phenomena = [r for r in rows if str(r["incident_key"]).startswith("ph:")]
    assert phenomena, "engine never ran — no phenomenon row in the live path"
    assert all(r["lifecycle_state"] != "alert" for r in phenomena)
    # The static window map would have said alert (15-20); the lifecycle
    # must own the published severity instead.
    detector_rows = [r for r in rows if not str(r["incident_key"]).startswith("ph:")]
    assert any(r["event_type"] == "mac_reappear" for r in detector_rows)


def test_single_ble_tile_advertisement_cannot_alert(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_service(tmp, mac=None, tile=True)

    snap = _snapshot(tmp / "run" / "status.json")
    assert snap["state"] != "alert"

    rows = _incident_rows(tmp / "cyt.db")
    phenomena = [r for r in rows if str(r["incident_key"]).startswith("ph:")]
    assert phenomena, "engine never ran — no phenomenon row in the live path"
    assert all(r["lifecycle_state"] != "alert" for r in phenomena)
    # B2 proof: the detector row is statically alert-severe, and the
    # published state ignored it.
    tile_rows = [r for r in rows if r["severity"] == "alert"]
    assert any(TILE_MAC in str(r["incident_key"]) for r in tile_rows)


def test_restart_continues_incident_keys_without_duplicates(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_service(tmp, mac=WINDOW_MAC, tile=False)

    first = [
        r
        for r in _incident_rows(tmp / "cyt.db")
        if str(r["incident_key"]).startswith("ph:")
    ]
    assert len(first) == 1

    # Second boot against the same store and capture: the reappearance is
    # re-detected under a new session, and the same phenomenon continues.
    _run_service(tmp, mac=WINDOW_MAC, tile=False)

    second = [
        r
        for r in _incident_rows(tmp / "cyt.db")
        if str(r["incident_key"]).startswith("ph:")
    ]
    assert len(second) == 1, "restart duplicated the phenomenon incident"
    assert second[0]["incident_key"] == first[0]["incident_key"]

    snap = _snapshot(tmp / "run" / "status.json")
    assert snap["state"] != "alert"
