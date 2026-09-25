"""B6: live alert provenance — every alert cites its observations, and the
store exports to a scenario that replays to identical incidents.

These tests execute the real service cycle against a fixture Kismet capture
DB, the same way tests/test_service_integration.py does, then exercise the
export -> replay path end to end:

1. a live deauth detector incident whose evidence lines carry non-empty
   obs_ids, every one resolvable to a kismet.alerts observation recorded in
   the same cycle (the ingest runs inside the cycle transaction);
2. the lifecycle phenomenon row fusing that evidence keeps the ids through
   the _row_evidence_lines fallback;
3. exporting the store produces a deterministic v1 scenario document whose
   replay files the same detector incidents as the live run.

The window matcher is service-only (the replay engine runs the RF detector
pipeline, not SecureCYTMonitor), so the parity projection compares
detector-filed rows (lifecycle_state IS NULL) — the same boundary the
adversarial review's D7 row records.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from cyt_platform.observations import (
    SOURCE_KISMET_ALERTS,
    CycleObsIndex,
    attach_obs_ids,
)
from cyt_platform.replay.engine import ReplayEngine
from cyt_platform.replay.scenario import (
    ScenarioError,
    scenario_from_dict,
    scenario_from_observations,
)
from cyt_platform.service import run
from cyt_platform.store import CytStore

ATTACKER = "AA:BB:CC:00:99:01"
VICTIM = "AA:BB:CC:00:02:22"


def _write_capture_db(path: Path, now: float) -> Path:
    """Kismet-shaped capture: one device snapshot plus one deauth attack.

    A single device row (no 15-20 minute reappearance) keeps the window
    matcher quiet, so the only detector incident is the deauth attack —
    six alert rows, the default min_events_for_attack, from one attacker
    to one victim.
    """
    db = path / "capture.kismet"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE devices (devmac TEXT, type TEXT, device TEXT, last_time INTEGER)"
    )
    conn.execute(
        "CREATE TABLE alerts (ts_sec INTEGER, header TEXT, json TEXT, "
        "src_mac TEXT, dst_mac TEXT, bssid TEXT)"
    )
    conn.execute(
        "INSERT INTO devices VALUES (?, ?, ?, ?)",
        (
            VICTIM,
            "Wi-Fi device",
            json.dumps(
                {
                    "kismet.device.base.signal": {
                        "kismet.common.signal.last_signal": -58
                    }
                }
            ),
            int(now),
        ),
    )
    alert_json = json.dumps(
        {
            "kismet.alert.header": "DEAUTH DISASSOC",
            "kismet.alert.text": "AP sends deauth (station)",
            "kismet.alert.source_mac": ATTACKER,
            "kismet.alert.dest_mac": VICTIM,
            "kismet.alert.channel": 6,
        }
    )
    for i in range(6):
        conn.execute(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
            (
                int(now) - 10 + i,
                "DEAUTH DISASSOC",
                alert_json,
                ATTACKER,
                VICTIM,
                "",
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


def _run_live_session(tmp: Path) -> None:
    now = time.time()
    db = _write_capture_db(tmp, now)
    cfg_path = _write_config(tmp, db)
    assert run(str(cfg_path), max_cycles=1) == 0


def _open_store(tmp: Path) -> CytStore:
    return CytStore.open({"path": str(tmp / "cyt.db")})


def _detector_incidents(store: CytStore):
    return store.conn.execute(
        "SELECT i.event_type, e.key AS entity_key, e.entity_type, "
        "i.window_label, i.severity, i.lifecycle_state "
        "FROM incidents i JOIN entities e ON e.id = i.entity_id "
        "WHERE i.lifecycle_state IS NULL ORDER BY i.incident_key"
    ).fetchall()


def _evidence_obs_ids(evidence_json: str | None) -> list[int]:
    """Every obs_id on the why/against lines of a stored evidence block."""
    if not evidence_json:
        return []
    block = json.loads(evidence_json).get("fusion") or {}
    ids: list[int] = []
    for line in list(block.get("why") or []) + list(block.get("against") or []):
        ids.extend(int(i) for i in line.get("obs_ids") or [])
    return ids


# --- pure behaviors ----------------------------------------------------------


def test_attach_obs_ids_fills_empty_lines_only():
    from cyt_platform.detectors import DetectionResult, EvidenceLine

    result = DetectionResult(
        detector="x",
        kind="x",
        subject="AA:BB:CC:00:00:01",
        subject_type="wifi_mac",
        window_label="w",
        severity="watch",
        observed_at=1.0,
        summary="s",
        evidence=(
            EvidenceLine("a", "no ids", obs_ids=()),
            EvidenceLine("b", "kept", obs_ids=(7,)),
        ),
        contra=(EvidenceLine("c", "contra", obs_ids=()),),
    )
    filled = attach_obs_ids(result, (3, 4))
    assert filled.evidence[0].obs_ids == (3, 4)
    assert filled.evidence[1].obs_ids == (7,)  # existing ids never replaced
    assert filled.contra[0].obs_ids == (3, 4)
    assert attach_obs_ids(result, ()) is result  # empty: untouched, not cleared


def test_cycle_index_lookups():
    rows = [
        {"id": 1, "ts": 100.0, "source": "kismet.alerts", "identity_key": "AA:BB:CC:00:99:01"},
        {"id": 2, "ts": 100.0, "source": "kismet.alerts", "identity_key": "AA:BB:CC:00:02:22"},
        {"id": 3, "ts": 101.0, "source": "kismet.devices", "identity_key": "aa:bb:cc:00:02:22"},
        {"id": 4, "ts": 100.0, "source": "gps", "identity_key": "operator"},
    ]
    index = CycleObsIndex(rows)
    assert index.ids_for_identity("AA:BB:CC:00:99:01") == (1,)
    # MAC case-normalized on both write and lookup
    assert index.ids_for_identity("aa:bb:cc:00:02:22") == (2, 3)
    assert index.ids_for_identity("DE:AD:BE:EF:00:00") == ()
    assert index.ids_for_alert_ts(100.0, (ATTACKER,)) == (1,)
    # No mac-matched id at that second: the ts bucket over alert-source rows
    # is the documented superset — contains the producing row rather than an
    # empty miss (GPS/device rows are never alert evidence).
    assert index.ids_for_alert_ts(100.0, ("DE:AD:BE:EF:00:00",)) == (1, 2)
    assert index.ids_for_alert_ts(42.0) == ()


# --- live session provenance -------------------------------------------------


def test_live_session_deauth_evidence_cites_observations(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_live_session(tmp)
    store = _open_store(tmp)
    try:
        rows = store.conn.execute(
            "SELECT evidence_json, last_seen FROM incidents "
            "WHERE event_type='deauth_attack' AND lifecycle_state IS NULL"
        ).fetchall()
        assert rows, "live run must file a deauth detector incident"
        for row in rows:
            ids = _evidence_obs_ids(row["evidence_json"])
            assert ids, "deauth evidence must cite its observations (B6)"
            cited = store.conn.execute(
                f"SELECT id, source, kind, cycle_id, ts FROM observations "
                f"WHERE id IN ({','.join('?' * len(ids))})",
                ids,
            ).fetchall()
            assert len(cited) == len(set(ids)), "every cited id must exist"
            assert all(
                c["source"] == SOURCE_KISMET_ALERTS and c["kind"] == "deauth_alert"
                for c in cited
            )
            # Provenance is time-honest: the cited rows are the attack's
            # own alert rows (last_seen minus the minute-scale freshness
            # window must still contain every cited ts).
            assert all(
                abs(c["ts"] - row["last_seen"]) < 600 for c in cited
            )
    finally:
        store.close()


def test_live_session_phenomenon_fuses_provenance_bearing_rows(tmp_path: Path):
    """The lifecycle runs live and consumes the provenance-bearing rows.

    The phenomenon row itself carries the fused confidence; its why/against
    evidence block is the engine's own storage design (the wiring PR's),
    so provenance is asserted on the detector row the engine fused.
    """
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_live_session(tmp)
    store = _open_store(tmp)
    try:
        ph_rows = store.conn.execute(
            "SELECT incident_key, confidence FROM incidents "
            "WHERE incident_key LIKE 'ph:%' AND lifecycle_state IS NOT NULL"
        ).fetchall()
        assert ph_rows, "the lifecycle engine must run in the live service"
        assert any(r["confidence"] is not None for r in ph_rows)

        # The detector rows the phenomenon fused cite their observations.
        detector_ev = store.conn.execute(
            "SELECT evidence_json FROM incidents WHERE lifecycle_state IS NULL"
        ).fetchall()
        assert detector_ev, "the deauth detector row must exist"
        assert any(_evidence_obs_ids(r["evidence_json"]) for r in detector_ev), (
            "detector evidence must cite its observations (B6)"
        )
    finally:
        store.close()


# --- export -> replay parity -------------------------------------------------


def test_export_replay_parity(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_live_session(tmp)

    store = _open_store(tmp)
    try:
        doc = scenario_from_observations(store)
        scenario = scenario_from_dict(doc)
        assert scenario.cycles, "the export must carry at least one cycle"

        engine = ReplayEngine(scenario, store_path=tmp / "replay.db")
        engine.run()

        replay_store = CytStore.open({"path": str(tmp / "replay.db")})
        try:
            live = [
                (r["event_type"], r["entity_key"], r["window_label"], r["severity"])
                for r in _detector_incidents(store)
                if r["event_type"] != "mac_reappear"  # window matcher: service-only
            ]
            replayed = [
                (r["event_type"], r["entity_key"], r["window_label"], r["severity"])
                for r in _detector_incidents(replay_store)
            ]
        finally:
            replay_store.close()
    finally:
        store.close()
    assert live, "the live run must have filed detector incidents"
    assert replayed, "the replayed export must have filed detector incidents"
    assert live == replayed, "replay must file identical incidents to the live run"


def test_export_is_deterministic(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_live_session(tmp)
    store = _open_store(tmp)
    try:
        one = json.dumps(
            scenario_from_observations(store), indent=2, sort_keys=True
        )
        two = json.dumps(
            scenario_from_observations(store), indent=2, sort_keys=True
        )
    finally:
        store.close()
    assert one == two
    # Round-trip: the exporter's own output revalidates as a scenario.
    scenario_from_dict(json.loads(one))


def test_export_respects_since_until(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_live_session(tmp)
    store = _open_store(tmp)
    try:
        newest = store.conn.execute("SELECT MAX(ts) AS m FROM observations").fetchone()[
            "m"
        ]
        oldest = store.conn.execute("SELECT MIN(ts) AS m FROM observations").fetchone()[
            "m"
        ]
        full = scenario_from_observations(store)
        head = scenario_from_observations(store, until_ts=oldest + 1)
        tail = scenario_from_observations(store, since_ts=newest - 1)
        with pytest.raises(ScenarioError):
            scenario_from_observations(store, since_ts=newest + 10)
    finally:
        store.close()
    full_rows = sum(len(c.rows) for c in scenario_from_dict(full).cycles)
    head_rows = sum(len(c.rows) for c in scenario_from_dict(head).cycles)
    tail_rows = sum(len(c.rows) for c in scenario_from_dict(tail).cycles)
    assert 0 < head_rows < full_rows
    assert 0 < tail_rows < full_rows
    assert head_rows + tail_rows <= full_rows


def test_cli_export_writes_file(tmp_path: Path):
    tmp = tmp_path / "svc"
    tmp.mkdir()
    _run_live_session(tmp)
    out = tmp / "export.json"
    from cyt_platform.__main__ import main

    code = main(
        [
            "-c",
            str(tmp / "config.json"),
            "export",
            "--out",
            str(out),
            "--scenario-id",
            "parity-check",
        ]
    )
    assert code == 0
    doc = json.loads(out.read_text())
    assert doc["scenario_version"] == 1
    assert doc["scenario_id"] == "parity-check"
    assert doc["cycles"]
    scenario_from_dict(doc)  # the CLI output loads as a valid scenario
