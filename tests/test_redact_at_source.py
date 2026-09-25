"""N13 regression: plain identifying strings must never reach output surfaces.

The D9 redaction suite (tests/test_evidence_redaction.py) plants markup
payloads — script tags, CDATA terminators, control characters. Redaction
passed every one of those while plain, non-hostile, identifying strings
sailed through the detectors' own reason interpolations into status.json,
the ntfy push body, replay reports, and the debrief (findings B3, S7, S8).

These tests plant exactly the plain strings the adversarial review proved
leaking — "Canete Family Home 5G" (the operator's trusted SSID) and
"Kristophers AirTag" (a bystander's device name) — at the source each
detector builds, and assert their absence from every downstream surface:

* detector reason text (rogue AP + BLE tracker),
* status.json and the push queue body, end to end through the real
  result builders, fusion attach, store, status engine, and push queue,
* replay reports for a real corpus scenario,
* the debrief markdown (reasons + entity keys),
* log records, via the PrivacyFilter on the real handlers (S7).

Panic-wipe coverage of debrief files lives in tests/test_wipe.py.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest

from conftest import escalate_lifecycle
from cyt_platform.ble_tracker import BLETrackerEngine, _ble_result, tracker_score
from cyt_platform.debrief import generate_debrief
from cyt_platform.logging_setup import setup_logging
from cyt_platform.detectors import incident_fields
from cyt_platform.fused_evidence import attach as attach_fusion
from cyt_platform.privacy import (
    configured_subjects,
    redact_subjects_in_text,
)
from cyt_platform.push import PushQueue
from cyt_platform.replay.engine import ReplayEngine
from cyt_platform.replay.scenario import load_scenario
from cyt_platform.rf_plugins import _rogue_result
from cyt_platform.rogue_ap_detector import RogueAPDetector
from cyt_platform.status import StatusEngine
from cyt_platform.store import CytStore

SSID = "Canete Family Home 5G"
BLE_NAME = "Kristophers AirTag"
TRUSTED_BSSID = "AA:BB:CC:DD:EE:01"
ROGUE_BSSID = "DE:AD:BE:EF:00:07"


# --- helpers --------------------------------------------------------------------------


@pytest.fixture
def isolated_root_logging():
    """Run a test with setup_logging() handlers on root, then restore."""
    root = logging.getLogger()
    saved = root.handlers[:]
    yield root
    for handler in root.handlers[:]:
        if handler not in saved:
            handler.close()
        root.removeHandler(handler)
    root.handlers[:] = saved


def _rogue_config() -> dict:
    return {
        "rogue_ap_detection": {
            "trusted_aps": [
                {"ssid": SSID, "bssid": TRUSTED_BSSID, "encryption": "WPA2"}
            ],
        }
    }


def _rogue_detector() -> RogueAPDetector:
    return RogueAPDetector(_rogue_config())


def _ble_device(name: str = BLE_NAME) -> dict:
    return {
        "mac": "AA:BB:CC:DD:EE:09",
        "type": "BTLE Device",
        "device_data": {
            "kismet.device.base.type": "BTLE Device",
            "kismet.device.base.commonname": name,
        },
    }


def _rogue_fixture_db(path: Path, *, ssid: str, bssid: str, last_time: float) -> Path:
    """Minimal Kismet-shaped capture DB with one AP advertising ``ssid``."""
    import sqlite3

    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(
            """
            CREATE TABLE devices (
              devmac     TEXT NOT NULL,
              type       TEXT,
              device     TEXT,
              last_time  REAL NOT NULL,
              first_time REAL
            );
            """
        )
        device_json = json.dumps(
            {
                "dot11.device": {
                    "dot11.device.advertised_ssid_map": {
                        "0": {
                            "dot11.advertisedssid.ssid": ssid,
                            "dot11.advertisedssid.crypt_string": "WPA2-PSK",
                        }
                    }
                }
            }
        )
        conn.execute(
            "INSERT INTO devices(devmac, type, device, last_time, first_time)"
            " VALUES (?, ?, ?, ?, ?)",
            (bssid, "Wi-Fi AP", device_json, last_time, last_time),
        )
        conn.commit()
    finally:
        conn.close()
    return path


# --- privacy helpers (new surface) -----------------------------------------------------


def test_configured_subjects_extracts_operator_ssids():
    config = {
        "rogue_ap_detection": {
            "monitored_ssids": ["HomeNet"],
            "trusted_aps": [
                {"ssid": SSID, "bssid": TRUSTED_BSSID},
                {"bssid": "AA:BB:CC:DD:EE:02"},  # no ssid — ignored
            ],
        }
    }
    assert configured_subjects(config) == sorted({SSID, "HomeNet"})


def test_redact_subjects_in_text_replaces_longest_first():
    subjects = ["Home", SSID]
    out = redact_subjects_in_text(f"probe for {SSID} near Home", subjects)
    assert SSID not in out
    assert "ssid(len=" in out
    # The short subject is still redacted, and no partial token was left
    # behind by a shorter replacement running first.
    assert "probe for" in out
    assert "Home" not in out.replace("HomeNet", "")  # sanity: input had it


# --- B3: rogue AP detector source ------------------------------------------------------


def test_rogue_evil_twin_reason_has_no_raw_ssid():
    detector = _rogue_detector()
    alert = detector._check_against_trusted(
        SSID, ROGUE_BSSID, "WPA2", 6, 1700000000.0
    )
    assert alert is not None, "evil twin must still be detected"
    # The subject itself stays intact for correlation/dedup — only the
    # reason text is a render surface.
    assert alert.ssid == SSID
    joined = " | ".join(alert.reasons)
    assert SSID not in joined
    assert "ssid(len=" in joined
    assert "EVIL TWIN" in joined  # the finding stays explainable


def test_rogue_new_bssid_reason_has_no_raw_ssid(tmp_path):
    detector = RogueAPDetector(
        {"rogue_ap_detection": {"monitored_ssids": [SSID]}}
    )
    detector.seen_bssids[SSID].add(TRUSTED_BSSID)
    db = _rogue_fixture_db(
        tmp_path / "kismet.db", ssid=SSID, bssid=ROGUE_BSSID, last_time=1700000000.0
    )
    alerts = detector.scan_kismet_db(str(db), now=1700000060.0)
    assert alerts, "new-BSSID alert must still be detected"
    joined = " | ".join(alerts[0].reasons)
    assert SSID not in joined
    assert "ssid(len=" in joined
    assert "New BSSID detected" in joined


def test_rogue_learned_ap_log_line_has_no_raw_ssid(tmp_path, caplog):
    detector = RogueAPDetector(
        {"rogue_ap_detection": {"monitored_ssids": [SSID], "auto_learn": True}}
    )
    db = _rogue_fixture_db(
        tmp_path / "kismet.db", ssid=SSID, bssid=ROGUE_BSSID, last_time=1700000000.0
    )
    with caplog.at_level(logging.INFO, logger="cyt_platform.rogue_ap_detector"):
        detector.scan_kismet_db(str(db), now=1700000060.0)
    assert SSID not in caplog.text
    assert "Learned AP" in caplog.text
    assert "ssid(len=" in caplog.text


# --- B3: BLE tracker source ------------------------------------------------------------


def test_ble_tracker_reason_and_detail_carry_no_raw_name():
    device = _ble_device()
    device_data = device["device_data"]
    score, reasons = tracker_score(device, device_data)
    # Detection semantics unchanged: the tracker pattern still fires and
    # still lands in the alert band.
    assert score >= 0.8
    joined = " | ".join(reasons)
    assert BLE_NAME not in joined
    assert "ssid(len=" in joined
    assert "name/manuf matches tracker pattern" in joined

    result = _ble_result(
        "AA:BB:CC:DD:EE:09", device_data, score, reasons, 1700000000.0
    )
    assert BLE_NAME not in json.dumps(result.detail)
    assert BLE_NAME not in json.dumps([line.detail for line in result.evidence])


# --- B3: end-to-end status.json + push body --------------------------------------------


def test_status_and_push_carry_no_plain_identifying_strings(tmp_path):
    status_path = tmp_path / "run" / "status.json"
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    config = {
        "status": {
            "file": str(status_path),
            "hold_seconds": 300,
            "stale_seconds": 150,
            "deaf_seconds": 180,
            "deaf_is_fail": True,
            "quiet_is_watch": False,
        },
        "push": {"enabled": True, "min_severity": "watch"},
    }
    try:
        store.begin_session()
        with store.transaction():
            store.write_heartbeat("analyzer", ok=True, cycle=1)
        now = time.time()

        # Real rogue alert (plain trusted SSID) through the real result
        # builder, fusion attach, and store — exactly the live emit path.
        alert = _rogue_detector()._check_against_trusted(
            SSID, ROGUE_BSSID, "WPA2", 6, now
        )
        result = _rogue_result(alert, now)
        rogue_fields = incident_fields(result, session_id="s")
        attach_fusion(rogue_fields, result)
        store.observe_incident(**rogue_fields)

        # Real BLE detection (plain bystander name) through the engine.
        engine = BLETrackerEngine(
            store, {"ble_tracker": {"enabled": True, "min_score": 0.5}}
        )
        with store.transaction():
            hits = engine.process_devices([_ble_device()], now=now)
        assert hits >= 1

        status = StatusEngine(store, config)
        # B2: detector rows no longer drive status severity — escalate the
        # phenomenon so the surfaces are hot. The push policy (v1) only
        # delivers on transition to alert, so the lifecycle row goes to
        # ALERT; the redaction contract under test is unchanged.
        with store.transaction():
            escalate_lifecycle(store, ROGUE_BSSID, now, "alert", subject_type="wifi_ap")
        snap = status.publish(
            cycle=1,
            db_label="x.kismet",
            freshness={
                "max_last_time": now,
                "recent_device_count": 5,
                "age_s": 5,
            },
            consecutive_fails=0,
        )
        assert snap["state"] == "alert"

        raw = status_path.read_text()
        assert SSID not in raw
        assert BLE_NAME not in raw

        queue = PushQueue(store, config)
        assert queue.enqueue_from_status(snap) == 1
        pending = store.list_push_pending(limit=10)
        assert pending, "push row must be queued for the alert"
        body = "\n".join(row["body"] for row in pending)
        assert SSID not in body
        assert BLE_NAME not in body
    finally:
        store.close()


# --- B3: replay report over a real corpus scenario -------------------------------------


def test_replay_report_of_corpus_scenario_carries_no_raw_ssid(tmp_path):
    scenarios_dir = Path(__file__).resolve().parent.parent / "scenarios" / "replay"
    scenario = load_scenario(str(scenarios_dir / "cafe-evil-twin.json"))
    report = ReplayEngine(scenario, store_path=tmp_path / "cyt.db").run()
    events_text = json.dumps(report["events"])
    incidents_text = json.dumps(report["incidents"])
    assert events_text, "the scenario must produce events"
    assert "CafeNet" not in events_text
    assert "CafeNet" not in incidents_text
    # The redacted token carries the explainability: length + stable hash.
    assert "ssid(len=" in events_text


# --- S8: debrief ------------------------------------------------------------------------


def test_debrief_carries_no_plain_name_and_masks_entity_keys(tmp_path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    config = {"paths": {"log_dir": str(tmp_path / "logs")}}
    try:
        store.begin_session()
        now = time.time()
        engine = BLETrackerEngine(
            store, {"ble_tracker": {"enabled": True, "min_score": 0.5}}
        )
        with store.transaction():
            assert engine.process_devices([_ble_device()], now=now) >= 1
        with store.transaction():
            for location_id in ("loc-a", "loc-b"):
                store.record_location_sighting(
                    "wifi_mac", "AA:BB:CC:DD:EE:FF", location_id, 47.6, -122.3, now
                )
        debrief = generate_debrief(store, config)
        markdown = debrief["markdown"]
        assert BLE_NAME not in markdown
        assert SSID not in markdown
        # Plaintext entity keys render as stable masked MACs.
        assert "AA:BB:CC:DD:EE:FF" not in markdown
        assert "AA:BB:xx:xx:xx:FF" in markdown
    finally:
        store.close()


# --- S7: the logging filter -------------------------------------------------------------


def _log_and_read(config: dict, message: str, tmp_path: Path) -> str:
    logger = setup_logging(config, level=logging.INFO)
    logger.warning(message)
    for handler in logging.getLogger().handlers:
        handler.flush()
    return (Path(config["paths"]["log_dir"]) / "analyzer.log").read_text()


def test_logging_filter_redacts_configured_ssid_and_blocks_forging(
    tmp_path, isolated_root_logging
):
    config = {
        "paths": {"log_dir": str(tmp_path / "logs")},
        "rogue_ap_detection": {"trusted_aps": [{"ssid": SSID, "bssid": TRUSTED_BSSID}]},
    }
    forged = (
        f"Probe detected from aa:bb:cc:dd:ee:ff: {SSID}\n"
        "2026-09-25 09:00:00,000 - CRITICAL - cyt_platform.service"
        " - analyzer stopped (forged)"
    )
    content = _log_and_read(config, forged, tmp_path)
    lines = content.splitlines()
    # One record = exactly one emitted line: no forged standalone line.
    assert len(lines) == 1
    assert not any(
        line.startswith("2026-09-25 09:00:00,000 - CRITICAL") for line in lines
    )
    # The configured SSID is replaced by its stable token.
    assert SSID not in content
    assert "ssid(len=" in content
    # Message content survives on the single line (redaction, not deletion).
    assert "analyzer stopped (forged)" in content
    # The MAC in the message is masked.
    assert "aa:bb:cc:" not in content
    assert "aa:bb:xx:xx:xx:ff" in content


def test_logging_filter_masks_macs_in_plain_records(tmp_path, isolated_root_logging):
    config = {"paths": {"log_dir": str(tmp_path / "logs")}}
    content = _log_and_read(
        config, "Device reappeared: AA:BB:CC:DD:EE:FF (15-20 min window)", tmp_path
    )
    assert "AA:BB:CC:DD:EE:FF" not in content
    assert "AA:BB:xx:xx:xx:FF" in content
    assert "Device reappeared" in content
