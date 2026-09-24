"""P2 debrief/push/gps and P3 IE/BLE tests."""

from __future__ import annotations

import time
from pathlib import Path

from cyt_platform.ble_tracker import BLETrackerEngine, tracker_score
from cyt_platform.debrief import generate_debrief
from cyt_platform.gps_live import LiveGpsFusion, extract_gps_from_device_json
from cyt_platform.location import stable_cluster_id as cluster_id
from cyt_platform.ie_fingerprint import IEFingerprintEngine, extract_ie_fingerprint
from cyt_platform.push import PushQueue
from cyt_platform.store import CytStore


def test_debrief_writes_markdown(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    sid = store.begin_session()
    now = time.time()
    with store.transaction():
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:DD:EE:01",
            window_label="15-20",
            severity="alert",
            session_id=sid,
            observed_at=now,
            summary="test",
            evidence={"reasons": ["seen across 2 places"], "kind": "mac_reappear"},
        )
    result = generate_debrief(store, {"paths": {"log_dir": str(tmp_path)}}, day=None)
    assert "End-of-Day Debrief" in result["markdown"]
    assert Path(result["path"]).is_file()
    store.close()


def test_push_queue_log_backend(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    config = {
        "push": {
            "enabled": True,
            "backend": "log",
            "min_severity": "alert",
            "cooldown_seconds": 0,
        }
    }
    q = PushQueue(store, config)
    with store.transaction():
        pid = q.enqueue(severity="alert", title="t", body="b")
        assert pid is not None
        stats = q.flush()
    assert stats["sent"] == 1
    store.close()


def test_gps_extract_and_cotravel(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    store.begin_session()
    fusion = LiveGpsFusion(
        store,
        {
            "gps_fusion": {
                "enabled": True,
                "min_locations_for_cotravel": 2,
                "min_span_seconds": 1,
                "incident_score_threshold": 0.9,  # high so may not open incident
            }
        },
    )
    now = time.time()
    with store.transaction():
        store.record_location_sighting(
            "wifi_mac", "AA:00:00:00:00:01", cluster_id(33.4, -112.0), 33.4, -112.0, now - 2000
        )
        store.record_location_sighting(
            "wifi_mac", "AA:00:00:00:00:01", cluster_id(33.5, -112.1), 33.5, -112.1, now
        )
        results = fusion.score_cotravel(now)
    assert any(r["location_count"] >= 2 for r in results)
    store.close()


def test_extract_gps_from_device_json():
    dd = {
        "kismet.device.base.location": {
            "kismet.common.location.geopoint": [-112.07, 33.45],
            "kismet.common.location.time_sec": 1700000000,
        }
    }
    r = extract_gps_from_device_json(dd)
    assert r is not None
    lat, lon, ts = r
    assert abs(lat - 33.45) < 0.01
    assert abs(lon + 112.07) < 0.01


def test_ie_fingerprint_relink(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    store.begin_session()
    eng = IEFingerprintEngine(store, {"ie_fingerprint": {"enabled": True, "min_probe_ssids": 1}})

    def dev(mac, ssids):
        return {
            "mac": mac,
            "device_data": {
                "dot11.device": {
                    "dot11.device.probed_ssid_map": {
                        s: {"dot11.probedssid.ssid": s} for s in ssids
                    },
                    "dot11.device.last_probed_ssid_record": {
                        "dot11.probedssid.ssid": ssids[0]
                    },
                    "fake.ie.tag": 1,
                    "fake.ie.tag2": 5,
                    "fake.ie.tag3": 7,
                }
            },
        }

    with store.transaction():
        # same probe set → same fingerprint
        n1 = eng.process_devices([dev("AA:BB:CC:00:00:01", ["HomeNet", "CafeWiFi"])])
        n2 = eng.process_devices([dev("AA:BB:CC:00:00:02", ["HomeNet", "CafeWiFi"])])
    assert n1 >= 1 and n2 >= 1
    # second MAC should trigger ie_relink incident (2 entities on fp)
    n = store.conn.execute(
        "SELECT COUNT(*) AS c FROM incidents WHERE event_type='ie_relink'"
    ).fetchone()["c"]
    assert n >= 1
    store.close()


def test_ble_tracker_score():
    d = {"mac": "AA:BB:CC:DD:EE:FF", "type": "BTLE Device"}
    dd = {"kismet.device.base.type": "BTLE Device", "kismet.device.base.commonname": "AirTag"}
    score, reasons = tracker_score(d, dd)
    assert score >= 0.5
    assert any("tracker" in r.lower() or "airtag" in r.lower() or "BLE" in r for r in reasons)


def test_ble_engine_incident(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    store.begin_session()
    eng = BLETrackerEngine(store, {"ble_tracker": {"enabled": True, "min_score": 0.5}})
    devices = [
        {
            "mac": "11:22:33:44:55:66",
            "type": "BTLE Device",
            "device_data": {
                "kismet.device.base.type": "BTLE Device",
                "kismet.device.base.commonname": "Tile Tracker",
            },
        }
    ]
    with store.transaction():
        hits = eng.process_devices(devices)
    assert hits >= 1
    n = store.conn.execute(
        "SELECT COUNT(*) AS c FROM incidents WHERE event_type='ble_tracker'"
    ).fetchone()["c"]
    assert n >= 1
    store.close()


def test_ie_extract_minimal():
    fp = extract_ie_fingerprint(
        {
            "dot11.device": {
                "dot11.device.last_probed_ssid_record": {
                    "dot11.probedssid.ssid": "OnlyOne"
                }
            }
        }
    )
    # may be None if not enough tags — with only 1 ssid and no tags
    # engine requires ssids>=1 OR tags>=3; extract returns if ssids>=1 OR tags>=3 OR caps
    assert fp is not None  # 1 ssid is enough for extract_ie_fingerprint
