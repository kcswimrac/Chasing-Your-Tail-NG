"""Baseline learning and suppression."""

from __future__ import annotations

import time
from pathlib import Path

from cyt_platform.baseline import BaselineEngine
from cyt_platform.incidents import IncidentDeduper
from cyt_platform.store import CytStore
from secure_main_logic import MatchEvent


def test_learn_and_suppress(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    config = {
        "baseline": {
            "enabled": True,
            "min_sightings": 3,
            "current_place": "home",
            "places": {"home": {"name": "Home"}},
        },
        "status": {
            "window_to_severity": {"5-10": "watch", "10-15": "watch", "15-20": "alert"}
        },
    }
    eng = BaselineEngine(store, config)
    sid = store.begin_session()
    deduper = IncidentDeduper(
        store,
        {},
        session_id=sid,
        baseline=eng,
        place_id="home",
    )
    mac = "AA:BB:CC:DD:EE:10"
    with store.transaction():
        for i in range(3):
            eng.record_sighting("home", "wifi_mac", mac, time.time())
    assert eng.is_baselined("home", "wifi_mac", mac)

    with store.transaction():
        deduper.handle_match(
            MatchEvent(
                kind="mac_reappear",
                subject=mac,
                window="15-20",
                observed_at=time.time(),
            )
        )
        results = deduper.flush()
    assert results[0].suppressed is True
    inputs = store.get_status_inputs(300)
    assert inputs.alert_open == 0
    assert inputs.suppressed_open >= 1
    store.close()


def test_mark_false(tmp_path: Path):
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    config = {
        "baseline": {
            "enabled": True,
            "min_sightings": 5,
            "places": {"work": {"name": "Work"}},
        }
    }
    eng = BaselineEngine(store, config)
    with store.transaction():
        eng.mark_manual("work", "wifi_mac", "11:22:33:44:55:66", source="mark_false")
    assert eng.is_baselined("work", "wifi_mac", "11:22:33:44:55:66")
    assert store.entity_is_ignored("wifi_mac", "11:22:33:44:55:66")
    store.close()
