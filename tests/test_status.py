"""Status engine hold / fail priority / invariants."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from conftest import escalate_lifecycle
from cyt_platform.status import StatusEngine
from cyt_platform.store import CytStore


@pytest.fixture
def env(tmp_path: Path):
    store_path = tmp_path / "cyt.db"
    status_path = tmp_path / "run" / "status.json"
    store = CytStore.open({"path": str(store_path), "mode": "durable"})
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
    engine = StatusEngine(store, config)
    yield store, engine, status_path
    store.close()


def test_clear_when_no_incidents(env):
    store, engine, status_path = env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    snap = engine.publish(
        cycle=1,
        db_label="x.kismet",
        freshness={"max_last_time": time.time(), "recent_device_count": 5, "age_s": 5},
        consecutive_fails=0,
    )
    assert snap["state"] == "clear"
    assert snap["counts"]["watch_open"] == 0
    assert snap["counts"]["alert_open"] == 0
    assert status_path.is_file()
    data = json.loads(status_path.read_text())
    assert data["state"] == "clear"


def test_alert_priority_and_invariant(env):
    store, engine, status_path = env
    sid = store.begin_session()
    now = time.time()
    with store.transaction():
        # B2: detector rows are contributions, never severity owners — a
        # watch and an alert detector row must not drive threat alone.
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:DD:EE:01",
            window_label="5-10",
            severity="watch",
            session_id=sid,
            observed_at=now,
            summary="w",
        )
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:DD:EE:02",
            window_label="15-20",
            severity="alert",
            session_id=sid,
            observed_at=now,
            summary="a",
        )
        store.write_heartbeat("analyzer", ok=True, cycle=2)
    snap = engine.publish(
        cycle=2,
        db_label="x.kismet",
        freshness={"max_last_time": now, "recent_device_count": 2, "age_s": 1},
        consecutive_fails=0,
    )
    assert snap["state"] == "clear"

    # The lifecycle row is the severity owner: an ALERT phenomenon drives
    # the threat state up the same ladder as before.
    with store.transaction():
        escalate_lifecycle(store, "AA:BB:CC:DD:EE:02", now, "alert", session_id=sid)
    snap = engine.publish(
        cycle=3,
        db_label="x.kismet",
        freshness={"max_last_time": now, "recent_device_count": 2, "age_s": 1},
        consecutive_fails=0,
    )
    assert snap["state"] == "alert"
    assert snap["counts"]["alert_open"] >= 1
    # invariant
    assert not (snap["state"] == "clear" and snap["counts"]["watch_open"] + snap["counts"]["alert_open"] > 0)


def test_deaf_is_fail(env):
    store, engine, _ = env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    snap = engine.publish(
        cycle=1,
        db_label="x.kismet",
        freshness={
            "max_last_time": time.time() - 500,
            "recent_device_count": 0,
            "age_s": 500,
        },
        consecutive_fails=0,
    )
    assert snap["state"] == "fail"
    assert snap["components"]["capture"]["reason"] == "deaf"


def test_prior_session_open_affects_threat(env):
    store, engine, _ = env
    old_session = "deadbeef" * 4
    now = time.time()
    # An open ALERT phenomenon from a prior session (session-independent
    # phenomenon key) still holds the threat state after a restart.
    with store.transaction():
        escalate_lifecycle(
            store,
            "AA:BB:CC:DD:EE:99",
            now - 30,
            "alert",
            session_id=old_session,
        )
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    # new session for runtime
    store.begin_session()
    snap = engine.publish(
        cycle=1,
        db_label="x.kismet",
        freshness={"max_last_time": now, "recent_device_count": 1, "age_s": 2},
        consecutive_fails=0,
    )
    assert snap["state"] == "alert"
    assert snap["counts"]["alert_open"] == 1
