"""CytStore WAL + incident dedup tests."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from cyt_platform.store import CytStore


@pytest.fixture
def store(tmp_path: Path):
    cfg = {
        "path": str(tmp_path / "cyt.db"),
        "synchronous": "NORMAL",
        "retention_days": 14,
        "heartbeat_keep_days": 7,
        "entity_retention_days": 30,
        "mode": "durable",
    }
    s = CytStore.open(cfg)
    yield s
    s.close()


def test_migrate_version(store: CytStore):
    row = store.conn.execute(
        "SELECT value FROM schema_meta WHERE key='version'"
    ).fetchone()
    assert row["value"] == "4"  # schema v4: canonical observation store


def test_dedup_ten_observes_one_incident(store: CytStore):
    session = store.begin_session()
    t0 = time.time()
    results = []
    with store.transaction():
        for i in range(10):
            r = store.observe_incident(
                event_type="mac_reappear",
                subject="AA:BB:CC:DD:EE:FF",
                window_label="15-20",
                severity="alert",
                session_id=session,
                observed_at=t0 + i,
                summary="mac_reappear window=15-20",
                kismet_db="test.kismet",
            )
            results.append(r)
    assert results[0].is_new is True
    assert results[-1].observation_count == 10
    assert all(r.id == results[0].id for r in results)
    n_open = store.conn.execute(
        "SELECT COUNT(*) AS c FROM incidents WHERE status='open'"
    ).fetchone()["c"]
    assert n_open == 1
    n_events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE event_type='incident_opened'"
    ).fetchone()["c"]
    assert n_events == 1


def test_close_stale_incidents(store: CytStore):
    session = store.begin_session()
    old = time.time() - 1000
    with store.transaction():
        store.observe_incident(
            event_type="mac_reappear",
            subject="11:22:33:44:55:66",
            window_label="5-10",
            severity="watch",
            session_id=session,
            observed_at=old,
            summary="old",
        )
        closed = store.close_stale_incidents(time.time(), close_after_seconds=600)
    assert closed == 1
    status = store.conn.execute(
        "SELECT status FROM incidents WHERE summary='old'"
    ).fetchone()["status"]
    assert status == "closed"


def test_get_status_inputs_hold_filter(store: CytStore):
    session = store.begin_session()
    now = time.time()
    with store.transaction():
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:00:00:00:00:01",
            window_label="5-10",
            severity="watch",
            session_id=session,
            observed_at=now - 10,
            summary="recent watch",
        )
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:00:00:00:00:02",
            window_label="15-20",
            severity="alert",
            session_id=session,
            observed_at=now - 400,  # outside 300s hold
            summary="stale alert",
        )
        store.write_heartbeat("analyzer", ok=True, cycle=1, detail="ok")
    inputs = store.get_status_inputs(hold_seconds=300)
    assert inputs.watch_open == 1
    assert inputs.alert_open == 0
    assert inputs.alert_open_total == 1
    assert inputs.watch_open_total == 1


def test_store_file_permissions(store: CytStore):
    mode = os.stat(store.path).st_mode & 0o777
    # umask may vary in CI; require no world read
    assert mode & 0o004 == 0
