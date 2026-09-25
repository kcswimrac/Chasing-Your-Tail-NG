"""D8 window rehydration: slot state survives restart, aged, never resurrected."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyt_platform.crypto import generate_key_file
from cyt_platform.store import CytStore
from cyt_platform.windows import (
    MAX_AGE_S,
    WINDOW_RUNTIME_KEY,
    collect_window_sets,
    load_window_sets,
    merge_into_monitor,
    save_window_sets,
)
from cyt_platform.secure_main_logic import SecureCYTMonitor

T0 = 1_700_000_000.0
FOLLOWER = "AA:BB:CC:DD:EE:01"
FOLLOWER_SSID = "coffeeshop-follower"


@pytest.fixture
def store(tmp_path: Path):
    s = CytStore.open({"path": str(tmp_path / "win.db")})
    yield s
    s.close()


def make_monitor() -> SecureCYTMonitor:
    return SecureCYTMonitor({}, [], [], None)


def test_collect_reads_monitor_slots():
    m = make_monitor()
    m.past_five_mins_macs = {FOLLOWER}
    m.five_ten_min_ago_ssids = {FOLLOWER_SSID}
    sets = collect_window_sets(m)
    assert sets["mac"]["past5"] == [FOLLOWER]
    assert sets["ssid"]["5-10"] == [FOLLOWER_SSID]
    assert sets["mac"]["15-20"] == []


def test_roundtrip_same_time(store: CytStore):
    m = make_monitor()
    m.past_five_mins_macs = {FOLLOWER}
    save_window_sets(store, collect_window_sets(m), saved_ts=T0)
    loaded = load_window_sets(store, now=T0)
    assert loaded is not None
    assert loaded["mac"]["past5"] == [FOLLOWER]


def test_aging_shifts_slots_forward(store: CytStore):
    m = make_monitor()
    m.past_five_mins_macs = {FOLLOWER}  # age 0-5 min at save time
    m.five_ten_min_ago_macs = {"AA:BB:CC:DD:EE:02"}  # age 5-10 min
    save_window_sets(store, collect_window_sets(m), saved_ts=T0)

    # One slot elapsed: everything gets one slot older.
    loaded = load_window_sets(store, now=T0 + 310)
    assert loaded is not None
    assert loaded["mac"]["5-10"] == [FOLLOWER]
    assert loaded["mac"]["10-15"] == ["AA:BB:CC:DD:EE:02"]
    assert loaded["mac"]["past5"] == []


def test_aging_drops_expired_subjects(store: CytStore):
    """Nothing rehydrates past its natural 20-minute expiry."""
    m = make_monitor()
    m.fifteen_twenty_min_ago_macs = {FOLLOWER}  # oldest slot at save time
    save_window_sets(store, collect_window_sets(m), saved_ts=T0)

    loaded = load_window_sets(store, now=T0 + 700)  # >2 slots elapsed
    assert loaded is not None
    assert all(FOLLOWER not in v for v in loaded["mac"].values())


def test_state_older_than_window_span_is_discarded(store: CytStore):
    m = make_monitor()
    m.past_five_mins_macs = {FOLLOWER}
    save_window_sets(store, collect_window_sets(m), saved_ts=T0)
    assert load_window_sets(store, now=T0 + MAX_AGE_S + 1) is None


def test_corrupt_snapshot_returns_none(store: CytStore):
    store.set_runtime("window_sets", "{not json")
    assert load_window_sets(store, now=T0) is None


def test_missing_snapshot_returns_none(store: CytStore):
    assert load_window_sets(store, now=T0) is None


def test_merge_into_monitor_unions_without_replacement():
    m = make_monitor()
    m.five_ten_min_ago_macs = {"AA:BB:CC:DD:EE:02"}  # capture-db ground truth
    added = merge_into_monitor(
        m,
        {
            "mac": {"5-10": [FOLLOWER, "AA:BB:CC:DD:EE:02"], "past5": []},
            "ssid": {},
        },
    )
    assert added == 1  # only the genuinely missing subject
    assert m.five_ten_min_ago_macs == {FOLLOWER, "AA:BB:CC:DD:EE:02"}


def test_restart_restores_follower_graceless(tmp_path: Path, store: CytStore):
    """Full boot path: pre-restart save, post-restart merge keeps the tail."""

    def boot() -> SecureCYTMonitor:
        m = SecureCYTMonitor({}, [], [], None)
        # capture-db init found nothing (rolled log) — slots start empty
        return m

    live = boot()
    live.past_five_mins_macs = {FOLLOWER}
    live.past_five_mins_ssids = {FOLLOWER_SSID}
    save_window_sets(store, collect_window_sets(live), saved_ts=T0)
    # ... service crash; nothing written between ...

    fresh = boot()  # new process, empty slots
    rehydrated = load_window_sets(store, now=T0 + 120)  # <1 slot elapsed
    assert rehydrated is not None
    assert merge_into_monitor(fresh, rehydrated) == 2
    # The follower is still in the past-5 slot: no fresh 20-min grace period.
    assert fresh.past_five_mins_macs == {FOLLOWER}
    assert fresh.past_five_mins_ssids == {FOLLOWER_SSID}


def test_window_blob_is_encrypted_at_rest(tmp_path: Path):
    """S13: field_encrypt must cover the persisted window sets.

    The blob holds raw MACs and probe SSIDs; writing it as plaintext into
    runtime_state would quietly undo field encryption for the most
    identifying data the service holds.
    """
    key_path = tmp_path / "store.key"
    generate_key_file(key_path)
    store = CytStore.open(
        {
            "path": str(tmp_path / "win.db"),
            "mode": "durable",
            "encryption": {
                "enabled": True,
                "sealed": False,  # keep the open file inspectable
                "field_encrypt": True,
                "key_file": str(key_path),
            },
        }
    )
    try:
        m = make_monitor()
        m.past_five_mins_macs = {FOLLOWER}
        m.five_ten_min_ago_ssids = {FOLLOWER_SSID}
        save_window_sets(store, collect_window_sets(m), saved_ts=T0)

        row = store.conn.execute(
            "SELECT value FROM runtime_state WHERE key = ?", (WINDOW_RUNTIME_KEY,)
        ).fetchone()
        assert row["value"].startswith("enc:v1:")
        assert FOLLOWER not in row["value"]
        assert FOLLOWER_SSID not in row["value"]

        # and the API still round-trips through transparent decryption
        loaded = load_window_sets(store, now=T0)
        assert loaded is not None
        assert loaded["mac"]["past5"] == [FOLLOWER]
        assert loaded["ssid"]["5-10"] == [FOLLOWER_SSID]
    finally:
        store.close()
