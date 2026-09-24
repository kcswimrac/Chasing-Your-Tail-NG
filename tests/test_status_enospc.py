"""D8 fault injection: status publish parks on write failure; service continues.

Simulated ENOSPC (OSError with errno.ENOSPC) on the status-file write must:
  - not raise out of publish()/publish_fail() (the cycle handler survives),
  - park the publish so later cycles skip the failing write,
  - be recoverable only by a successful disk write,
  - recover to the last ATTEMPTED state — never a fabricated "clear".
"""

from __future__ import annotations

import errno
import json
import time
from pathlib import Path

import pytest

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
        }
    }
    engine = StatusEngine(store, config)
    yield store, engine, status_path
    store.close()


def enospc(*_args, **_kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def publish_kwargs() -> dict:
    return dict(
        cycle=1,
        db_label="x.kismet",
        freshness={"max_last_time": time.time(), "recent_device_count": 5, "age_s": 5},
        consecutive_fails=0,
    )


def test_publish_parks_on_enospc(env, monkeypatch):
    store, engine, status_path = env
    store.begin_session()
    with store.transaction():
        store.write_heartbeat("analyzer", ok=True, cycle=1)
    monkeypatch.setattr(engine, "_write_atomic", enospc)

    snap = engine.publish(**publish_kwargs())  # must not raise

    assert snap["parked"] is True
    assert snap["park_reason"].startswith("status_write_failed")
    assert snap["state"] == "clear"  # computed state is untouched
    assert engine.parked_publish() is True
    assert not status_path.exists()  # nothing was written


def test_publish_fail_parks_on_enospc(env, monkeypatch):
    store, engine, _ = env
    monkeypatch.setattr(engine, "_write_atomic", enospc)
    snap = engine.publish_fail(
        reason="analyzer_error", consecutive_fails=2, cycle=1
    )
    assert snap["state"] == "fail"
    assert snap["parked"] is True
    assert engine.parked_publish() is True


def test_parked_publish_does_not_raise_when_already_parked(env, monkeypatch):
    store, engine, _ = env
    monkeypatch.setattr(engine, "_write_atomic", enospc)
    engine.publish(**publish_kwargs())
    snap = engine.publish(**publish_kwargs())  # second attempt: still quiet
    assert snap["parked"] is True


def test_recovery_unparks_and_rewrites_last_true_state(env, monkeypatch):
    store, engine, status_path = env
    monkeypatch.setattr(engine, "_write_atomic", enospc)
    engine.publish_fail(reason="analyzer_error", consecutive_fails=1, cycle=1)

    real_write = StatusEngine._write_atomic.__get__(engine)
    monkeypatch.setattr(engine, "_write_atomic", real_write)

    assert engine.recover_publish() is True
    assert engine.parked_publish() is False
    recovered = json.loads(status_path.read_text())
    # Recovery re-writes the last attempted snapshot (true state "fail"),
    # never a fabricated "clear" that would silence a safety device.
    assert recovered["state"] == "fail"
    assert recovered["parked"] is False


def test_recovery_while_disk_still_full_stays_parked(env, monkeypatch):
    store, engine, _ = env
    monkeypatch.setattr(engine, "_write_atomic", enospc)
    engine.publish(**publish_kwargs())
    assert engine.recover_publish() is False
    assert engine.parked_publish() is True


def test_next_successful_publish_unparks(env, monkeypatch):
    store, engine, status_path = env
    monkeypatch.setattr(engine, "_write_atomic", enospc)
    engine.publish(**publish_kwargs())
    real_write = StatusEngine._write_atomic.__get__(engine)
    monkeypatch.setattr(engine, "_write_atomic", real_write)

    snap = engine.publish(**publish_kwargs())
    assert "parked" not in snap
    assert engine.parked_publish() is False
    assert json.loads(status_path.read_text())["state"] == "clear"


def test_service_failure_handler_survives_disk_full(env, monkeypatch):
    """The service loop shape: a cycle error triggers store + status writes
    inside the except handler. With the disk full, none of them may raise —
    the handler must return and the loop continues."""
    store, engine, _ = env
    monkeypatch.setattr(engine, "_write_atomic", enospc)

    def failing_cycle():
        raise RuntimeError("kismet_db_validation_failed")

    try:
        failing_cycle()
    except Exception:
        try:
            # Mirrors the guarded failure path in service.py.
            engine.publish_fail(
                reason="analyzer_error", consecutive_fails=1, cycle=1
            )
        except Exception as pe:  # pragma: no cover - would kill the service
            pytest.fail(f"status publish escaped the cycle handler: {pe}")
    assert engine.parked_publish() is True