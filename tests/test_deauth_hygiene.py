"""Deauth event hygiene (B4) and clock-jump watermark trust (S10).

B4: deauth events were retained for the process lifetime, attacks were
rebuilt from that whole list, and the runner re-filed the rebuilt list
every cycle through ``attacks[-20:]``. Consequences proven in review probe
p5_*: close/reopen churn on quiet tails, lifetime-count escalation (a slow
drip ending at alert), restart divergence (a fresh process loses the
memory), and the most severe attack being the one dropped by the tail
slice. These tests pin the repaired behavior: windowed memory, filing
idempotence on the attack's last_seen, windowed-count classification, and
severity-sorted filing order.

S10: a watermark pushed ahead of the analyzer's clock by a transient clock
jump used to blind capture reads forever. The watermark is now untrusted
when far ahead (reads fall back to the bounded catch-up window) and the
anomaly surfaces as a ``clock`` component failure.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from cyt_platform import deauth_detector
from cyt_platform.health import clock_skew_reason
from cyt_platform.kismet_ro import scan_start_from_watermark
from cyt_platform.rf_plugins import DEAUTH_WATERMARK_KEY, RFPluginRunner
from cyt_platform.store import CytStore

ATTACKER = "AA:BB:CC:DD:EE:01"
VICTIM = "AA:BB:CC:DD:EE:02"


def make_kismet_db(tmp_path: Path, name: str = "capture.kismet") -> Path:
    """Minimal Kismet-shaped capture DB with an empty alerts table."""
    db = tmp_path / name
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE alerts (ts_sec INTEGER, header TEXT, json TEXT)")
    conn.execute(
        """CREATE TABLE devices
           (devmac TEXT, type TEXT, device TEXT, last_time INTEGER)"""
    )
    conn.commit()
    conn.close()
    return db


def add_deauth_alert(db: Path, alert_ts: float, dest: str = VICTIM) -> None:
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
                    "kismet.alert.source_mac": ATTACKER,
                    "kismet.alert.dest_mac": dest,
                    "kismet.alert.channel": 6,
                }
            ),
        ),
    )
    conn.commit()
    conn.close()


def detector_config(**overrides) -> dict:
    cfg = {
        "deauth_detection": {
            "min_events_for_attack": 2,
            "catchup_window_seconds": 1800,
            "attack_window_seconds": 1800,
            "protected_macs": [],
        }
    }
    cfg["deauth_detection"].update(overrides)
    return cfg


def incident_rows(store: CytStore) -> list:
    return store.conn.execute(
        """SELECT e.key, i.severity, i.status, i.observation_count
           FROM incidents i JOIN entities e ON i.entity_id = e.id
           ORDER BY e.key, i.id"""
    ).fetchall()


# --- B4: windowed memory ------------------------------------------------------


def test_events_pruned_to_attack_window(tmp_path):
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    add_deauth_alert(db, now - 1500)
    add_deauth_alert(db, now - 10)
    det = deauth_detector.DeauthDetector(detector_config(attack_window_seconds=600))
    det.scan_kismet_db(str(db), now=now)
    # The 1500 s old event is beyond the 600 s attack window: memory keeps
    # only recent frames, so classification can never see process lifetime.
    assert len(det.events) == 1


def test_slow_drip_never_escalates(tmp_path):
    # 11 frames 20 minutes apart toward a protected MAC: lifetime totals
    # crossed the escalation threshold (review probe p5_live_deauth_churn),
    # but the windowed count is 2 — below any attack threshold.
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    for k in range(11):
        add_deauth_alert(db, now - k * 1200)
    det = deauth_detector.DeauthDetector(
        detector_config(
            catchup_window_seconds=40000, protected_macs=[VICTIM]
        )
    )
    det.scan_kismet_db(str(db), now=now)
    attacks = det.analyze_attacks()
    # The attack still exists (2 frames in the window), but its severity is
    # classified from the windowed count — never from the 11-frame lifetime
    # total that crossed the escalation threshold on the old code.
    assert len(attacks) == 1
    assert attacks[0].total_frames == 2
    assert attacks[0].severity == "LOW"


def test_repeated_scan_does_not_duplicate_events(tmp_path):
    # A persisted watermark that trails the rows (e.g. clock drift backward)
    # can re-read the same alerts; remembered events must not duplicate.
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    add_deauth_alert(db, now - 5)
    add_deauth_alert(db, now - 2)
    det = deauth_detector.DeauthDetector(
        detector_config(), watermark_loader=lambda: now + 3600
    )
    det.scan_kismet_db(str(db), now=now)
    det.scan_kismet_db(str(db), now=now)
    assert len(det.events) == 2


def test_closed_incident_not_refiled_on_quiet_cycles(tmp_path):
    # Quiet cycles after a close must not churn the incident (review probe
    # p5_deauth_flap saw 54 close/reopen pairs).
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    add_deauth_alert(db, now - 5)
    add_deauth_alert(db, now - 2)
    store = CytStore.open({"path": str(tmp_path / "r.db")})
    store.begin_session()
    config = detector_config()
    config["rf"] = {"deauth_enabled": True, "rogue_enabled": False}
    runner = RFPluginRunner(store, config)

    runner.run_cycle(kdb=None, db_path=str(db), now=now)
    assert len(incident_rows(store)) == 1
    store.close_stale_incidents(now + 600, 600)
    assert incident_rows(store)[0][2] == "closed"

    for cycle in (1, 2, 3):
        runner.run_cycle(kdb=None, db_path=str(db), now=now + 660 + cycle)
    rows = incident_rows(store)
    assert len(rows) == 1
    assert rows[0][2] == "closed"
    assert rows[0][3] == 1  # no re-observations of the stale attack
    reopened = store.conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type = 'incident_reopened'"
    ).fetchone()[0]
    assert reopened == 0
    store.close()


def test_new_frame_on_existing_attack_refiles_once(tmp_path):
    # Filing is idempotent on the attack's last_seen: a cycle with no new
    # frames re-files nothing; one new frame advances exactly once.
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    add_deauth_alert(db, now - 5)
    add_deauth_alert(db, now - 2)
    store = CytStore.open({"path": str(tmp_path / "r.db")})
    store.begin_session()
    config = detector_config()
    config["rf"] = {"deauth_enabled": True, "rogue_enabled": False}
    runner = RFPluginRunner(store, config)

    runner.run_cycle(kdb=None, db_path=str(db), now=now)
    assert incident_rows(store)[0][3] == 1

    runner.run_cycle(kdb=None, db_path=str(db), now=now + 60)
    assert incident_rows(store)[0][3] == 1

    add_deauth_alert(db, now + 115)
    runner.run_cycle(kdb=None, db_path=str(db), now=now + 120)
    rows = incident_rows(store)
    assert len(rows) == 1
    assert rows[0][3] == 2
    store.close()


def test_most_severe_attack_survives_per_cycle_budget(tmp_path):
    # 21 single-frame attacks plus one protected 11-frame flood: the budget
    # of 20 must keep the severity-sorted head. The old tail slice dropped
    # exactly the worst attack (review probe p5_truncation).
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    for k in range(11):
        add_deauth_alert(db, now - 100 + k, dest="AA:BB:CC:00:00:01")
    for idx in range(21):
        add_deauth_alert(
            db, now - 10, dest=f"AA:BB:CC:0A:{idx // 256:02d}:{idx % 256:02d}"
        )
    store = CytStore.open({"path": str(tmp_path / "r.db")})
    store.begin_session()
    config = detector_config(
        min_events_for_attack=1, protected_macs=["AA:BB:CC:00:00:01"]
    )
    config["rf"] = {"deauth_enabled": True, "rogue_enabled": False}
    runner = RFPluginRunner(store, config)

    runner.run_cycle(kdb=None, db_path=str(db), now=now)

    rows = incident_rows(store)
    assert len(rows) == 20
    protected = [row for row in rows if row[0] == "AA:BB:CC:00:00:01"]
    assert protected, "the worst (protected-flood) attack was dropped"
    assert protected[0][1] == "alert"
    store.close()


# --- S10: untrusted ahead-watermarks ------------------------------------------


def test_scan_start_falls_back_when_watermark_far_ahead():
    now = 1700000000.0
    # Far ahead: untrusted, fall back to the bounded catch-up floor.
    assert scan_start_from_watermark(now + 3600, now, 1800) == now - 1800
    # Within the skew allowance: trusted.
    assert scan_start_from_watermark(now + 100, now, 1800) == now + 100
    # Fresh store (no persisted value): bounded look-back.
    assert scan_start_from_watermark(0.0, now, 1800) == now - 1800
    # A normal trailing watermark passes through untouched.
    assert scan_start_from_watermark(now - 60, now, 1800) == now - 60


def test_clock_jump_does_not_blind_detection(tmp_path):
    # Review probe p5_clock_jump: a watermark one year ahead permanently
    # hid real-time attacks. The untrusted watermark must fall back so the
    # attack is detected immediately after the clock is corrected.
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    add_deauth_alert(db, now - 5)
    add_deauth_alert(db, now - 2)
    det = deauth_detector.DeauthDetector(
        detector_config(), watermark_loader=lambda: now + 31536000
    )
    assert len(det.scan_kismet_db(str(db), now=now)) == 2
    attacks = det.analyze_attacks()
    assert len(attacks) == 1
    assert attacks[0].target_mac == VICTIM


def test_clock_failure_registered_then_cleared(tmp_path):
    # The ahead-watermark anomaly must be visible in the health registry
    # (review p5_clock_jump: no health signal fired) and must clear once
    # the watermark is back in range.
    now = 1700000000.0
    db = make_kismet_db(tmp_path)
    add_deauth_alert(db, now - 5)
    add_deauth_alert(db, now - 2)
    store = CytStore.open({"path": str(tmp_path / "r.db")})
    store.begin_session()
    store.set_runtime(DEAUTH_WATERMARK_KEY, str(now + 3600))
    config = detector_config()
    config["rf"] = {"deauth_enabled": True, "rogue_enabled": False}
    runner = RFPluginRunner(store, config)

    stats = runner.run_cycle(kdb=None, db_path=str(db), now=now)
    assert stats["detector_failures"].get("clock") == "clock_ahead"

    # The repaired watermark is now near the processed rows: the clock
    # component recovers on the next cycle.
    stats = runner.run_cycle(kdb=None, db_path=str(db), now=now + 10)
    assert "clock" not in stats["detector_failures"]
    store.close()


def test_clock_skew_reason_boundaries():
    now = 1700000000.0
    assert clock_skew_reason(watermark=now + 3600, newest_event_ts=None, now=now) == "clock_ahead"
    assert clock_skew_reason(watermark=now + 100, newest_event_ts=None, now=now) is None
    assert clock_skew_reason(watermark=None, newest_event_ts=now + 3600, now=now) == "clock_ahead"
    assert clock_skew_reason(watermark=None, newest_event_ts=None, now=now) is None
