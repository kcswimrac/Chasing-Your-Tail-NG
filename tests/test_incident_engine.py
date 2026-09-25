"""D2 incident engine: restart continuity, decay, dispositions, reopen.

The engine consumes detector rows through the same emit path the detectors
use (incident_fields + fusion attach + observe_incident), so these tests
exercise the real contract boundary, not a mock.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cyt_platform.detectors import DetectionResult, EvidenceLine, incident_fields
from cyt_platform.fused_evidence import attach as attach_fusion
from cyt_platform.incidents import (
    INCIDENTS_V2_DEFAULTS,
    IncidentEngine,
    IncidentStatus,
)
from cyt_platform.store import CytStore

MAC = "AA:BB:CC:00:00:42"
T0 = 1700000000.0


@pytest.fixture
def store(tmp_path):
    """Same shape as the test_store.py fixture."""
    s = CytStore.open(
        {
            "path": str(tmp_path / "cyt.db"),
            "synchronous": "NORMAL",
            "retention_days": 14,
            "heartbeat_keep_days": 7,
            "entity_retention_days": 30,
            "mode": "durable",
        }
    )
    yield s
    s.close()

# Two evidence classes, equal weights: one row of each fuses to
# 1 - (0.5 * 0.5) = 0.75 (>= alert bar 0.60); one row alone is 0.50
# (>= watch bar 0.30, below alert bar).
FUSION_CFG = {
    "fusion": {"weights": {"window_match": 0.5, "cotravel_visit": 0.5}},
    "incidents_v2": {
        "enabled": True,
        "watch_confidence": 0.30,
        "alert_confidence": 0.60,
        "alert_min_detectors": 2,
        "close_after_s": 600.0,
        "decay_grace_s": 120.0,
    },
}


def _result(
    detector: str,
    kind_evidence: str,
    observed_at: float = T0,
    subject: str = MAC,
    window: str = "15-20",
) -> DetectionResult:
    return DetectionResult(
        detector=detector,
        kind=detector,
        subject=subject,
        subject_type="wifi_mac",
        window_label=window,
        severity="watch",
        observed_at=observed_at,
        summary=f"{detector} on {subject}",
        evidence=(EvidenceLine(kind_evidence, f"{kind_evidence} detail"),),
    )


def _emit(store: CytStore, result: DetectionResult, session: str = "sess-1") -> None:
    """The exact emit path every contract detector uses."""
    fields = incident_fields(result, session_id=session)
    attach_fusion(fields, result)
    store.observe_incident(**fields)


def _engine(store: CytStore, config: dict = FUSION_CFG) -> IncidentEngine:
    return IncidentEngine(store, config)


def _phenomenon(store: CytStore):
    rows = store.conn.execute(
        "SELECT * FROM incidents WHERE phenomenon_key IS NOT NULL"
    ).fetchall()
    assert len(rows) <= 1
    return rows[0] if rows else None


def _timeline_states(store: CytStore, incident_id: int) -> list:
    rows = store.list_incident_timeline(incident_id)
    return [r["to_state"] for r in rows]


# --- the merge + escalation core -------------------------------------------------


def test_window_and_cotravel_merge_into_one_incident(store: CytStore):
    """Same subject, two evidence classes -> ONE phenomenon incident."""
    _emit(store, _result("mac_reappear", "window_match"))
    _emit(store, _result("cotravel", "cotravel_visit"))
    plans = _engine(store).apply(now=T0)

    rows = store.conn.execute(
        "SELECT * FROM incidents WHERE phenomenon_key IS NOT NULL"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["lifecycle_state"] == IncidentStatus.ALERT.value
    # Escalation is stepwise through the machine: new -> observing -> watch -> alert.
    assert _timeline_states(store, rows[0]["id"]) == [
        "new",
        "observing",
        "watch",
        "alert",
    ]
    assert len(plans) == 3


def test_fused_confidence_and_transition_reasons_carry_evidence(store: CytStore):
    """Every transition records the confidence and the evidence summary."""
    _emit(store, _result("mac_reappear", "window_match"))
    _emit(store, _result("cotravel", "cotravel_visit"))
    _engine(store).apply(now=T0)
    row = _phenomenon(store)
    assert row["confidence"] == pytest.approx(0.75)
    events = store.conn.execute(
        "SELECT summary, detail_json FROM events WHERE event_type='incident_transition' ORDER BY ts, summary"
    ).fetchall()
    assert len(events) == 3
    detail = __import__("json").loads(events[-1]["detail_json"])
    assert detail["to"] == "alert"
    assert detail["confidence"] == pytest.approx(0.75)


def test_repetition_only_assessment_cannot_reach_alert(store: CytStore):
    """The D4 handoff: alert_gate demotes repetition-only assessments, so
    the phenomenon stops at WATCH even when repeated confidence clears the
    alert bar (locked decision 1 — repetition alone is never sufficient).
    Two rows, one evidence kind: noisy-OR reaches 0.75 >= 0.60 alert bar,
    but a single kind cannot justify alerting."""
    _emit(store, _result("mac_reappear", "window_match", window="15-20"))
    _emit(store, _result("mac_reappear", "window_match", window="20-25"))
    _engine(store).apply(now=T0 + 1)
    row = _phenomenon(store)
    assert row["confidence"] == pytest.approx(0.75)
    assert row["lifecycle_state"] == IncidentStatus.WATCH.value


def test_single_weak_observation_stays_new(store: CytStore):
    """Below the watch bar and uncorroborated: recorded, not escalated."""
    weak_cfg = {
        "fusion": {"weights": {"window_match": 0.2}},
        "incidents_v2": {"enabled": True},
    }
    _emit(store, _result("mac_reappear", "window_match"))
    _engine(store, weak_cfg).apply(now=T0)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.NEW.value


# --- restart continuity (acceptance 2) -------------------------------------------


def test_restart_mid_observation_continues_same_incident_key(tmp_path: Path):
    """A store close/reopen mid-phenomenon must continue the SAME incident:
    state and cursor live in the store, so rehydration composes with the
    window-rehydration semantics (no duplicate, no replayed transitions)."""
    path = tmp_path / "cyt.db"

    def open_store() -> CytStore:
        return CytStore.open(
            {"path": str(path), "mode": "durable", "synchronous": "NORMAL"}
        )

    store = open_store()
    _emit(store, _result("mac_reappear", "window_match"))
    _emit(store, _result("cotravel", "cotravel_visit"))
    _engine(store).apply(now=T0)
    before = _phenomenon(store)
    store.close()

    # "Restart": fresh engine on a fresh store object, same DB. Fresh
    # two-class evidence keeps the phenomenon at ALERT (one class alone
    # would rightly decay toward WATCH — see the gating tests).
    store2 = open_store()
    try:
        engine2 = _engine(store2)
        _emit(store2, _result("mac_reappear", "window_match", observed_at=T0 + 100))
        _emit(store2, _result("cotravel", "cotravel_visit", observed_at=T0 + 100))
        engine2.apply(now=T0 + 100)
        after = _phenomenon(store2)
        assert after["id"] == before["id"]
        assert after["incident_key"] == before["incident_key"]
        assert after["lifecycle_state"] == IncidentStatus.ALERT.value
        # Exactly one phenomenon row exists — the restart duplicated nothing.
        count = store2.conn.execute(
            "SELECT COUNT(*) AS c FROM incidents WHERE phenomenon_key IS NOT NULL"
        ).fetchone()["c"]
        assert count == 1
    finally:
        store2.close()


def test_restart_does_not_reconsume_pre_restart_rows(tmp_path: Path):
    """The persisted cursor makes consumption exactly-once across restarts."""
    path = str(tmp_path / "cyt.db")
    store = CytStore.open({"path": path, "mode": "durable"})
    _emit(store, _result("mac_reappear", "window_match"))
    _engine(store).apply(now=T0)
    store.close()

    store2 = CytStore.open({"path": path, "mode": "durable"})
    try:
        plans = _engine(store2).apply(now=T0 + 1)
        assert plans == []  # nothing new: the t=T0 row is behind the cursor
    finally:
        store2.close()


# --- decay / staleness (acceptance 4) ---------------------------------------------


def test_stale_evidence_decays_alert_stepwise(store: CytStore):
    """No fresh evidence: ALERT decays to WATCH, then stale-closes."""
    _emit(store, _result("mac_reappear", "window_match"))
    _emit(store, _result("cotravel", "cotravel_visit"))
    _engine(store).apply(now=T0)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.ALERT.value

    # 130s of silence (past decay_grace 120, below close_after 600): one step down.
    _engine(store).apply(now=T0 + 130)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.WATCH.value

    # Another 130s: WATCH decays to OBSERVING.
    _engine(store).apply(now=T0 + 260)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.OBSERVING.value

    # Past close_after (600s since last evidence at T0): stale-close.
    _engine(store).apply(now=T0 + 700)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.RESOLVED.value
    assert row["status"] == "closed"
    assert row["closed_at"] is not None


def test_legacy_stale_close_skips_engine_owned_rows(store: CytStore):
    """close_stale_incidents (legacy path) keeps legacy detector rows but
    must not fight the engine: the phenomenon row it would close (stale,
    status='open') is engine-owned and stays exactly as the engine set it."""
    _emit(store, _result("mac_reappear", "window_match"))
    _emit(store, _result("cotravel", "cotravel_visit"))
    _engine(store).apply(now=T0)
    closed = store.close_stale_incidents(now=T0 + 700, close_after_seconds=600.0)
    # The two legacy detector rows close (unchanged legacy behavior); the
    # engine-owned phenomenon row is excluded by the lifecycle column.
    assert closed == 2
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.ALERT.value
    assert row["status"] == "open"
    assert row["closed_at"] is None


# --- dispositions + reopening windows (acceptance 4) -------------------------------


def _drive_to_watch(store: CytStore) -> str:
    _emit(store, _result("mac_reappear", "window_match"))
    _engine(store).apply(now=T0)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.WATCH.value
    return str(row["incident_key"])


def test_operator_disposition_false_positive_sticks_within_window(store: CytStore):
    key = _drive_to_watch(store)
    engine = _engine(store)
    engine.dispose(key, IncidentStatus.FALSE_POSITIVE, ts=T0 + 10)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.FALSE_POSITIVE.value
    assert row["disposition"] == "false_positive"
    assert row["status"] == "closed"

    # Fresh evidence 1 hour later: inside the 7-day reopen window — noted,
    # not reopened (the operator's judgment holds).
    _emit(store, _result("mac_reappear", "window_match", observed_at=T0 + 3700))
    engine.apply(now=T0 + 3700)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.FALSE_POSITIVE.value
    timeline = store.list_incident_timeline(row["id"])
    assert any(r["reason"].startswith("note:") for r in timeline)


def test_disposition_reopens_after_window(store: CytStore):
    key = _drive_to_watch(store)
    engine = _engine(store)
    engine.dispose(key, IncidentStatus.FALSE_POSITIVE, ts=T0 + 10)

    # 8 days later the same subject shows up again: reopens as NEW, then
    # the same apply escalates it on fresh two-class evidence (one class
    # alone can only reach WATCH — the alert bar needs the merge).
    _emit(
        store,
        _result("mac_reappear", "window_match", observed_at=T0 + 8 * 86400),
    )
    _emit(
        store,
        _result("cotravel", "cotravel_visit", observed_at=T0 + 8 * 86400),
    )
    engine.apply(now=T0 + 8 * 86400)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.ALERT.value
    states = _timeline_states(store, row["id"])
    assert "false_positive" in states and "new" in states


def test_resolved_incident_reopens_immediately_by_default(store: CytStore):
    """RESOLVED is an automatic staleness close, not an operator judgment:
    fresh evidence reopens at once (configurable window for the spec's
    literal 24h episode separation)."""
    key = _drive_to_watch(store)
    engine = _engine(store)
    engine.dispose(key, IncidentStatus.RESOLVED, ts=T0 + 10)

    _emit(store, _result("mac_reappear", "window_match", observed_at=T0 + 60))
    _emit(store, _result("cotravel", "cotravel_visit", observed_at=T0 + 60))
    engine.apply(now=T0 + 60)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.ALERT.value


def test_dispose_rejects_legacy_rows_and_terminal_states(store: CytStore):
    """Dispositions only apply to engine-managed, active incidents."""
    engine = _engine(store)
    # Detector-owned row (no lifecycle): clear error, not a confusing crash.
    _emit(store, _result("mac_reappear", "window_match"))
    with pytest.raises(ValueError, match="detector-owned"):
        engine.dispose(
            "mac_reappear|AA:BB:CC:00:00:42|15-20|sess-1",
            IncidentStatus.FALSE_POSITIVE,
            ts=T0,
        )
    # Unknown key.
    with pytest.raises(ValueError, match="unknown incident"):
        engine.dispose("ph:nowhere", IncidentStatus.RESOLVED, ts=T0)
    # Terminal incident: the machine rejects the move.
    key = _drive_to_watch(store)
    engine.dispose(key, IncidentStatus.KNOWN_DEVICE, ts=T0 + 5)
    with pytest.raises(Exception):
        engine.dispose(key, IncidentStatus.RESOLVED, ts=T0 + 6)


# --- engine config ----------------------------------------------------------------


def test_engine_config_validation():
    store = None
    with pytest.raises(ValueError, match="alert_confidence"):
        IncidentEngine(
            store,
            {
                "incidents_v2": {
                    "watch_confidence": 0.6,
                    "alert_confidence": 0.3,
                }
            },
        )
    with pytest.raises(ValueError, match="within"):
        IncidentEngine(store, {"incidents_v2": {"watch_confidence": 1.5}})
    # Defaults stand in when no config section is given.
    engine = IncidentEngine(store, None)
    assert engine.cfg["watch_confidence"] == INCIDENTS_V2_DEFAULTS["watch_confidence"]


def test_unknown_event_types_never_merge(store: CytStore):
    """Conservative default: event types outside the class map each get
    their own phenomenon — no accidental cross-detector merging."""
    _emit(store, _result("mystery_detector", "mystery_kind"))
    _emit(store, _result("other_detector", "other_kind"))
    _engine(store).apply(now=T0)
    rows = store.conn.execute(
        "SELECT incident_key FROM incidents WHERE phenomenon_key IS NOT NULL ORDER BY incident_key"
    ).fetchall()
    assert len(rows) == 2
