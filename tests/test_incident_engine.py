"""D2 incident engine: restart continuity, decay, dispositions, reopen.

S19: driven by the REAL result builders (rf_plugins._deauth_result /
_rogue_result, gps_live._cotravel_result, ble_tracker._ble_result) and the
window matcher's MatchEvent path, all under config.DEFAULTS. The
pre-S19 version of this file used a synthetic two-kind weight table
(window_match / cotravel_visit at 0.5) that no detector emits — exactly
the drift that hid S1 and S2 from CI. It is not kept.

Fusion expectations are derived from the config table itself
(conftest.expected_confidence), so every case documents
kinds → confidence → lifecycle state.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    T0,
    TARGET_MAC,
    ble_tracker_hit,
    cotravel_sighting,
    deauth_attack,
    emit_result,
    emit_window_match,
    expected_confidence,
    rogue_alert,
)
from cyt_platform.config import DEFAULTS
from cyt_platform.detectors import DetectionResult, EvidenceLine
from cyt_platform.incidents import (
    INCIDENTS_V2_DEFAULTS,
    IncidentEngine,
    IncidentStatus,
)
from cyt_platform.store import CytStore

MAC = TARGET_MAC


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


def _engine(store: CytStore) -> IncidentEngine:
    """The engine under the shipped defaults — no synthetic overrides."""
    return IncidentEngine(store, dict(DEFAULTS))


def _phenomenon(store: CytStore):
    rows = store.conn.execute(
        "SELECT * FROM incidents WHERE phenomenon_key IS NOT NULL"
    ).fetchall()
    assert len(rows) <= 1
    return rows[0] if rows else None


def _timeline_states(store: CytStore, incident_id: int) -> list:
    rows = store.list_incident_timeline(incident_id)
    return [r["to_state"] for r in rows]


# --- the S19 table: real builder output -> lifecycle outcome ---------------------

_BUILDERS = {
    "deauth": deauth_attack,
    "rogue": rogue_alert,
    "ble": ble_tracker_hit,
    "cotravel": cotravel_sighting,
}

# S1: one Kismet deauth alert row is ONE observation. Its facets
# (attack_signature, source_severity) are self-ref kinds: they contribute
# weight but never independent kinds, so a single row can never alert by
# itself. The window matcher's mac_reappear rows are repetition — they
# cannot act as the second detector either.
REAL_LIFECYCLE_TABLE = [
    pytest.param(
        [("deauth", {})],
        IncidentStatus.WATCH,
        ("deauth_pattern", "attack_signature", "source_severity"),
        (),
        id="single-medium-deauth-holds-at-watch",
    ),
    pytest.param(
        [("deauth", {"severity": "HIGH"})],
        IncidentStatus.WATCH,
        ("deauth_pattern", "attack_signature", "source_severity"),
        (),
        id="alert-severity-deauth-holds-at-watch",
    ),
    pytest.param(
        [("deauth", {"severity": "HIGH"}), ("window", {"window": "5-10"})],
        IncidentStatus.WATCH,
        ("deauth_pattern", "attack_signature", "source_severity", "mac_reappear"),
        (),
        id="deauth-plus-window-repetition-holds-at-watch",
    ),
    pytest.param(
        [("window", {"window": "5-10"})],
        IncidentStatus.NEW,
        ("mac_reappear",),
        (),
        id="single-window-repetition-stays-new",
    ),
    pytest.param(
        [
            ("window", {"window": "5-10"}),
            ("window", {"window": "10-15"}),
            ("window", {"window": "15-20"}),
        ],
        IncidentStatus.OBSERVING,
        ("mac_reappear", "mac_reappear", "mac_reappear"),
        (),
        id="repetition-across-all-windows-never-alerts",
    ),
    pytest.param(
        [("rogue", {"reasons": ("Evil twin suspected",)})],
        IncidentStatus.NEW,
        ("rogue_reason",),
        (),
        id="single-rogue-reason-stays-new",
    ),
    pytest.param(
        [("rogue", {})],
        IncidentStatus.WATCH,
        ("rogue_reason", "rogue_reason"),
        (),
        id="single-rogue-alert-two-reasons-holds-at-watch",
    ),
    pytest.param(
        [("ble", {})],
        IncidentStatus.WATCH,
        ("ble_signal", "ble_signal", "score"),
        (),
        id="single-ble-tracker-sighting-holds-at-watch",
    ),
    pytest.param(
        [("cotravel", {})],
        IncidentStatus.WATCH,
        ("copresence", "travel_span", "score"),
        (),
        id="single-cotravel-open-room-holds-at-watch",
    ),
    pytest.param(
        [("cotravel", {"visit_densities": (0, 3, 2)})],
        IncidentStatus.WATCH,
        ("copresence", "travel_span", "score"),
        ("density", "density"),
        id="cotravel-crowded-visits-discount-confidence",
    ),
    pytest.param(
        [("cotravel", {}), ("deauth", {})],
        IncidentStatus.ALERT,
        (
            "copresence",
            "travel_span",
            "score",
            "deauth_pattern",
            "attack_signature",
            "source_severity",
        ),
        (),
        id="cotravel-plus-deauth-corroborates-to-alert",
    ),
    pytest.param(
        [("cotravel", {"visit_densities": (3,)}), ("deauth", {})],
        IncidentStatus.ALERT,
        (
            "copresence",
            "travel_span",
            "score",
            "deauth_pattern",
            "attack_signature",
            "source_severity",
        ),
        ("density",),
        id="cotravel-plus-deauth-with-density-still-alerts",
    ),
]


def _file(store: CytStore, at: float, session: str, emissions) -> None:
    """File a table case's rows through the real emit paths at time ``at``."""
    for emitter, kwargs in emissions:
        if emitter == "window":
            emit_window_match(
                store,
                window=kwargs.get("window", "5-10"),
                kind=kwargs.get("kind", "mac_reappear"),
                observed_at=at,
                session_id=session,
            )
            continue
        emit_result(
            store, _BUILDERS[emitter](**kwargs, now=at), session_id=session
        )


@pytest.mark.parametrize(
    "emissions,expected_state,support,contra", REAL_LIFECYCLE_TABLE
)
def test_real_builder_lifecycle_outcomes(
    store: CytStore, emissions, expected_state, support, contra
):
    """S19: the lifecycle outcome of every real detector emission pattern,
    under the shipped DEFAULTS. Expectations are derived from the fusion
    weight table, so weight recalibration updates these numbers
    automatically while taxonomy drift fails loudly."""
    _file(store, T0, "sess-1", emissions)
    _engine(store).apply(now=T0)

    row = _phenomenon(store)
    assert row is not None, "case produced no phenomenon incident"
    assert row["lifecycle_state"] == expected_state.value
    assert row["confidence"] == pytest.approx(expected_confidence(support, contra))


def test_deauth_plus_repetition_stops_short_of_alert_in_timeline(store: CytStore):
    """The S1 probe, end to end: one alert-severity deauth plus the target
    MAC seen again used to walk new→observing→watch→alert. With the facets
    in self_ref_kinds and repetition excluded from alert_min_detectors the
    same emissions stop at WATCH."""
    _file(
        store,
        T0,
        "sess-1",
        [("deauth", {"severity": "HIGH"}), ("window", {"window": "5-10"})],
    )
    plans = _engine(store).apply(now=T0)

    row = _phenomenon(store)
    assert _timeline_states(store, row["id"]) == ["new", "observing", "watch"]
    assert len(plans) == 2
    # The confidence still clears the alert bar — the independent-kind gate
    # (not the number) is what holds the phenomenon at WATCH.
    assert row["confidence"] == pytest.approx(0.6022)


def test_window_repetition_row_cannot_count_as_second_detector(store: CytStore):
    """S1: co-travel plus two repetition rows clears the confidence bar
    (0.617275 >= 0.60) and has 2 independent kinds, but only ONE real
    detector contributes — the repetition rows must not satisfy
    alert_min_detectors. Before the fix this walked to ALERT."""
    emit_result(
        store, cotravel_sighting(score=0.9, locs=5), session_id="sess-1"
    )
    emit_window_match(store, window="5-10", observed_at=T0, session_id="sess-1")
    emit_window_match(store, window="10-15", observed_at=T0, session_id="sess-1")
    _engine(store).apply(now=T0)

    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.WATCH.value
    assert row["confidence"] == pytest.approx(
        expected_confidence(
            ("copresence", "travel_span", "score", "mac_reappear", "mac_reappear")
        )
    )


def test_cotravel_density_contra_populates_against_block(store: CytStore):
    """S2/D4: crowded operator visits emit density contra lines, so the
    against block is non-empty live and the confidence discount is visible
    in the stored fusion evidence."""
    emit_result(
        store,
        cotravel_sighting(score=0.9, locs=5, visit_densities=(0, 3, 2)),
        session_id="sess-1",
    )
    _engine(store).apply(now=T0)

    # The fusion block (why/against) lives on the detector-owned row the
    # engine consumed — the same place the live explain surface reads it.
    det = store.conn.execute(
        "SELECT evidence_json FROM incidents WHERE lifecycle_state IS NULL"
    ).fetchone()
    block = json.loads(det["evidence_json"])["fusion"]
    contra = block["against"]
    assert [c["kind"] for c in contra] == ["density", "density"]
    assert all(w < 0 for w in (c["weight"] for c in contra))
    # Crowded visits (2 and 3) carry count-bearing, non-identifying details.
    details = [c["detail"] for c in contra]
    assert any("Ambient density 3 other device" in d for d in details)
    assert any("Ambient density 2 other device" in d for d in details)
    assert all("near operator visit #" in d for d in details)


# --- the merge + escalation core -------------------------------------------------


def test_deauth_and_cotravel_merge_into_one_incident(store: CytStore):
    """Same subject, two real detector classes in one cycle -> ONE
    phenomenon incident escalated stepwise to ALERT."""
    emit_result(store, deauth_attack(), session_id="sess-1")
    emit_result(store, cotravel_sighting(), session_id="sess-1")
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
    emit_result(store, deauth_attack(), session_id="sess-1")
    emit_result(store, cotravel_sighting(), session_id="sess-1")
    _engine(store).apply(now=T0)
    row = _phenomenon(store)
    assert row["confidence"] == pytest.approx(
        expected_confidence(
            (
                "deauth_pattern",
                "attack_signature",
                "source_severity",
                "copresence",
                "travel_span",
                "score",
            )
        )
    )
    events = store.conn.execute(
        "SELECT summary, detail_json FROM events WHERE event_type='incident_transition' ORDER BY ts, summary"
    ).fetchall()
    assert len(events) == 3
    detail = json.loads(events[-1]["detail_json"])
    assert detail["to"] == "alert"
    assert detail["confidence"] == row["confidence"]


def test_repetition_only_assessment_cannot_reach_alert(store: CytStore):
    """Locked decision 1: deauth repetition raises fused confidence past
    the alert bar (0.804636 >= 0.60), but every line is the same
    detector's own classification — independent_kinds stays
    ('deauth_pattern',) and the phenomenon holds at WATCH."""
    emit_result(store, deauth_attack(), session_id="sess-1")
    emit_result(
        store,
        deauth_attack(severity="HIGH", attacker="AA:BB:CC:00:00:F1"),
        session_id="sess-2",  # post-restart session: a second detector row
    )
    _engine(store).apply(now=T0 + 1)
    row = _phenomenon(store)
    assert row["confidence"] == pytest.approx(
        expected_confidence(
            (
                "deauth_pattern",
                "attack_signature",
                "source_severity",
                "deauth_pattern",
                "attack_signature",
                "source_severity",
            )
        )
    )
    assert row["lifecycle_state"] == IncidentStatus.WATCH.value


def test_deauth_repetition_across_restarts_stays_watch(store: CytStore):
    """The live churn shape: the same deauth re-filed in later cycles (new
    session per restart) re-corroborates but never escalates past WATCH on
    repetition alone."""
    engine = _engine(store)
    emit_result(store, deauth_attack(), session_id="sess-1")
    engine.apply(now=T0)
    assert _phenomenon(store)["lifecycle_state"] == IncidentStatus.WATCH.value

    emit_result(
        store, deauth_attack(severity="HIGH"), session_id="sess-2"
    )
    engine.apply(now=T0 + 60)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.WATCH.value
    contribs = store.list_incident_contributions(row["id"])
    assert len(contribs) == 1 and contribs[0]["hits"] == 2


def test_single_weak_observation_stays_new(store: CytStore):
    """Below the watch bar and uncorroborated: recorded, not escalated.
    Under DEFAULTS a single rogue reason fuses to 0.25 (< 0.30 watch bar)
    with one detector row — no synthetic weak config needed."""
    emit_result(store, rogue_alert(reasons=("Evil twin suspected",)), session_id="sess-1")
    _engine(store).apply(now=T0)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.NEW.value


# --- restart continuity (acceptance 2) -------------------------------------------


def test_restart_mid_observation_continues_same_incident_key(tmp_path):
    """A store close/reopen mid-phenomenon must continue the SAME incident:
    state and cursor live in the store, so rehydration composes with the
    window-rehydration semantics (no duplicate, no replayed transitions)."""
    path = tmp_path / "cyt.db"

    def open_store() -> CytStore:
        return CytStore.open(
            {"path": str(path), "mode": "durable", "synchronous": "NORMAL"}
        )

    store = open_store()
    emit_result(store, deauth_attack(), session_id="sess-1")
    emit_result(store, cotravel_sighting(), session_id="sess-1")
    _engine(store).apply(now=T0)
    before = _phenomenon(store)
    store.close()

    # "Restart": fresh engine on a fresh store object, same DB. Fresh
    # two-detector evidence keeps the phenomenon at ALERT (one detector
    # alone would rightly decay toward WATCH — see the gating tests).
    store2 = open_store()
    try:
        engine2 = _engine(store2)
        emit_result(
            store2, deauth_attack(now=T0 + 100), session_id="sess-2"
        )
        emit_result(
            store2, cotravel_sighting(now=T0 + 100), session_id="sess-2"
        )
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


def test_restart_does_not_reconsume_pre_restart_rows(tmp_path):
    """The persisted cursor makes consumption exactly-once across restarts."""
    path = str(tmp_path / "cyt.db")
    store = CytStore.open({"path": path, "mode": "durable"})
    emit_result(store, deauth_attack(), session_id="sess-1")
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
    emit_result(store, deauth_attack(), session_id="sess-1")
    emit_result(store, cotravel_sighting(), session_id="sess-1")
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
    emit_result(store, deauth_attack(), session_id="sess-1")
    emit_result(store, cotravel_sighting(), session_id="sess-1")
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
    """One real MEDIUM deauth row: confidence 0.558 crosses the watch bar
    with a real attack-pattern kind behind it."""
    emit_result(store, deauth_attack(), session_id="sess-1")
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
    emit_result(
        store, deauth_attack(now=T0 + 3700, last_seen=T0 + 3700), session_id="sess-1"
    )
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
    # the same apply escalates it on fresh two-detector evidence (one
    # detector alone can only reach WATCH — the alert band needs the
    # corroboration).
    late = T0 + 8 * 86400
    emit_result(store, deauth_attack(now=late, last_seen=late), session_id="sess-1")
    emit_result(store, cotravel_sighting(now=late), session_id="sess-1")
    engine.apply(now=late)
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

    emit_result(
        store, deauth_attack(now=T0 + 60, last_seen=T0 + 60), session_id="sess-1"
    )
    engine.apply(now=T0 + 60)
    row = _phenomenon(store)
    assert row["lifecycle_state"] == IncidentStatus.WATCH.value


def test_dispose_rejects_legacy_rows_and_terminal_states(store: CytStore):
    """Dispositions only apply to engine-managed, active incidents."""
    engine = _engine(store)
    # Detector-owned row (no lifecycle): clear error, not a confusing crash.
    emit_result(store, deauth_attack(), session_id="sess-1")
    legacy_key = f"deauth_attack|{MAC}|deauth|sess-1"
    with pytest.raises(ValueError, match="detector-owned"):
        engine.dispose(legacy_key, IncidentStatus.FALSE_POSITIVE, ts=T0)
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


def test_unknown_event_types_merge_by_subject(store: CytStore):
    """Subject-keyed merging is universal: even event types outside the
    known set merge on the same subject (one explained case), while
    different subjects never share a phenomenon — no accidental
    cross-subject merging either way. Built directly as contract results
    (an unknown DETECTOR, not an invented weight table): unknown kinds get
    the conservative default weight and never count as independent."""
    mystery = DetectionResult(
        detector="mystery_detector",
        kind="mystery_detector",
        subject=MAC,
        subject_type="wifi_mac",
        window_label="15-20",
        severity="watch",
        observed_at=T0,
        summary=f"mystery_detector on {MAC}",
        evidence=(EvidenceLine("mystery_kind", "mystery_kind detail"),),
    )
    other = DetectionResult(
        detector="other_detector",
        kind="other_detector",
        subject=MAC,
        subject_type="wifi_mac",
        window_label="15-20",
        severity="watch",
        observed_at=T0,
        summary=f"other_detector on {MAC}",
        evidence=(EvidenceLine("other_kind", "other_kind detail"),),
    )
    third = DetectionResult(
        detector="third_detector",
        kind="third_detector",
        subject="AA:BB:CC:00:00:43",
        subject_type="wifi_mac",
        window_label="15-20",
        severity="watch",
        observed_at=T0,
        summary="third_detector on AA:BB:CC:00:00:43",
        evidence=(EvidenceLine("third_kind", "third_kind detail"),),
    )
    emit_result(store, mystery, session_id="sess-1")
    emit_result(store, other, session_id="sess-1")
    emit_result(store, third, session_id="sess-1")
    _engine(store).apply(now=T0)
    rows = store.conn.execute(
        """SELECT i.incident_key, e.key AS entity_key
           FROM incidents i JOIN entities e ON e.id = i.entity_id
           WHERE i.phenomenon_key IS NOT NULL ORDER BY i.incident_key"""
    ).fetchall()
    assert len(rows) == 2  # one per SUBJECT, not per event type
    merged = store.list_incident_contributions(
        store.conn.execute(
            """SELECT i.id FROM incidents i JOIN entities e ON e.id = i.entity_id
               WHERE i.phenomenon_key IS NOT NULL AND e.key='AA:BB:CC:00:00:42'"""
        ).fetchone()["id"]
    )
    assert {(c["detector"], c["evidence_class"]) for c in merged} == {
        ("mystery_detector", "mystery_detector"),
        ("other_detector", "other_detector"),
    }


def test_contributions_are_cumulative_not_per_cycle(store: CytStore):
    """The same detector recurring across cycles extends its contribution
    (hits + window), it does not duplicate rows."""
    for at in (T0, T0 + 10, T0 + 20):
        emit_result(
            store, deauth_attack(now=at, last_seen=at), session_id="sess-1"
        )
        _engine(store).apply(now=at)
    row = _phenomenon(store)
    contributions = store.list_incident_contributions(row["id"])
    assert len(contributions) == 1
    assert contributions[0]["hits"] == 3
    assert contributions[0]["first_ts"] == pytest.approx(T0)
    assert contributions[0]["last_ts"] == pytest.approx(T0 + 20)


# --- S12: the cursor runs on filing sequence, never on evidence time --------


def test_late_stamped_evidence_is_consumed_not_skipped(store: CytStore):
    """A HIGH row filed at T+60 carrying last_seen=T-10 must be consumed.

    A deauth result is stamped with the attack's last-frame time, so
    late-filed evidence legitimately trails the cycle clock. The old
    cursor (max(now, newest_last_seen)) jumped past it on the quiet T0
    pass and the row was skipped forever.
    """
    engine = _engine(store)
    # Quiet pass at T0: under the old scheme this advanced the cursor to
    # T0 — exactly the state that hid late-stamped rows.
    assert engine.apply(now=T0) == []

    emit_result(
        store,
        deauth_attack(
            severity="HIGH", last_seen=T0 - 10, now=T0 + 60
        ),
        session_id="sess-late",
    )
    engine.apply(now=T0 + 60)

    ph = _phenomenon(store)
    assert ph is not None, "late-stamped detector row was skipped by the cursor"
    assert ph["lifecycle_state"] is not None
    contrib = store.conn.execute(
        "SELECT hits FROM incident_contributions "
        "WHERE incident_id=? AND detector='deauth_attack'",
        (ph["id"],),
    ).fetchone()
    assert contrib is not None and int(contrib["hits"]) == 1

    # Cursor monotonicity: a further quiet pass re-consumes nothing — no
    # duplicate contribution hits. (The lifecycle state itself may decay
    # on stale evidence; that is the staleness pass, not consumption.)
    engine.apply(now=T0 + 120)
    hits = store.conn.execute(
        "SELECT hits FROM incident_contributions "
        "WHERE incident_id=? AND detector='deauth_attack'",
        (ph["id"],),
    ).fetchone()
    assert int(hits["hits"]) == 1


def test_refiled_row_is_reconsumed_on_newer_evidence(store: CytStore):
    """Re-filing the same incident key with newer evidence re-consumes it.

    The old timestamp cursor re-selected updated rows because last_seen
    moved past it; the sequence cursor must do the same — every file and
    re-file assigns a fresh sequence.
    """
    emit_result(
        store, cotravel_sighting(now=T0), session_id="sess-refile"
    )
    engine = _engine(store)
    engine.apply(now=T0)
    ph = _phenomenon(store)
    assert ph is not None

    emit_result(
        store,
        cotravel_sighting(now=T0 + 30),
        session_id="sess-refile",
    )
    engine.apply(now=T0 + 60)

    hits = store.conn.execute(
        "SELECT hits FROM incident_contributions "
        "WHERE incident_id=? AND detector='cotravel'",
        (ph["id"],),
    ).fetchone()
    assert int(hits["hits"]) == 2
