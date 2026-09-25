"""Shared test helpers.

The lifecycle engine is the only writer of watch/alert rows (locked
decision 1 / B2), so tests that need hot status derive rows through the
same validated transition ladder the engine walks — never by writing
severity columns directly.

S19: the real result builders (rf_plugins._deauth_result / _rogue_result,
gps_live._cotravel_result, ble_tracker._ble_result) and the window
matcher's MatchEvent path are the only evidence sources production ever
sees. Tests that exercise fusion or lifecycle outcomes must derive their
rows from those builders under config.DEFAULTS — synthetic weight tables
and invented kinds (window_match / cotravel_visit) hid S1 and S2 from CI.
"""

from __future__ import annotations

from types import SimpleNamespace

from cyt_platform.config import DEFAULTS
from cyt_platform.detectors import DetectionResult, incident_fields
from cyt_platform.fused_evidence import attach
from cyt_platform.incidents import (
    IncidentDeduper,
    IncidentStatus,
    TransitionPlan,
    phenomenon_key_for,
)
from cyt_platform.secure_main_logic import MatchEvent
from cyt_platform.store import CytStore

_LADDER = ("observing", "watch", "alert")

# Deterministic fixtures shared by the real-kind test suites.
T0 = 1700000000.0
TARGET_MAC = "AA:BB:CC:00:00:42"
ATTACKER_MAC = "AA:BB:CC:00:00:FE"
ROGUE_BSSID = "AA:BB:CC:00:00:BD"


def expected_confidence(support_kinds, contra_kinds=()) -> float:
    """Fused confidence derived FROM config.DEFAULTS (the table-driven
    expectation): noisy-OR over the support lines' table weights, then the
    contra discount — exactly what confidence.fuse computes. Kinds outside
    the table take the config default_weight (the window-match repetition
    kinds are deliberately unweighted). Deriving the expectation from the
    table keeps the tests honest when weights are recalibrated and
    documents each case as (kinds → confidence)."""
    fusion = DEFAULTS["fusion"]
    weights = fusion["weights"]
    survival = 1.0
    for kind in support_kinds:
        survival *= 1.0 - weights.get(kind, fusion["default_weight"])
    contra_survival = 1.0
    for kind in contra_kinds:
        contra_survival *= 1.0 - weights.get(kind, fusion["default_weight"])
    confidence = (1.0 - survival) * contra_survival
    ceiling = DEFAULTS["fusion"]["max_confidence"]
    return round(max(0.0, min(confidence, ceiling)), 6)


def emit_result(
    store: CytStore,
    result: DetectionResult,
    session_id: str = "sess-1",
) -> None:
    """File one contract result through the exact production emit path:
    incident_fields -> fusion attach -> observe_incident."""
    fields = incident_fields(result, session_id=session_id)
    attach(fields, result)
    store.observe_incident(**fields)


def emit_window_match(
    store: CytStore,
    subject: str = TARGET_MAC,
    window: str = "5-10",
    kind: str = "mac_reappear",
    observed_at: float = T0,
    session_id: str = "sess-1",
) -> int:
    """File one window-match repetition row through the real deduper path
    (secure_main_logic.MatchEvent -> IncidentDeduper.handle_match -> flush),
    the way service.py wires the window matcher. Returns rows flushed."""
    deduper = IncidentDeduper(store, DEFAULTS["incidents"], session_id)
    deduper.handle_match(
        MatchEvent(
            kind=kind,
            subject=subject,
            window=window,
            observed_at=observed_at,
        )
    )
    return len(deduper.flush())


# --- real result builders (the four production emitters) ----------------------


def deauth_attack(
    *,
    target: str = TARGET_MAC,
    severity: str = "MEDIUM",
    last_seen: float = T0,
    now: float = T0,
    attacker: str = ATTACKER_MAC,
    frames: int = 6,
    attack_type: str = "deauth",
):
    """A Kismet deauth alert row through the real _deauth_result builder."""
    from cyt_platform.rf_plugins import _deauth_result

    attack = SimpleNamespace(
        target_mac=target,
        attacker_mac=attacker,
        attack_type=attack_type,
        total_frames=frames,
        severity=severity,
        last_seen=last_seen,
    )
    return _deauth_result(attack, now)


def rogue_alert(
    *,
    bssid: str = ROGUE_BSSID,
    reasons: tuple = ("Evil twin suspected", "Beacon mismatch"),
    severity: str = "HIGH",
    now: float = T0,
):
    """A Kismet rogue/evil-twin alert row through _rogue_result."""
    from cyt_platform.rf_plugins import _rogue_result

    alert = SimpleNamespace(
        rogue_bssid=bssid,
        ssid="X" * 8,
        reasons=list(reasons),
        severity=severity,
        timestamp=now,
    )
    return _rogue_result(alert, now)


def ble_tracker_hit(
    *,
    mac: str = TARGET_MAC,
    score: float = 0.8,
    name: str = "Tile",
    now: float = T0,
):
    """One BLE advertisement through the real _ble_result builder."""
    from cyt_platform.ble_tracker import _ble_result

    device_data = {"kismet.device.base.commonname": name}
    reasons = ["BLE/BTLE PHY", f"name/manuf matches tracker pattern ({name})"]
    return _ble_result(mac, device_data, score, reasons, now)


def cotravel_sighting(
    *,
    key: str = TARGET_MAC,
    locs: int = 5,
    score: float = 0.9,
    visit_densities: tuple = (0,),
    now: float = T0,
):
    """One high-confidence co-travel result through _cotravel_result.

    ``visit_densities`` gives each matched operator visit its ambient
    bystander count (0 = empty room) so density contra lines can be
    exercised per visit.
    """
    from cyt_platform.gps_live import _cotravel_result

    visits = [
        {
            "enter_ts": now + 600 * position,
            "exit_ts": now + 900 * position,
            "lat": 33.4 + position / 1000,
            "lon": -112.0 + position / 1000,
            "cluster_id": f"cluster-{position}",
            "density": density,
        }
        for position, density in enumerate(visit_densities, start=1)
    ]
    detail = {
        "locations": locs,
        "span_hours": 2.5,
        "sees": 12,
        "operator_visits": visits,
    }
    return _cotravel_result(key, locs, score, detail, now)


def escalate_lifecycle(
    store: CytStore,
    subject: str,
    ts: float,
    to_state: str,
    *,
    session_id: str = "test",
    subject_type: str = "wifi_mac",
    confidence: float = 0.9,
) -> int:
    """Deterministically walk a phenomenon NEW -> ``to_state``.

    Walks NEW -> OBSERVING -> WATCH -> ALERT through ``apply_transition``,
    the production transition writer, so the row's timeline and events
    match what the engine produces. Returns the incident id.
    """
    key = phenomenon_key_for(subject_type, subject)
    incident_id, _ = store.ensure_phenomenon_incident(
        incident_key=key,
        entity_type=subject_type,
        subject=subject,
        ts=ts,
        session_id=session_id,
    )
    current = IncidentStatus.NEW
    for nxt in _LADDER[: _LADDER.index(to_state) + 1]:
        store.apply_transition(
            TransitionPlan(
                incident_id=incident_id,
                incident_key=key,
                from_state=current,
                to_state=IncidentStatus(nxt),
                reason="test escalation",
                ts=ts,
                confidence=confidence,
            )
        )
        current = IncidentStatus(nxt)
    return incident_id
