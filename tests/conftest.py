"""Shared test helpers.

The lifecycle engine is the only writer of watch/alert rows (locked
decision 1 / B2), so tests that need hot status derive rows through the
same validated transition ladder the engine walks — never by writing
severity columns directly.
"""

from __future__ import annotations

from cyt_platform.incidents import (
    IncidentStatus,
    TransitionPlan,
    phenomenon_key_for,
)
from cyt_platform.store import CytStore

_LADDER = ("observing", "watch", "alert")


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
