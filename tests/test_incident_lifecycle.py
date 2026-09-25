"""D2 incident lifecycle: the full transition table, every state pair.

Acceptance criterion: transition-table unit tests over EVERY allowed and
disallowed state pair — disallowed pairs raise ``InvalidTransition`` (fail
loudly, never silently no-op). The table under test is the spec's
``ALLOWED`` map in ``cyt_platform.incidents``; the expected table is
re-stated here independently so a code-side drift is a test failure.
"""

from __future__ import annotations

import pytest

from cyt_platform.incidents import (
    ALLOWED,
    ACTIVE_STATES,
    TERMINAL_STATES,
    IncidentRef,
    IncidentStatus,
    InvalidTransition,
    transition,
)

TS = 1700000000.0

# The build spec's transition table, restated independently of the code.
EXPECTED_ALLOWED = {
    IncidentStatus.NEW: {"observing", "false_positive", "known_device"},
    IncidentStatus.OBSERVING: {
        "watch",
        "resolved",
        "false_positive",
        "known_device",
    },
    IncidentStatus.WATCH: {
        "alert",
        "observing",
        "resolved",
        "false_positive",
        "known_device",
    },
    IncidentStatus.ALERT: {
        "watch",
        "resolved",
        "false_positive",
        "known_device",
    },
    # Terminal states re-open only as NEW when fresh evidence arrives.
    IncidentStatus.RESOLVED: {"new"},
    IncidentStatus.FALSE_POSITIVE: {"new"},
    IncidentStatus.KNOWN_DEVICE: {"new"},
    IncidentStatus.ARCHIVED: set(),
}


def _ref(state: IncidentStatus) -> IncidentRef:
    return IncidentRef(
        incident_id=1,
        incident_key="ph:tracking:wifi_mac:AA:BB:CC:DD:EE:01",
        lifecycle_state=state,
        confidence=0.5,
        last_seen=TS,
    )


def test_transition_table_covers_every_state_pair():
    """Every (from, to) ordered pair is either allowed or raises — and the
    allowed set matches the spec exactly."""
    checked = 0
    for from_state in IncidentStatus:
        expected = EXPECTED_ALLOWED[from_state]
        for to_state in IncidentStatus:
            ref = _ref(from_state)
            if to_state.value in expected:
                plan = transition(ref, to_state, "spec trigger", TS, 0.5)
                assert plan.from_state is from_state
                assert plan.to_state is to_state
                assert plan.incident_id == 1
                assert plan.reason == "spec trigger"
            else:
                with pytest.raises(InvalidTransition):
                    transition(ref, to_state, "spec trigger", TS, 0.5)
            checked += 1
    assert checked == 64  # 8 states x 8 targets, nothing skipped


def test_code_table_matches_spec_table():
    """The code's ALLOWED map and the spec table restated above agree."""
    for from_state in IncidentStatus:
        code_targets = {s.value for s in ALLOWED[from_state]}
        assert code_targets == EXPECTED_ALLOWED[from_state], from_state


def test_invalid_transition_carries_details():
    """InvalidTransition names the incident and both states (loud, greppable)."""
    with pytest.raises(InvalidTransition) as exc:
        transition(_ref(IncidentStatus.NEW), IncidentStatus.ALERT, "jump", TS)
    assert "new -> alert" in str(exc.value)
    assert exc.value.from_state is IncidentStatus.NEW
    assert exc.value.to_state is IncidentStatus.ALERT


def test_archived_is_fully_terminal():
    """ARCHIVED has no outgoing moves at all."""
    assert ALLOWED[IncidentStatus.ARCHIVED] == frozenset()
    for to_state in IncidentStatus:
        with pytest.raises(InvalidTransition):
            transition(_ref(IncidentStatus.ARCHIVED), to_state, "any", TS)


def test_active_and_terminal_partition_all_states():
    """Every state is exactly one of active or terminal."""
    assert ACTIVE_STATES | TERMINAL_STATES == set(IncidentStatus)
    assert not ACTIVE_STATES & TERMINAL_STATES


def test_empty_reason_is_rejected():
    """A transition without a reason is a silent-drift risk — rejected."""
    ref = _ref(IncidentStatus.WATCH)
    with pytest.raises(ValueError, match="reason"):
        transition(ref, IncidentStatus.ALERT, "   ", TS)


def test_transition_accepts_string_state_values():
    """IncidentStatus(str, Enum) accepts raw string values from store rows."""
    plan = transition(_ref(IncidentStatus.WATCH), "alert", "threshold", TS)
    assert plan.to_state is IncidentStatus.ALERT


def test_transition_is_pure_no_store_required():
    """The state machine never touches SQLite: same inputs, same plan."""
    a = transition(_ref(IncidentStatus.NEW), IncidentStatus.OBSERVING, "r", TS, 0.4)
    b = transition(_ref(IncidentStatus.NEW), IncidentStatus.OBSERVING, "r", TS, 0.4)
    assert a == b
