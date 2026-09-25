"""Incident dedup: MatchEvent → CytStore.observe_incident (+ baseline + evidence)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from cyt_platform.baseline import BaselineEngine
from cyt_platform.explain import build_evidence
from cyt_platform.store import CytStore, IncidentResult

logger = logging.getLogger(__name__)


class IncidentDeduper:
    """
    Buffers match events in-cycle and flushes inside a store transaction.
    One open incident per (event_type, subject, window, session_id).
    """

    def __init__(
        self,
        store: CytStore,
        incidents_cfg: dict,
        session_id: str,
        window_to_severity: Optional[Dict[str, str]] = None,
        baseline: Optional[BaselineEngine] = None,
        place_id: Optional[str] = None,
    ):
        self.store = store
        self.cfg = incidents_cfg or {}
        self.session_id = session_id
        self.window_to_severity = window_to_severity or {
            "5-10": "watch",
            "10-15": "watch",
            "15-20": "alert",
        }
        self.baseline = baseline
        self.place_id = place_id
        self._buffer: List[Any] = []

    def set_place(self, place_id: Optional[str]) -> None:
        self.place_id = place_id

    def handle_match(self, event: Any) -> None:
        """Called from SecureCYTMonitor.on_match; buffers for cycle flush."""
        self._buffer.append(event)

    def flush(self) -> List[IncidentResult]:
        results: List[IncidentResult] = []
        for ev in self._buffer:
            results.append(self._apply(ev))
        self._buffer.clear()
        return results

    def _apply(self, ev: Any) -> IncidentResult:
        kind = getattr(ev, "kind", "mac_reappear")
        subject = getattr(ev, "subject", "")
        window = getattr(ev, "window", "5-10")
        observed_at = float(getattr(ev, "observed_at", 0) or 0)
        source_mac = getattr(ev, "source_mac", None)
        kismet_db = getattr(ev, "kismet_db", "") or ""

        severity = self.window_to_severity.get(window, "watch")
        if kind == "ssid_probe_repeat":
            entity_type = "wifi_ssid"
            summary = f"ssid_probe_repeat window={window}"
        else:
            entity_type = "wifi_mac"
            summary = f"mac_reappear window={window}"

        # Learning + suppression
        suppressed = False
        baselined = False
        if self.baseline and self.baseline.enabled:
            self.baseline.record_sighting(
                self.place_id, entity_type, subject, observed_at
            )
            if self.baseline.should_suppress_threat(
                entity_type, subject, self.place_id
            ):
                suppressed = True
                baselined = True

        evidence = build_evidence(
            kind=kind,
            subject=subject,
            window=window,
            severity=severity,
            place_id=self.place_id,
            baselined=baselined,
            suppressed=suppressed,
        )

        detail = {
            "window": window,
            "kind": kind,
            "suppressed": suppressed,
        }
        if source_mac:
            detail["source_mac_present"] = True
        if self.place_id:
            detail["place_id"] = self.place_id

        return self.store.observe_incident(
            event_type=kind,
            subject=subject,
            window_label=window,
            severity=severity,
            session_id=self.session_id,
            observed_at=observed_at,
            summary=summary,
            detail=detail,
            kismet_db=kismet_db,
            entity_type=entity_type,
            suppressed=suppressed,
            evidence=evidence,
        )


def make_on_match(deduper: IncidentDeduper) -> Callable[[Any], None]:
    return deduper.handle_match


# ---------------------------------------------------------------------------
# D2: incident lifecycle v2 — deterministic 8-state machine.
#
# One phenomenon = one incident. The engine (below) merges same-subject
# detections into phenomenon incidents and drives them through this state
# machine; detectors never write lifecycle state. Every transition is
# validated against ``ALLOWED`` — an illegal move raises
# ``InvalidTransition`` (fail loudly, never silently no-op) — and every
# applied transition appends a timeline row plus an audit event.
# ---------------------------------------------------------------------------


class IncidentStatus(str, Enum):
    """The lifecycle states of a phenomenon incident (build spec D2)."""

    NEW = "new"
    OBSERVING = "observing"
    WATCH = "watch"
    ALERT = "alert"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    KNOWN_DEVICE = "known_device"
    ARCHIVED = "archived"


# The transition table, exactly as drafted in build spec D2. Active states
# escalate/de-escalate one step at a time and may take an operator
# disposition; terminal states re-open only as NEW when fresh evidence
# arrives after their reopening window; ARCHIVED is terminal (nothing
# transitions to it in this build — it exists for operator archiving later).
ALLOWED: Dict[IncidentStatus, frozenset] = {
    IncidentStatus.NEW: frozenset(
        {
            IncidentStatus.OBSERVING,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.KNOWN_DEVICE,
        }
    ),
    IncidentStatus.OBSERVING: frozenset(
        {
            IncidentStatus.WATCH,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.KNOWN_DEVICE,
        }
    ),
    IncidentStatus.WATCH: frozenset(
        {
            IncidentStatus.ALERT,
            IncidentStatus.OBSERVING,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.KNOWN_DEVICE,
        }
    ),
    IncidentStatus.ALERT: frozenset(
        {
            IncidentStatus.WATCH,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.KNOWN_DEVICE,
        }
    ),
    # Terminal states re-open only as NEW when fresh evidence arrives.
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.NEW}),
    IncidentStatus.FALSE_POSITIVE: frozenset({IncidentStatus.NEW}),
    IncidentStatus.KNOWN_DEVICE: frozenset({IncidentStatus.NEW}),
    IncidentStatus.ARCHIVED: frozenset(),
}

# States that keep status='open' in the legacy incidents column (status.json
# composition and stale-close read that column); terminal states map to
# 'closed'. Lifecycle state is the authority; this is the compatibility map.
ACTIVE_STATES: frozenset = frozenset(
    {
        IncidentStatus.NEW,
        IncidentStatus.OBSERVING,
        IncidentStatus.WATCH,
        IncidentStatus.ALERT,
    }
)
TERMINAL_STATES: frozenset = frozenset(set(IncidentStatus) - set(ACTIVE_STATES))

# Store-level severity proxy per lifecycle state (the incidents.severity
# column feeds legacy status composition; WATCH/ALERT map onto themselves,
# pre-watch states are informational, terminal states keep their last
# severity so closing a case does not erase what it was).
SEVERITY_FOR_STATE: Dict[IncidentStatus, Optional[str]] = {
    IncidentStatus.NEW: "info",
    IncidentStatus.OBSERVING: "info",
    IncidentStatus.WATCH: "watch",
    IncidentStatus.ALERT: "alert",
    IncidentStatus.RESOLVED: None,  # keep current severity
    IncidentStatus.FALSE_POSITIVE: None,
    IncidentStatus.KNOWN_DEVICE: None,
    IncidentStatus.ARCHIVED: None,
}


class InvalidTransition(ValueError):
    """An illegal lifecycle move was attempted — always loud, never silent."""

    def __init__(self, incident_key: str, from_state: IncidentStatus, to: IncidentStatus):
        self.incident_key = incident_key
        self.from_state = from_state
        self.to_state = to
        super().__init__(
            f"invalid incident transition {incident_key}: "
            f"{from_state.value} -> {to.value}"
        )


@dataclass(frozen=True)
class IncidentRef:
    """The lifecycle-relevant view of an incident row (pure, store-free).

    ``transition`` consumes this — the state machine never touches SQLite
    directly, so the full transition table is testable without a store.
    """

    incident_id: int
    incident_key: str
    lifecycle_state: IncidentStatus
    confidence: float = 0.0
    last_seen: float = 0.0
    disposition: Optional[str] = None


@dataclass(frozen=True)
class TransitionPlan:
    """One validated lifecycle move, ready for ``CytStore.apply_transition``.

    Carries everything persistence needs: the row to update, the states, the
    reason, the confidence at the moment of the move, and the scenario/ingest
    clock time (never a wall clock inside detection — locked decision 4).
    """

    incident_id: int
    incident_key: str
    from_state: IncidentStatus
    to_state: IncidentStatus
    reason: str
    ts: float
    confidence: Optional[float] = None


def transition(
    ref: IncidentRef,
    to: IncidentStatus,
    reason: str,
    ts: float,
    confidence: Optional[float] = None,
) -> TransitionPlan:
    """Validate one lifecycle move and return its persistence plan.

    This function and ``ALLOWED`` are the ONLY authority on incident state:
    the engine applies plans through ``CytStore.apply_transition``, which
    appends the timeline row and the audit event. Invalid moves raise
    ``InvalidTransition`` — no silent state drift.
    """
    target = IncidentStatus(to)
    if not str(reason).strip():
        raise ValueError("transition reason must be a non-empty string")
    if to not in ALLOWED[ref.lifecycle_state]:
        raise InvalidTransition(ref.incident_key, ref.lifecycle_state, target)
    return TransitionPlan(
        incident_id=ref.incident_id,
        incident_key=ref.incident_key,
        from_state=ref.lifecycle_state,
        to_state=target,
        reason=str(reason),
        ts=float(ts),
        confidence=confidence,
    )
