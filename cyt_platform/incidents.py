"""Incident dedup: MatchEvent → CytStore.observe_incident (+ baseline + evidence)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from cyt_platform.baseline import BaselineEngine
from cyt_platform.confidence import alert_gate
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


# Severity rank used for stepwise escalation/de-escalation (never a jump:
# NEW -> ALERT is illegal per ALLOWED, so the engine walks the chain).
_ESCALATION_PATH: Tuple[IncidentStatus, ...] = (
    IncidentStatus.NEW,
    IncidentStatus.OBSERVING,
    IncidentStatus.WATCH,
    IncidentStatus.ALERT,
)
_STATE_RANK: Dict[IncidentStatus, int] = {
    state: rank for rank, state in enumerate(_ESCALATION_PATH)
}

# Default knobs for the D2 engine (config section ``incidents_v2``). All
# thresholds are config-owned with documented rationale — locked decision 8.
#
# There is no ``enabled`` key: the lifecycle is the only writer of incident
# state and status derives from lifecycle rows only, so switching the engine
# off would silently blind status (the exact "cannot detect looks like no
# threat" failure the build exists to prevent). Evidence-first is the
# product principle (locked decision 1), not an option.
INCIDENTS_V2_DEFAULTS: Dict[str, Any] = {
    # Fused confidence at/above which an OBSERVING incident becomes WATCH.
    "watch_confidence": 0.30,
    # Fused confidence at/above which WATCH may become ALERT (still gated
    # by alert_gate + corroboration below).
    "alert_confidence": 0.60,
    # Alert escalation needs corroboration beyond the fusion gate: at least
    # this many DISTINCT non-repetition detectors contributing to the
    # phenomenon (the spec's "tracker-class detector corroboration" leg; the
    # "2 independent locations" leg is covered by the fusion gate's
    # independent-kind rule). Window-match repetition kinds (see
    # REPETITION_KINDS) never count: a subject seen again is repetition,
    # not a second detector (S1).
    "alert_min_detectors": 2,
    # Stale-close: no fresh evidence for this long -> RESOLVED.
    "close_after_s": 600.0,
    # Decay: no fresh evidence this long -> step down (ALERT -> WATCH ->
    # OBSERVING) one step per staleness evaluation.
    "decay_grace_s": 120.0,
    # Reopening windows (spec D2). RESOLVED is an AUTOMATIC staleness close,
    # not an operator judgment — a fresh observation reopens immediately
    # (window 0.0): a blind window on a live subject would contradict the
    # product principle. Operators who want the spec's literal 24h episode
    # separation set this to 86400.0.
    "reopen_resolved_s": 0.0,
    # Operator dispositions (FALSE_POSITIVE / KNOWN_DEVICE) DO stick: fresh
    # evidence inside this window is noted on the timeline but does not
    # re-flag the subject; after it, evidence reopens as NEW.
    "reopen_disposition_s": 604800.0,  # 7 days
}

# S12: the consumption cursor is a SEQUENCE (store-assigned updated_seq),
# not a timestamp. A timestamp cursor — max(now, newest_last_seen) —
# silently skipped rows filed later whose evidence time trailed the cycle
# clock (deauth results carry the attack's last-frame time). The old
# "incidents_v2_cursor" key is migrated away in the store's v4 block.
CURSOR_RUNTIME_KEY = "incidents_v2_cursor_seq"

# S1: window-match repetition kinds — the MatchEvent emissions the deduper
# files (a subject or SSID being seen AGAIN). Repetition by definition, so
# these rows corroborate presence but are never a second DETECTOR: they must
# not satisfy alert_min_detectors, or one real detector row plus one
# repetition row walks a phenomenon new→observing→watch→alert.
REPETITION_KINDS = frozenset({"mac_reappear", "ssid_probe_repeat"})


def phenomenon_key_for(subject_type: str, subject: str) -> str:
    """The session-independent phenomenon key: the SUBJECT, nothing else.

    Deliberately excludes event type, window label, and session id — the
    spec's merge invariant is one phenomenon per subject (window-match +
    co-travel + IE on one MAC is ONE explained case, not three incidents).
    Cross-identity unification (two MACs, one device) is the identity
    layer's job (D3 hypotheses), not the key's.
    """
    return f"ph:{subject_type}:{subject}"


class IncidentEngine:
    """Owns lifecycle state for phenomenon incidents (D2).

    Per cycle ``apply(now)``:
    1. staleness pass — active phenomena with no fresh evidence decay
       (ALERT -> WATCH -> OBSERVING) and stale-close to RESOLVED;
    2. detection pass — detector incident rows observed since the cursor
       are grouped by phenomenon key, fused through the D4 model, and the
       phenomenon advances through the state machine (escalating stepwise,
       de-escalating when fused confidence drops, reopening disposed
       incidents only per their windows).

    Detectors never write lifecycle state: they persist detection rows
    through ``CytStore.observe_incident`` (the same choke point they use
    today); the engine is the only writer of lifecycle columns. The state
    lives in the store, so a restart rehydrates exactly where the
    phenomenon was — no replayed transitions, no duplicated incidents.
    """

    def __init__(self, store: Any, config: Optional[dict] = None):
        self.store = store
        self._source_config = config or {}
        cfg = dict(INCIDENTS_V2_DEFAULTS)
        raw = dict(self._source_config.get("incidents_v2") or {})
        if not isinstance(self._source_config.get("incidents_v2") or {}, dict):
            raise ValueError("config['incidents_v2'] must be a mapping")
        obsolete = raw.pop("enabled", None)
        if obsolete is not None:
            # The engine is always on since the evidence-first wiring (B1);
            # fail loudly in logs rather than pretend a switch exists.
            logger.warning(
                "config incidents_v2.enabled is obsolete (engine is always on); "
                "ignoring %r — remove the key",
                obsolete,
            )
        cfg.update(raw)
        self.cfg = cfg
        self._validate_cfg()

    def _validate_cfg(self) -> None:
        watch = float(self.cfg["watch_confidence"])
        alert = float(self.cfg["alert_confidence"])
        if not 0.0 <= watch <= 1.0 or not 0.0 <= alert <= 1.0:
            raise ValueError("incidents_v2 thresholds must be within [0, 1]")
        if alert < watch:
            raise ValueError(
                "incidents_v2.alert_confidence must be >= watch_confidence"
            )
        if float(self.cfg["alert_min_detectors"]) < 1:
            raise ValueError("incidents_v2.alert_min_detectors must be >= 1")
        for key in ("close_after_s", "decay_grace_s", "reopen_resolved_s", "reopen_disposition_s"):
            if float(self.cfg[key]) < 0.0:
                raise ValueError(f"incidents_v2.{key} must be >= 0")

    # --- the cycle entry point ---

    def apply(self, now: float) -> List[TransitionPlan]:
        """Run one engine cycle at scenario/host time ``now`` (never wall)."""
        plans: List[TransitionPlan] = []
        plans.extend(self._staleness_pass(now))
        plans.extend(self._detection_pass(now))
        return plans

    # --- staleness / decay ---

    def _staleness_pass(self, now: float) -> List[TransitionPlan]:
        plans: List[TransitionPlan] = []
        close_after = float(self.cfg["close_after_s"])
        grace = float(self.cfg["decay_grace_s"])
        for row in self.store.active_phenomenon_incidents():
            state = IncidentStatus(row["lifecycle_state"])
            elapsed = now - float(row["last_seen"])
            if elapsed <= grace and state is not IncidentStatus.ALERT:
                continue
            if elapsed > close_after:
                plans.append(
                    self._apply(
                        row, IncidentStatus.RESOLVED,
                        f"stale_close: no evidence for {elapsed:.0f}s", now,
                        float(row["confidence"] or 0.0),
                    )
                )
            elif elapsed > grace:
                if state is IncidentStatus.ALERT:
                    plans.append(
                        self._apply(
                            row, IncidentStatus.WATCH,
                            f"decay: no fresh evidence for {elapsed:.0f}s", now,
                            float(row["confidence"] or 0.0),
                        )
                    )
                elif state is IncidentStatus.WATCH:
                    plans.append(
                        self._apply(
                            row, IncidentStatus.OBSERVING,
                            f"decay: no fresh evidence for {elapsed:.0f}s", now,
                            float(row["confidence"] or 0.0),
                        )
                    )
        return [p for p in plans if p is not None]

    # --- detection consumption ---

    def _detection_pass(self, now: float) -> List[TransitionPlan]:
        rows = self.store.touched_incidents_since(self._load_cursor())
        if not rows:
            # Nothing consumed: a sequence cursor does not advance on wall
            # time (S12). Anything filed after this pass — even with
            # evidence time behind `now` — is picked up next cycle.
            return []

        # Baseline-suppressed detector rows are noted-and-ignored: they
        # advance the cursor (they have been consumed) but never open,
        # touch, corroborate, or escalate a phenomenon. Status counts
        # lifecycle rows only, so an unsuppressed phenomenon derived from
        # a suppressed detector row would silently reintroduce the very
        # alerts the baseline exists to prevent.
        active = [r for r in rows if not r.get("suppressed")]

        plans: List[TransitionPlan] = []
        if not active:
            self._advance_cursor(rows)
            return []
        groups = self._group_by_phenomenon(active)
        for key in sorted(groups):
            group_rows = groups[key]
            row0 = group_rows[0]
            freshest = max(float(r["last_seen"]) for r in group_rows)
            existing = self.store.get_incident_by_key(key)
            if existing is None:
                self.store.ensure_phenomenon_incident(
                    incident_key=key,
                    entity_type=row0["entity_type"],
                    subject=row0["entity_key"],
                    ts=freshest,
                    session_id=row0["session_id"],
                )
                existing = self.store.get_incident_by_key(key)
            elif existing["lifecycle_state"] in TERMINAL_STATES:
                reopened = self._maybe_reopen(existing, now)
                if reopened is not None:
                    plans.append(reopened)
                    existing = self.store.get_incident_by_key(key)
                else:
                    # Disposition sticks: the evidence goes on the record
                    # (timeline note) but does not re-flag the subject.
                    self.store.append_incident_note(
                        int(existing["id"]),
                        freshest,
                        f"evidence suppressed during reopen window "
                        f"({row0['event_type']} on {row0['entity_key']})",
                    )
                    continue

            # Evidence time moves the staleness clock, never the
            # transitions themselves (touch, don't let state moves
            # defer staleness).
            incident_id = int(existing["id"])
            self.store.touch_incident(incident_id, freshest)
            # Every detector row in the group is a recorded contribution
            # (cumulative upsert) — the incident's “who contributed what”
            # ledger, and the corroboration memory across cycles.
            for r in group_rows:
                self.store.record_contribution(
                    incident_id,
                    str(r["event_type"]),
                    str(r["event_type"]),
                    float(r["last_seen"]),
                )
            assessment = self._fuse_group(group_rows)
            if assessment is not None:
                plans.extend(
                    self._advance(existing, assessment, group_rows, now)
                )
        self._advance_cursor(rows)
        return plans

    def _load_cursor(self) -> int:
        raw = self.store.get_runtime(CURSOR_RUNTIME_KEY)
        return int(float(raw)) if raw else 0

    def _advance_cursor(self, rows: List[dict]) -> None:
        """Persist the consumption cursor (restart-safe, watermark-shaped).

        Sequence-based (S12): the cursor runs on ``updated_seq`` — the
        sequence the store assigns when a row is filed or re-filed — never
        on evidence time, so late-stamped rows are never skipped. Rows only
        move the cursor forward; quiet cycles advance nothing.
        """
        newest = max(int(r["updated_seq"]) for r in rows)
        self.store.set_runtime(
            CURSOR_RUNTIME_KEY, repr(max(self._load_cursor(), newest))
        )

    def _group_by_phenomenon(self, rows: List[dict]) -> Dict[str, List[dict]]:
        groups: Dict[str, List[dict]] = {}
        for row in rows:
            key = phenomenon_key_for(row["entity_type"], row["entity_key"])
            groups.setdefault(key, []).append(row)
        return groups

    # --- fusion + state advance ---

    def _fuse_group(self, rows: List[dict]) -> Optional[Any]:
        """Fuse one phenomenon's detector rows through the D4 model.

        Each row becomes a DetectionResult shell (the row already carries
        its fusion-attached evidence lines from the emit path); fusing the
        shells re-derives weights from the same config table, so the
        assessment is identical to fusing the original results — and
        merges across evidence classes for free.
        """
        from cyt_platform.confidence import fuse
        from cyt_platform.detectors import DetectionResult

        shells: List[DetectionResult] = []
        for row in rows:
            lines, contras = _row_evidence_lines(row)
            shells.append(
                DetectionResult(
                    detector=row["event_type"],
                    kind=row["event_type"],
                    subject=row["entity_key"],
                    subject_type=row["entity_type"],
                    window_label=row["window_label"],
                    severity=row["severity"],
                    observed_at=float(row["last_seen"]),
                    summary=row["summary"],
                    evidence=lines,
                    contra=contras,
                )
            )
        try:
            return fuse(shells, config=self._source_config)
        except Exception:  # noqa: BLE001 - fusion must never kill the engine
            logger.exception("incident fusion failed for %s rows", len(rows))
            return None

    def _advance(
        self, existing: Any, assessment: Any, rows: List[dict], now: float
    ) -> List[TransitionPlan]:
        """Walk the phenomenon toward its evidence-justified state.

        Escalation is stepwise (the machine has no NEW -> ALERT edge);
        de-escalation on fresh lower-confidence evidence steps down but
        never below OBSERVING (no OBSERVING -> NEW edge). Repetition-only
        assessments cannot escalate past WATCH — ``alert_gate`` demotes
        the proposed severity before any transition (the D4 handoff).
        """
        watch_conf = float(self.cfg["watch_confidence"])
        alert_conf = float(self.cfg["alert_confidence"])
        min_detectors = int(self.cfg["alert_min_detectors"])
        confidence = float(assessment.confidence)

        proposed = (
            "alert"
            if confidence >= alert_conf
            else "watch"
            if confidence >= watch_conf
            else "info"
        )
        gated = alert_gate(assessment, proposed)
        # S1: repetition rows are not detector corroboration — count only
        # distinct non-repetition detectors toward the alert gate.
        distinct_detectors = len(
            {d for d in assessment.detectors if d not in REPETITION_KINDS}
        )
        # Corroboration (NEW -> OBSERVING): a second DetectionResult in this
        # group, confidence already at the watch bar, or a cumulative second
        # contribution from an earlier cycle (the ledger outlives cycles).
        corroborated = (
            len(rows) >= 2
            or confidence >= watch_conf
            or self.store.count_incident_contributions(int(existing["id"])) >= 2
        )

        if gated == "alert":
            desired = (
                IncidentStatus.ALERT
                if assessment.may_alert and distinct_detectors >= min_detectors
                else IncidentStatus.WATCH
            )
        elif gated == "watch":
            desired = IncidentStatus.WATCH
        else:
            desired = IncidentStatus.OBSERVING if corroborated else IncidentStatus.NEW

        ref = _ref_from_row(existing)
        current = ref.lifecycle_state
        current_rank = _STATE_RANK[current]
        desired_rank = _STATE_RANK[desired]
        plans: List[TransitionPlan] = []

        reason = (
            f"fused confidence {confidence:.2f} "
            f"({len(assessment.independent_kinds)} kinds, "
            f"{distinct_detectors} detector(s), gated={gated})"
        )
        while current_rank < desired_rank:
            nxt = _ESCALATION_PATH[current_rank + 1]
            plan = transition(ref, nxt, reason, now, confidence)
            self.store.apply_transition(plan)
            plans.append(plan)
            ref = IncidentRef(
                incident_id=ref.incident_id,
                incident_key=ref.incident_key,
                lifecycle_state=nxt,
                confidence=confidence,
                last_seen=ref.last_seen,
                disposition=ref.disposition,
            )
            current_rank += 1
        while current_rank > desired_rank and current_rank >= _STATE_RANK[IncidentStatus.WATCH]:
            down = {
                _STATE_RANK[IncidentStatus.ALERT]: IncidentStatus.WATCH,
                _STATE_RANK[IncidentStatus.WATCH]: IncidentStatus.OBSERVING,
            }[current_rank]
            plan = transition(ref, down, reason, now, confidence)
            self.store.apply_transition(plan)
            plans.append(plan)
            ref = IncidentRef(
                incident_id=ref.incident_id,
                incident_key=ref.incident_key,
                lifecycle_state=down,
                confidence=confidence,
                last_seen=ref.last_seen,
                disposition=ref.disposition,
            )
            current_rank -= 1
        if not plans:
            # Evidence changed but the state held: keep the row's fused
            # confidence current (no timeline row — that is for moves).
            self.store.update_incident_confidence(ref.incident_id, confidence)
        return plans

    # --- dispositions + reopen ---

    def dispose(
        self,
        incident_key: str,
        disposition: IncidentStatus,
        ts: float,
        reason: str = "operator_disposition",
    ) -> TransitionPlan:
        """Apply an operator disposition to an active phenomenon incident."""
        if disposition not in (
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.KNOWN_DEVICE,
        ):
            raise ValueError(
                f"dispose() takes RESOLVED/FALSE_POSITIVE/KNOWN_DEVICE, got {disposition}"
            )
        row = self.store.get_incident_by_key(incident_key)
        if row is None:
            raise ValueError(f"unknown incident: {incident_key}")
        if row["lifecycle_state"] is None:
            raise ValueError(
                f"{incident_key} is a detector-owned row, not an "
                "engine-managed phenomenon incident"
            )
        if row["lifecycle_state"] not in (
            IncidentStatus.NEW.value,
            IncidentStatus.OBSERVING.value,
            IncidentStatus.WATCH.value,
            IncidentStatus.ALERT.value,
        ):
            raise InvalidTransition(
                incident_key,
                IncidentStatus(row["lifecycle_state"]),
                disposition,
            )
        return self._apply(row, disposition, reason, ts, float(row["confidence"] or 0.0))

    def _maybe_reopen(self, existing: Any, now: float) -> Optional[TransitionPlan]:
        """Reopen a terminal incident on fresh evidence, per its window.

        RESOLVED is an automatic staleness close: it reopens immediately by
        default (reopen_resolved_s = 0). Operator dispositions
        (FALSE_POSITIVE / KNOWN_DEVICE) stick for reopen_disposition_s —
        inside the window the caller records a note instead.
        """
        state = IncidentStatus(existing["lifecycle_state"])
        window = (
            float(self.cfg["reopen_resolved_s"])
            if state is IncidentStatus.RESOLVED
            else float(self.cfg["reopen_disposition_s"])
        )
        closed_at = float(existing["closed_at"] or 0.0)
        if now - closed_at < window:
            return None
        return self._apply(
            existing,
            IncidentStatus.NEW,
            f"reopened: fresh evidence after {state.value} "
            f"({now - closed_at:.0f}s past close)",
            now,
            float(existing["confidence"] or 0.0),
        )

    # --- the single persistence path ---

    def _apply(
        self, row: Any, to: IncidentStatus, reason: str, ts: float, confidence: float
    ) -> TransitionPlan:
        """Validate through the pure machine, persist, return the plan."""
        ref = _ref_from_row(row)
        plan = transition(ref, to, reason, ts, confidence)
        self.store.apply_transition(plan)
        return plan


def _ref_from_row(row: Any) -> IncidentRef:
    """IncidentRef view of an incident row (store row or dict)."""
    return IncidentRef(
        incident_id=int(row["id"]),
        incident_key=str(row["incident_key"]),
        lifecycle_state=IncidentStatus(row["lifecycle_state"]),
        confidence=float(row["confidence"] or 0.0),
        last_seen=float(row["last_seen"] or 0.0),
        disposition=row["disposition"],
    )


def _row_evidence_lines(
    row: dict,
) -> Tuple[Tuple[Any, ...], Tuple[Any, ...]]:
    """Extract weighted evidence/contra lines from a detector incident row.

    Rows emitted through the contract carry the D4 fusion block (why/against
    with weights); rows from paths without fusion get one conservative line
    named by their event type, weighted by the fusion table's default.
    """
    from cyt_platform.detectors import EvidenceLine

    raw = row.get("evidence_json")
    block = None
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                block = parsed.get("fusion")
        except json.JSONDecodeError:
            block = None
    if block and (block.get("why") or block.get("against")):
        why = tuple(
            EvidenceLine(
                kind=str(c.get("kind") or "unknown"),
                detail=str(c.get("detail") or ""),
                obs_ids=tuple(c.get("obs_ids") or ()),
                weight=float(c.get("weight") or 0.0),
            )
            for c in block.get("why") or []
        )
        against = tuple(
            EvidenceLine(
                kind=str(c.get("kind") or "unknown"),
                detail=str(c.get("detail") or ""),
                obs_ids=tuple(c.get("obs_ids") or ()),
                weight=-abs(float(c.get("weight") or 0.0)),
            )
            for c in block.get("against") or []
        )
        return why, against
    return (
        EvidenceLine(str(row["event_type"]), str(row["summary"])),
    ), ()
