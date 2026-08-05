"""Incident dedup: MatchEvent → CytStore.observe_incident (+ baseline + evidence)."""

from __future__ import annotations

import logging
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
