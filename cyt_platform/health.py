"""D6: per-component failure registry feeding status composition.

One registry receives every component's failure reports — each RF detector
(``detector:deauth``, ``detector:rogue``, ``detector:ie``, ``detector:ble``),
the GPS fusion feed (``gps``), and the plugin runner itself (``rf_runner``) —
and renders them for status composition. StatusEngine.publish keeps its
existing publish semantics (parks on write failure, recovers by rewriting the
true snapshot); the registry only changes WHAT is composed, never HOW the
snapshot is written.

Two invariants:

- A failing component degrades the published state — ``clear`` would read as
  "no threat", which a safety device must never say while blind.
- Recovery is explicit: a component stops failing only when its owner reports
  a successful cycle, never by timeout or restart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from cyt_platform.kismet_ro import WATERMARK_SKEW_ALLOWANCE_S

# Components whose failure means reduced detection. The aggregate
# "detectors" component in status.json stays derived from this prefix.
DETECTOR_PREFIX = "detector:"

# GPS dropout: no located fix for the operator feed. A short gap is normal
# (cold start, tunnel); past the grace window the feed is treated as dead.
GPS_DROPOUT_DEFAULT_SECONDS = 900.0

# First-cycle state for a sensor that has never produced a fix.
GPS_NEVER_SEEN = "no_fix"
GPS_DROPOUT = "dropout"


def gps_dropout_reason(
    *,
    last_fix_ts: Optional[float],
    now: float,
    dropout_seconds: float,
    min_cycles_before_dropout: int = 0,
    cycles_seen: int = 1,
) -> Optional[str]:
    """Reason the GPS feed is considered degraded, or None when healthy.

    Pure function of the last known fix and the scenario clock (locked
    decision 4): replayable, no wall-clock reads. A feed that has never
    produced a fix is ``no_fix`` as soon as it is given a real chance
    (``min_cycles_before_dropout`` cycles); a feed whose newest fix is older
    than ``dropout_seconds`` is ``dropout``. Inside the grace window the feed
    is considered warm and healthy.
    """
    if dropout_seconds <= 0:
        raise ValueError("dropout_seconds must be > 0")
    if last_fix_ts is None:
        if cycles_seen >= max(1, min_cycles_before_dropout):
            return GPS_NEVER_SEEN
        return None
    age = now - last_fix_ts
    if age < 0:
        # Clock moved backwards / out-of-order fix; treat as fresh rather
        # than fabricate a failure.
        return None
    return GPS_DROPOUT if age > dropout_seconds else None


# Reason code for the ``clock`` component: a watermark or captured event is
# stamped ahead of the analyzer's own clock by more than the skew allowance.
CLOCK_AHEAD = "clock_ahead"


def clock_skew_reason(
    *,
    watermark: Optional[float],
    newest_event_ts: Optional[float],
    now: float,
    skew_allowance_s: float = WATERMARK_SKEW_ALLOWANCE_S,
) -> Optional[str]:
    """Reason the ``clock`` component is failing, or None when healthy.

    Pure function of the suspect timestamps and the scenario clock (locked
    decision 4). A persisted watermark or a captured event stamped more
    than ``skew_allowance_s`` ahead of ``now`` means the capture's clock
    and the analyzer's clock disagree; detection over such a skew cannot
    be trusted, so it must be visible rather than silently applied.
    """
    ahead = 0.0
    for ts in (watermark, newest_event_ts):
        if ts is not None and ts - now > ahead:
            ahead = ts - now
    if ahead <= skew_allowance_s:
        return None
    return CLOCK_AHEAD


@dataclass
class ComponentFailure:
    """One failing component: what broke, why, and since when."""

    component: str
    reason: str
    failing_since: float


@dataclass
class ComponentFailureRegistry:
    """Failure state for every reporting component (D6 health).

    ``record_failure`` is idempotent per component: the first failing cycle
    pins ``failing_since``; later reports refresh the reason but not the
    since-ts. ``record_success`` clears the failure and stamps ``last_ok``.
    Timestamps are supplied by the caller (scenario clock under replay);
    only init-time failures without a clock may fall back to the wall clock,
    which never reaches replay output (reasons are rendered without ts).
    """

    _failures: Dict[str, ComponentFailure] = field(default_factory=dict)
    _last_ok: Dict[str, float] = field(default_factory=dict)

    def record_failure(self, component: str, reason: str, ts: Optional[float] = None) -> None:
        if ts is None:
            ts = time.time()
        existing = self._failures.get(component)
        if existing is None:
            self._failures[component] = ComponentFailure(
                component=component, reason=reason, failing_since=ts
            )
        else:
            existing.reason = reason

    def record_success(self, component: str, ts: Optional[float] = None) -> None:
        self._failures.pop(component, None)
        if ts is not None:
            self._last_ok[component] = ts

    def is_failing(self, component: str) -> bool:
        return component in self._failures

    def failures(self) -> Dict[str, str]:
        """Component -> sanitized failure detail; sorted, empty when healthy."""
        return {name: f.reason for name, f in sorted(self._failures.items())}

    def failing_since(self, component: str) -> Optional[float]:
        f = self._failures.get(component)
        return f.failing_since if f else None

    def last_ok(self, component: str) -> Optional[float]:
        return self._last_ok.get(component)

    def components(self) -> Dict[str, dict]:
        """Render per-component health entries for the status snapshot.

        Every failing component renders ``ok: false`` with its reason and
        ``failing_since``; components that have reported success render
        ``ok: true`` with ``last_ok``. Healthy components never reported
        into the registry are absent — the caller composes those.
        """
        out: Dict[str, dict] = {}
        for name, f in sorted(self._failures.items()):
            entry: Dict[str, object] = {"ok": False, "reason": f.reason}
            if f.failing_since is not None:
                entry["failing_since"] = f.failing_since
            out[name] = entry
        for name, ts in sorted(self._last_ok.items()):
            if name in out:
                continue
            out[name] = {"ok": True, "last_ok": ts}
        return out
