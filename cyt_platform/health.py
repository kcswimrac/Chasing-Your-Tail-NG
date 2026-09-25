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

# Components whose failure means reduced detection. The aggregate
# "detectors" component in status.json stays derived from this prefix.
DETECTOR_PREFIX = "detector:"


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
