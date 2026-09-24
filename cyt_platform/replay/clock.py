"""Injected clock for deterministic replay (D7a).

Detection logic must never read the wall clock (locked decision 4 of the
trustworthiness build: deterministic core, injected clock). Under replay the
engine advances this clock to each scenario cycle's ``clock_ts`` and passes
``clock.now()`` into every clock-aware seam (``RFPluginRunner.run_cycle``,
``close_stale_incidents``, observation ``recorded_ts``).
"""

from __future__ import annotations


class ReplayClock:
    """Minimal settable clock handed to the replayed pipeline."""

    def __init__(self) -> None:
        self._now: float = 0.0

    def set(self, ts: float) -> None:
        self._now = float(ts)

    def now(self) -> float:
        return self._now
