"""Deterministic replay engine (D7a, engine half).

Replays a labeled scenario session through the production pipeline with an
injected clock: the same D1 normalizers persist observations, the same
``RFPluginRunner`` detectors (deauth, rogue) run per cycle, incidents flow
through the same ``CytStore`` paths, and staleness closes use the scenario
clock — never the wall clock.

Per cycle:
1. ingest — scenario rows are normalized by the production normalizers and
   recorded as observations (``recorded_ts`` = scenario clock, so the store
   itself carries no wall-clock on the replay path);
2. detect — ``RFPluginRunner.run_cycle(..., now=clock.now())`` runs the real
   detectors against the Kismet-shaped fixture DB; detector watermarks are
   persisted in ``runtime_state`` exactly as in the service;
3. stale-close — ``close_stale_incidents`` with the scenario clock.

A restart (scenario ``restarts`` or ``run(restarts=[...])``) closes and
re-opens the store and rebuilds the runner: fresh in-memory detector state,
persisted watermarks reloaded — the P0 restart-safety semantics exercised
for real. The replay keeps the scenario's logical session id across the
restart because incident keys are session-scoped in the current model;
the D2 incident model v2 makes keys session-independent.

v1 boundary: device-row detectors (ie fingerprint, BLE, GPS co-travel) are
disabled and the runner's device pull is empty — the observation-sourced
device feed arrives with the D6 detector contract migration.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyt_platform import observations as obs
from cyt_platform.replay.clock import ReplayClock
from cyt_platform.replay.fixture import KismetFixture
from cyt_platform.replay.report import build_report
from cyt_platform.replay.scenario import (
    REPLAYABLE_FAULT_COMPONENTS,
    SOURCE_BLE,
    SOURCE_GPS,
    SOURCE_KISMET_ALERTS,
    SOURCE_KISMET_DEVICES,
    ScenarioCycle,
    ScenarioDocument,
    ScenarioError,
    deep_merge,
)

# Replay runs the alert-path detectors (deauth, rogue) only. Device-row
# detectors are disabled via config, not by patching the runner.
DEFAULT_REPLAY_CONFIG: Dict[str, Any] = {
    "rf": {"deauth_enabled": True, "rogue_enabled": True},
    "ie_fingerprint": {"enabled": False},
    "ble_tracker": {"enabled": False},
    "gps_fusion": {"enabled": False},
}


class _ReplayKismetView:
    """Minimal kdb stand-in for ``RFPluginRunner.run_cycle``.

    With device-row detectors disabled the device pull is unused; it stays
    an explicit empty view rather than relying on the runner's exception
    fallback. Observation-sourced device rows arrive with D6.
    """

    def get_devices_by_time_range(self, since_ts: float) -> List[dict]:
        return []


# Scenario fault injection: component -> RFPluginRunner attribute. A fault
# replaces the detector with a proxy whose scan raises, so failures travel
# the production path (runner registers -> stats map -> state composition).
_FAULT_ATTRS = {
    "detector:deauth": "deauth",
    "detector:rogue": "rogue",
}


class _FailingDetector:
    """Detector proxy that fails every scan with a deterministic error."""

    def __init__(self, error: str):
        self._error = error
        self.last_scan_error = None

    def scan_kismet_db(self, db_path: str, now: Optional[float] = None) -> List[dict]:
        raise RuntimeError(f"fault_injected: {self._error}")

    def analyze_attacks(self) -> List[dict]:
        return []


class ReplayEngine:
    """Run one scenario session through the production pipeline.

    One engine instance performs one ``run()``; create a fresh engine (and a
    fresh store path) for an independent run.
    """

    def __init__(
        self,
        scenario: ScenarioDocument,
        *,
        store_path: Optional[Path] = None,
    ):
        self.scenario = scenario
        self.clock = ReplayClock()
        self._tmp_dir: Optional[str] = None
        if store_path is None:
            self._tmp_dir = tempfile.mkdtemp(prefix="cyt-replay-")
            store_path = Path(self._tmp_dir) / "cyt.db"
        self.store_path = Path(store_path)
        # Store and fixture live together; create the directory on demand so
        # a fresh --store-path from the CLI just works.
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.config = deep_merge(DEFAULT_REPLAY_CONFIG, scenario.config_overrides)
        # Provenance ref baked into observation source_ref values: derived
        # from the scenario id (not the temp path) so it is stable across runs.
        self._db_ref = f"scenario:{scenario.scenario_id}"

    # --- store lifecycle ---
    def _open_store(self) -> Any:
        from cyt_platform.store import CytStore

        store = CytStore.open({"path": str(self.store_path), "mode": "durable"})
        # Deterministic session identity: never uuid4 (the service's
        # begin_session) — the scenario owns the session id.
        store.set_runtime("session_id", self.scenario.session_id)
        return store

    def _build_runner(self, store: Any) -> Any:
        from cyt_platform.rf_plugins import RFPluginRunner

        return RFPluginRunner(store, self.config)

    # --- the replay loop ---
    def run(self, *, restarts: Optional[List[int]] = None) -> Dict[str, Any]:
        """Replay the scenario; return the deterministic report dict.

        ``restarts`` overrides the scenario's declarative restart points when
        given (same scenario + same restarts = byte-identical report).
        """
        points = list(
            sorted(set(restarts))
            if restarts is not None
            else self.scenario.restarts
        )
        self._validate_faults()
        fixture = KismetFixture(self.store_path.parent / "kismet_fixture.db")
        try:
            fixture.write_rows(
                row for cycle in self.scenario.cycles for row in cycle.rows
            )
            store = self._open_store()
            summaries: List[Dict[str, Any]] = []
            try:
                runner = self._build_runner(store)
                for cycle in self.scenario.cycles:
                    self.clock.set(cycle.clock_ts)
                    recorded = self._ingest_cycle(store, cycle)
                    self._apply_faults(runner, cycle.cycle_id)
                    stats = self._detect(store, runner, fixture)
                    state = self._compose_cycle_state(store, stats)
                    self._close_stale(store)
                    summaries.append(
                        {
                            "cycle_id": cycle.cycle_id,
                            "clock_ts": cycle.clock_ts,
                            "observations_recorded": len(recorded),
                            "detection": stats,
                            "state": state,
                        }
                    )
                    if cycle.cycle_id in points:
                        # Simulated service restart: close/reopen the store
                        # (watermarks live in runtime_state) and rebuild the
                        # runner with fresh in-memory detector state.
                        store.close()
                        store = self._open_store()
                        runner = self._build_runner(store)
                report = build_report(self.scenario, store, summaries, points)
            finally:
                store.close()
        finally:
            fixture.close()
            self._cleanup()
        return report

    def _cleanup(self) -> None:
        if self._tmp_dir:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None

    # --- pipeline stages ---
    def _ingest_cycle(self, store: Any, cycle: ScenarioCycle) -> List[int]:
        """Normalize scenario rows with the production normalizers and record
        them as observations (provenance-bearing, append-only)."""
        ids: List[int] = []
        with store.transaction():
            for row in cycle.rows:
                record = self._normalize_row(cycle, row)
                if record is None:
                    continue
                record["recorded_ts"] = self.clock.now()
                ids.append(store.record_observation(**record))
        return ids

    def _normalize_row(
        self, cycle: ScenarioCycle, row: Any
    ) -> Optional[dict]:
        session_id = self.scenario.session_id
        if row.source == SOURCE_KISMET_DEVICES:
            return obs.normalize_device_row(
                row.row,
                cycle_id=cycle.cycle_id,
                db_ref=self._db_ref,
                session_id=session_id,
            )
        if row.source == SOURCE_KISMET_ALERTS:
            return obs.normalize_alert_row(
                row.row,
                cycle_id=cycle.cycle_id,
                db_ref=self._db_ref,
                session_id=session_id,
            )
        if row.source == SOURCE_GPS:
            fix = row.gps_fix or {}
            return obs.normalize_gps_fix(
                lat=fix.get("lat"),
                lon=fix.get("lon"),
                ts=fix.get("ts"),
                cycle_id=cycle.cycle_id,
                accuracy_m=fix.get("accuracy_m"),
                session_id=session_id,
            )
        if row.source == SOURCE_BLE:
            return obs.normalize_ble_advertisement(
                mac=row.row.get("mac"),
                ts=row.row.get("ts"),
                cycle_id=cycle.cycle_id,
                db_ref=self._db_ref,
                name=row.row.get("name"),
                rssi=row.row.get("rssi"),
                company_id=row.row.get("company_id"),
                session_id=session_id,
            )
        return None

    def _detect(
        self, store: Any, runner: Any, fixture: KismetFixture
    ) -> Dict[str, Any]:
        # Same transaction shape as the service loop: watermark writes commit
        # atomically with the incidents derived from the same scan.
        with store.transaction():
            return runner.run_cycle(
                _ReplayKismetView(),
                str(fixture.path),
                now=self.clock.now(),
            )

    def _close_stale(self, store: Any) -> None:
        with store.transaction():
            store.close_stale_incidents(
                self.clock.now(), self.scenario.close_after_seconds
            )

    # --- faults + state (D6 detector_failure scenario) ---

    def _validate_faults(self) -> None:
        """Fail fast on faults the replay cannot route (named error, at load)."""
        for fault in self.scenario.faults:
            if fault.component not in REPLAYABLE_FAULT_COMPONENTS:
                raise ScenarioError(
                    f"fault component '{fault.component}' is not a replayable "
                    f"detector (replay runs {list(REPLAYABLE_FAULT_COMPONENTS)})"
                )

    def _apply_faults(self, runner: Any, cycle_id: int) -> None:
        """Activate declared faults for this cycle (idempotent; from_cycle N
        onward). Re-applied after restarts because the runner is rebuilt."""
        for fault in self.scenario.faults:
            if fault.from_cycle > cycle_id:
                continue
            attr = _FAULT_ATTRS[fault.component]
            if not isinstance(getattr(runner, attr, None), _FailingDetector):
                setattr(runner, attr, _FailingDetector(fault.error))

    def _compose_cycle_state(self, store: Any, stats: Dict[str, Any]) -> str:
        """Compose this cycle's state with the production status ladder.

        Open-incident counts are read with read-only SQL (same pattern as
        report.py — no incident read API exists yet); staleness is already
        handled by ``close_stale_incidents`` on the scenario clock, so no
        hold window applies. No wall clock is read.
        """
        from cyt_platform.status import compose_state

        rows = store.conn.execute(
            """
            SELECT severity, COUNT(*) AS c FROM incidents
            WHERE status='open' AND COALESCE(suppressed, 0)=0
            GROUP BY severity
            """
        ).fetchall()
        by_severity = {r["severity"]: r["c"] for r in rows}
        threat_level = 2 if by_severity.get("alert") else (
            1 if by_severity.get("watch") else 0
        )
        # Replay v1 composes the detection surface only: the fixture DB and
        # analyzer are healthy by construction, so component_fail/deaf are
        # always False — detector failures carry the degraded signal.
        state, _reason = compose_state(
            component_fail=False,
            deaf_fail_is_fail=False,
            analyzer_err=False,
            kismet_db_ok=True,
            fail_reason=None,
            threat_level=threat_level,
            quiet_watch=False,
            detector_failures=stats.get("detector_failures") or {},
        )
        return state