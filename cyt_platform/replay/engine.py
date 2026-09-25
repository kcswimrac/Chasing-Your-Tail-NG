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

The fixture DB also feeds the device-row path: the runner's device pull
reads the same Kismet-shaped fixture read-only with the same row shape as
the live ``SecureKismetDB`` pull (``last_time >= since_ts``), so BLE
tracking and GPS co-travel see exactly the rows the live capture would
return. Device-row detectors stay disabled unless the scenario enables
them via ``config_overrides``.
"""

from __future__ import annotations

import json
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

# Replay runs every enabled detector against the fixture: the alert scan
# paths read the alerts table and the device pull reads the devices table,
# both read-only.
DEFAULT_REPLAY_CONFIG: Dict[str, Any] = {
    "rf": {"deauth_enabled": True, "rogue_enabled": True},
    "ie_fingerprint": {"enabled": False},
    "ble_tracker": {"enabled": False},
    "gps_fusion": {"enabled": False},
}


class _ReplayKismetView:
    """Fixture-backed kdb stand-in for ``RFPluginRunner.run_cycle``.

    Serves the device pull from the scenario's Kismet-shaped fixture DB,
    read-only, with the same row shape and ``last_time >= since_ts``
    semantics as the live ``SecureKismetDB`` pull. Only
    ``get_devices_by_time_range`` is implemented because it is the only
    method the device-row detectors consume.

    A live capture DB only contains rows up to the current time; the
    replay fixture holds the whole session at once. ``max_ts`` (set to
    the cycle clock before each detect stage) reproduces the live bound:
    rows dated after the cycle clock are not yet visible.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self.max_ts: Optional[float] = None

    def get_devices_by_time_range(self, since_ts: float) -> List[dict]:
        from cyt_platform.kismet_ro import connect_readonly

        query = (
            "SELECT devmac, type, device, last_time FROM devices "
            "WHERE last_time >= ?"
        )
        params: List[Any] = [since_ts]
        if self.max_ts is not None:
            query += " AND last_time <= ?"
            params.append(self.max_ts)
        query += " ORDER BY rowid"

        conn = connect_readonly(self._db_path)
        try:
            rows = conn.execute(query, params).fetchall()
        finally:
            conn.close()
        out: List[dict] = []
        for devmac, dev_type, device, last_time in rows:
            try:
                device_data = json.loads(device) if device else None
            except (ValueError, TypeError):
                device_data = None
            out.append(
                {
                    "mac": devmac,
                    "type": dev_type,
                    "device_data": device_data,
                    "last_time": last_time,
                }
            )
        return out


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

    def _build_lifecycle(self, store: Any) -> Optional[Any]:
        """The D2 incident lifecycle engine, opt-in via incidents_v2.enabled.

        Off by default so pre-lifecycle scenario reports stay byte-identical
        (no phenomenon rows, no transition events, no lifecycle summary key).
        Rebuilt with the store after simulated restarts — the engine holds a
        store reference, and restart reopens the store.
        """
        from cyt_platform.incidents import IncidentEngine

        if not (self.config.get("incidents_v2") or {}).get("enabled"):
            return None
        return IncidentEngine(store, self.config)

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
                lifecycle = self._build_lifecycle(store)
                # Built once after the fixture is populated; read-only and
                # stateless, so it survives simulated restarts unchanged.
                kdb = _ReplayKismetView(str(fixture.path))
                for cycle in self.scenario.cycles:
                    self.clock.set(cycle.clock_ts)
                    # Rows dated after this cycle's clock are not yet visible
                    # (a live capture cannot contain rows from the future).
                    kdb.max_ts = cycle.clock_ts
                    recorded = self._ingest_cycle(store, cycle)
                    self._apply_faults(runner, cycle.cycle_id)
                    stats = self._detect(store, runner, kdb, fixture)
                    state = self._compose_cycle_state(store, stats)
                    lifecycle_transitions = 0
                    if lifecycle is not None:
                        # The engine owns phenomenon state: one apply per
                        # cycle, after detection, before stale-close (its
                        # own staleness decay handles lifecycle rows).
                        with store.transaction():
                            lifecycle_transitions = len(
                                lifecycle.apply(self.clock.now())
                            )
                    self._close_stale(store)
                    summary = {
                        "cycle_id": cycle.cycle_id,
                        "clock_ts": cycle.clock_ts,
                        "observations_recorded": len(recorded),
                        "detection": stats,
                        "state": state,
                    }
                    if lifecycle is not None:
                        summary["lifecycle_transitions"] = lifecycle_transitions
                    summaries.append(summary)
                    if cycle.cycle_id in points:
                        # Simulated service restart: close/reopen the store
                        # (watermarks live in runtime_state) and rebuild the
                        # runner with fresh in-memory detector state.
                        store.close()
                        store = self._open_store()
                        runner = self._build_runner(store)
                        lifecycle = self._build_lifecycle(store)
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
        self, store: Any, runner: Any, kdb: Any, fixture: KismetFixture
    ) -> Dict[str, Any]:
        # Same transaction shape as the service loop: watermark writes commit
        # atomically with the incidents derived from the same scan. The runner
        # owns every detector, including the gps fusion; its pull window now
        # shares the runner's injected clock.
        with store.transaction():
            return runner.run_cycle(
                kdb,
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