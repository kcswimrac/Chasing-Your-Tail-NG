"""Scenario format for labeled replay sessions (D7a).

A scenario is a versioned JSON document describing one recorded or synthetic
session: an ordered list of analysis cycles, each carrying the raw source
rows observed in that cycle (the same row shapes the D1 normalizers accept),
the cycle's scenario clock timestamp, optional declarative restart points,
detector config overrides, and evaluation labels.

Example::

    {
      "scenario_version": 1,
      "scenario_id": "rogue-evil-twin-basic",
      "description": "Trusted AP plus a spoofing evil twin in cycle 2",
      "labels": {"expect": {"detect": true}},
      "config_overrides": {
        "rogue_ap_detection": {"trusted_aps": [{"ssid": "HomeNet",
            "bssid": "AA:BB:CC:00:11:01", "encryption": "WPA2-PSK", "channel": 6}]}
      },
      "restarts": [2],
      "cycles": [
        {"cycle_id": 1, "clock_ts": 1700000000.0, "rows": [
          {"source": "kismet.devices", "row": {"devmac": "AA:BB:CC:00:11:01",
            "type": "Wi-Fi AP", "last_time": 1699999990.0,
            "device": {"kismet.device.base.channel": "6"}}},
          {"source": "kismet.alerts", "row": {"ts_sec": 1699999900.0,
            "header": "DEAUTH", "json": "{...}", "src_mac": "AA:BB:CC:00:99:99",
            "dst_mac": "AA:BB:CC:00:02:22", "bssid": ""}},
          {"source": "gps", "fix": {"lat": 45.52, "lon": -122.68,
            "ts": 1700000000.0, "accuracy_m": 8.0}},
          {"source": "ble", "row": {"mac": "DD:DD:DD:DD:DD:01",
            "ts": 1700000000.0, "name": "Tile", "rssi": -70.0}}
        ]}
      ]
    }

The loader is strict: unknown keys are rejected and every field is type/range
checked, so a malformed scenario fails at load time with a named error rather
than producing a misleading replay report.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

REPLAY_SCENARIO_VERSION = 1

# Replayable fault components (D6 detector_failure scenario): a fault makes
# the named detector's scan raise through the runner's real failure path.
FAULT_DETECTOR_DEAUTH = "detector:deauth"
FAULT_DETECTOR_ROGUE = "detector:rogue"
REPLAYABLE_FAULT_COMPONENTS = (FAULT_DETECTOR_DEAUTH, FAULT_DETECTOR_ROGUE)

# Sources a scenario row may carry; same source names the D1 normalizer
# stores on observations.
SOURCE_KISMET_DEVICES = "kismet.devices"
SOURCE_KISMET_ALERTS = "kismet.alerts"
SOURCE_GPS = "gps"
SOURCE_BLE = "ble"
SUPPORTED_SOURCES = (
    SOURCE_KISMET_DEVICES,
    SOURCE_KISMET_ALERTS,
    SOURCE_GPS,
    SOURCE_BLE,
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "scenario_version",
        "scenario_id",
        "session_id",
        "description",
        "labels",
        "config_overrides",
        "close_after_seconds",
        "restarts",
        "faults",
        "cycles",
    }
)


class ScenarioError(ValueError):
    """Raised when a scenario document is malformed or out of range."""


@dataclass(frozen=True)
class ScenarioRow:
    """One raw source row inside a cycle."""

    source: str
    row: Dict[str, Any]  # kismet.devices / kismet.alerts / ble row
    gps_fix: Optional[Dict[str, Any]] = None  # set when source == "gps"


@dataclass(frozen=True)
class ScenarioCycle:
    cycle_id: int
    clock_ts: float
    rows: Tuple[ScenarioRow, ...]


@dataclass(frozen=True)
class ScenarioFault:
    """A deterministic detector failure injected from cycle N onward.

    The engine routes the fault through the production failure path (the
    detector's scan raises; the runner registers it), so the scenario proves
    what status composition does with a failing detector — never a faked
    stat.
    """

    component: str
    from_cycle: int
    error: str = "scan_error"


@dataclass(frozen=True)
class ScenarioDocument:
    scenario_id: str
    session_id: str
    description: str
    labels: Dict[str, Any]
    config_overrides: Dict[str, Any]
    close_after_seconds: float
    restarts: Tuple[int, ...]  # restart after completing cycle N
    cycles: Tuple[ScenarioCycle, ...]
    faults: Tuple[ScenarioFault, ...] = ()


def _require_mapping(value: Any, where: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{where} must be an object")
    return value


def _finite_number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScenarioError(f"{where} must be a number")
    out = float(value)
    if not math.isfinite(out):
        raise ScenarioError(f"{where} must be a finite number")
    return out


def _nonempty_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"{where} must be a non-empty string")
    return value


def _validate_row(raw: Any, cycle_desc: str, index: int) -> ScenarioRow:
    where = f"{cycle_desc} rows[{index}]"
    row_map = _require_mapping(raw, where)
    unknown = set(row_map) - {"source", "row", "fix"}
    if unknown:
        raise ScenarioError(f"{where} has unknown keys: {sorted(unknown)}")
    source = _nonempty_str(row_map.get("source"), f"{where}.source")
    if source not in SUPPORTED_SOURCES:
        raise ScenarioError(
            f"{where}.source '{source}' not in {list(SUPPORTED_SOURCES)}"
        )
    if source == SOURCE_GPS:
        fix = _require_mapping(row_map.get("fix"), f"{where}.fix")
        _finite_number(fix.get("lat"), f"{where}.fix.lat")
        _finite_number(fix.get("lon"), f"{where}.fix.lon")
        _finite_number(fix.get("ts"), f"{where}.fix.ts")
        if "accuracy_m" in fix and fix["accuracy_m"] is not None:
            _finite_number(fix["accuracy_m"], f"{where}.fix.accuracy_m")
        return ScenarioRow(source=source, row={}, gps_fix=fix)

    payload = _require_mapping(row_map.get("row"), f"{where}.row")
    if source == SOURCE_KISMET_DEVICES:
        _nonempty_str(payload.get("devmac"), f"{where}.row.devmac")
        _finite_number(payload.get("last_time"), f"{where}.row.last_time")
    elif source == SOURCE_KISMET_ALERTS:
        _finite_number(payload.get("ts_sec"), f"{where}.row.ts_sec")
    elif source == SOURCE_BLE:
        _nonempty_str(payload.get("mac"), f"{where}.row.mac")
        _finite_number(payload.get("ts"), f"{where}.row.ts")
    return ScenarioRow(source=source, row=payload)


def _validate_cycle(raw: Any, index: int) -> ScenarioCycle:
    where = f"cycles[{index}]"
    cycle_map = _require_mapping(raw, where)
    unknown = set(cycle_map) - {"cycle_id", "clock_ts", "rows"}
    if unknown:
        raise ScenarioError(f"{where} has unknown keys: {sorted(unknown)}")
    cycle_id = cycle_map.get("cycle_id")
    if isinstance(cycle_id, bool) or not isinstance(cycle_id, int):
        raise ScenarioError(f"{where}.cycle_id must be an integer")
    clock_ts = _finite_number(cycle_map.get("clock_ts"), f"{where}.clock_ts")
    raw_rows = cycle_map.get("rows", [])
    if not isinstance(raw_rows, list):
        raise ScenarioError(f"{where}.rows must be an array")
    rows = tuple(
        _validate_row(r, where, i) for i, r in enumerate(raw_rows)
    )
    return ScenarioCycle(cycle_id=cycle_id, clock_ts=clock_ts, rows=rows)


def scenario_from_dict(doc: Any) -> ScenarioDocument:
    """Validate a parsed scenario document and return its dataclasses."""
    doc_map = _require_mapping(doc, "scenario")
    version = doc_map.get("scenario_version")
    if version != REPLAY_SCENARIO_VERSION:
        raise ScenarioError(
            f"scenario_version must be {REPLAY_SCENARIO_VERSION}, got {version!r}"
        )
    unknown = set(doc_map) - _TOP_LEVEL_KEYS
    if unknown:
        raise ScenarioError(f"scenario has unknown keys: {sorted(unknown)}")

    scenario_id = _nonempty_str(doc_map.get("scenario_id"), "scenario_id")
    session_id = doc_map.get("session_id") or f"replay-{scenario_id}"
    session_id = _nonempty_str(session_id, "session_id")

    description = doc_map.get("description") or ""
    if not isinstance(description, str):
        raise ScenarioError("description must be a string")
    labels = doc_map.get("labels") or {}
    labels = _require_mapping(labels, "labels")
    overrides = doc_map.get("config_overrides") or {}
    overrides = _require_mapping(overrides, "config_overrides")

    close_after = doc_map.get("close_after_seconds", 600.0)
    close_after_f = _finite_number(close_after, "close_after_seconds")
    if close_after_f <= 0:
        raise ScenarioError("close_after_seconds must be > 0")

    raw_restarts = doc_map.get("restarts") or []
    if not isinstance(raw_restarts, list):
        raise ScenarioError("restarts must be an array of cycle ids")
    cycles = tuple(
        _validate_cycle(c, i) for i, c in enumerate(doc_map.get("cycles") or [])
    )
    if not cycles:
        raise ScenarioError("scenario must contain at least one cycle")
    seen_ids = set()
    for c in cycles:
        if c.cycle_id in seen_ids:
            raise ScenarioError(f"duplicate cycle_id: {c.cycle_id}")
        seen_ids.add(c.cycle_id)

    restarts: List[int] = []
    for r in raw_restarts:
        if isinstance(r, bool) or not isinstance(r, int):
            raise ScenarioError("restarts entries must be integers (cycle ids)")
        if r not in seen_ids:
            raise ScenarioError(
                f"restart after cycle {r} does not match any cycle_id "
                f"(restarts reference cycle_id values, and must fall "
                f"inside the session)"
            )
        restarts.append(r)

    raw_faults = doc_map.get("faults") or []
    if not isinstance(raw_faults, list):
        raise ScenarioError("faults must be an array")
    faults: List[ScenarioFault] = []
    for i, f in enumerate(raw_faults):
        f_map = _require_mapping(f, f"faults[{i}]")
        unknown = set(f_map) - {"component", "from_cycle", "error"}
        if unknown:
            raise ScenarioError(f"faults[{i}] has unknown keys: {sorted(unknown)}")
        component = _nonempty_str(f_map.get("component"), f"faults[{i}].component")
        if component not in REPLAYABLE_FAULT_COMPONENTS:
            raise ScenarioError(
                f"faults[{i}].component '{component}' is not a replayable "
                f"detector (replay runs {list(REPLAYABLE_FAULT_COMPONENTS)})"
            )
        from_cycle = f_map.get("from_cycle")
        if isinstance(from_cycle, bool) or not isinstance(from_cycle, int):
            raise ScenarioError(f"faults[{i}].from_cycle must be an integer")
        if from_cycle not in seen_ids:
            raise ScenarioError(
                f"faults[{i}].from_cycle {from_cycle} does not match any "
                f"cycle_id (faults reference cycle_id values)"
            )
        error = f_map.get("error") or "scan_error"
        error = _nonempty_str(error, f"faults[{i}].error")
        faults.append(
            ScenarioFault(component=component, from_cycle=from_cycle, error=error)
        )

    return ScenarioDocument(
        scenario_id=scenario_id,
        session_id=session_id,
        description=description,
        labels=labels,
        config_overrides=overrides,
        close_after_seconds=close_after_f,
        restarts=tuple(sorted(restarts)),
        cycles=cycles,
        faults=tuple(faults),
    )


def load_scenario(path: Any) -> ScenarioDocument:
    """Load and validate a scenario JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        try:
            doc = json.load(f)
        except json.JSONDecodeError as e:
            raise ScenarioError(f"{path}: invalid JSON: {e}") from e
    return scenario_from_dict(doc)


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursive config merge; override wins, nested dicts merge."""
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out
