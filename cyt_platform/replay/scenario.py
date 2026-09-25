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


# ---------------------------------------------------------------------------
# B6: store-to-scenario export — make live alerts replayable.
# ---------------------------------------------------------------------------

# Reconstruction notes, per source. The exporter rebuilds the raw source rows
# the D1 normalizers accept from the whitelisted observation payloads, so a
# replayed export re-runs the production normalizers and detectors on the
# same values the live service saw:
#   - kismet.devices: devmac/type/last_time plus the whitelisted device JSON
#     fields (signal, channel, frequency, commonname, manuf). Probe-SSID text
#     is not persisted (privacy whitelist keeps only the count), so the
#     reconstructed device JSON carries no SSID lists — detection that reads
#     them cannot be reproduced from an export by design.
#   - kismet.alerts: the deauth scan resolves attacker/victim from the alert
#     JSON's MAC fields; those are preserved in the payload and rebuilt into
#     the exported ``json`` blob, so deauth detection round-trips exactly.
#   - gps: lat/lon/ts/accuracy_m survive as columns on the observation.
#   - ble: mac/ts plus the advertised name, rssi, and company id the tracker
#     scores on.
_EXPORT_ALERT_JSON_KEYS = (
    ("source_mac", "kismet.alert.source_mac"),
    ("dest_mac", "kismet.alert.dest_mac"),
    ("channel", "kismet.alert.channel"),
)


def _device_row_from_payload(
    identity_key: str, ts: float, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Rebuild a kismet.devices-shaped row from a whitelisted payload."""
    device: Dict[str, Any] = {}
    if payload.get("rssi") is not None:
        device["kismet.device.base.signal"] = {
            "kismet.common.signal.last_signal": payload["rssi"]
        }
    for payload_key, device_key in (
        ("channel", "kismet.device.base.channel"),
        ("frequency", "kismet.device.base.frequency"),
        ("commonname", "kismet.device.base.commonname"),
        ("manuf", "kismet.device.base.manuf"),
    ):
        if payload.get(payload_key) is not None:
            device[device_key] = payload[payload_key]
    row: Dict[str, Any] = {
        "devmac": identity_key,
        "last_time": ts,
        "device": device,
    }
    if payload.get("device_type") is not None:
        row["type"] = payload["device_type"]
    return row


def _alert_row_from_payload(
    ts: float, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Rebuild a kismet.alerts-shaped row from a whitelisted payload."""
    alert_json: Dict[str, Any] = {}
    if payload.get("header"):
        alert_json["kismet.alert.header"] = payload["header"]
    if payload.get("text"):
        alert_json["kismet.alert.text"] = payload["text"]
    for payload_key, json_key in _EXPORT_ALERT_JSON_KEYS:
        if payload.get(payload_key) is not None:
            alert_json[json_key] = payload[payload_key]
    row: Dict[str, Any] = {"ts_sec": ts, "json": alert_json}
    for col_key in ("header", "src_mac", "dst_mac", "bssid"):
        if payload.get(col_key) is not None:
            row[col_key] = payload[col_key]
    return row


def _scenario_rows_for_observation(obs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map one persisted observation to its v1 scenario row shape."""
    source = obs.get("source")
    payload = obs.get("payload") or {}
    ts = float(obs["ts"])
    if source == SOURCE_GPS:
        fix: Dict[str, Any] = {"lat": obs["lat"], "lon": obs["lon"], "ts": ts}
        if obs.get("accuracy_m") is not None:
            fix["accuracy_m"] = obs["accuracy_m"]
        return [{"source": SOURCE_GPS, "fix": fix}]
    if source == SOURCE_BLE:
        ble_row: Dict[str, Any] = {"mac": obs["identity_key"], "ts": ts}
        for key in ("name", "rssi", "company_id"):
            if payload.get(key) is not None:
                ble_row[key] = payload[key]
        return [{"source": SOURCE_BLE, "row": ble_row}]
    if source == SOURCE_KISMET_ALERTS:
        return [
            {"source": SOURCE_KISMET_ALERTS, "row": _alert_row_from_payload(ts, payload)}
        ]
    if source == SOURCE_KISMET_DEVICES:
        return [
            {
                "source": SOURCE_KISMET_DEVICES,
                "row": _device_row_from_payload(obs["identity_key"], ts, payload),
            }
        ]
    # Unknown source: never invent a shape — drop with the caller informed
    # via the export summary (the observation itself stays authoritative).
    return []


def _row_clock_ts(row: Dict[str, Any]) -> float:
    """The source timestamp of an exported scenario row (its cycle clock bound)."""
    if row.get("fix"):
        return float(row["fix"].get("ts") or 0.0)
    payload = row.get("row") or {}
    return float(payload.get("ts_sec") or payload.get("ts") or payload.get("last_time") or 0.0)


def scenario_from_observations(
    store: Any,
    *,
    since_ts: Optional[float] = None,
    until_ts: Optional[float] = None,
    scenario_id: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a v1 scenario document from persisted observations (B6).

    Groups the store's observations by their cycle_id (the live analysis
    cycle that recorded them), one scenario cycle per live cycle with
    ``clock_ts`` at the newest row it contains — the bound a live capture
    held when that cycle ran. Rows are ordered deterministically, so the
    same store content always exports to a byte-identical document.

    Fidelity follows the observation payload whitelist (see the notes at
    the module top of this section): deauth alert and BLE detection data
    survive exactly; probe-SSID text was never persisted. Detection that
    depends on operator-supplied config (trusted APs, protected MACs) must
    be re-supplied via ``config_overrides`` on the exported document.
    """
    params: List[Any] = []
    where = ""
    if since_ts is not None:
        where += " AND ts >= ?"
        params.append(float(since_ts))
    if until_ts is not None:
        where += " AND ts <= ?"
        params.append(float(until_ts))
    rows = store.conn.execute(
        """
        SELECT id, ts, source, kind, identity_key, cycle_id, session_id,
               lat, lon, accuracy_m, payload_json
        FROM observations
        WHERE 1=1"""
        + where
        + " ORDER BY ts, id",
        params,
    ).fetchall()

    sessions = {r["session_id"] for r in rows if r["session_id"]}
    session_id = sorted(sessions)[0] if sessions else "exported"
    cycle_map: Dict[int, List[Dict[str, Any]]] = {}
    row_count = 0
    unmapped = 0
    for r in rows:
        obs_row: Dict[str, Any] = dict(r)
        if r["payload_json"]:
            try:
                obs_row["payload"] = json.loads(r["payload_json"])
            except (ValueError, TypeError):
                obs_row["payload"] = {}
        else:
            obs_row["payload"] = {}
        scenario_rows = _scenario_rows_for_observation(obs_row)
        if not scenario_rows:
            # Unknown source: never invent a shape — the observation stays
            # authoritative, the export just cannot reproduce it.
            unmapped += 1
            continue
        cycle_map.setdefault(int(r["cycle_id"]), []).extend(scenario_rows)
        row_count += len(scenario_rows)

    cycles: List[Dict[str, Any]] = []
    for cycle_id in sorted(cycle_map):
        group = cycle_map[cycle_id]
        clock_ts = max(_row_clock_ts(row) for row in group)
        cycles.append(
            {
                "cycle_id": cycle_id,
                "clock_ts": clock_ts,
                "rows": group,
            }
        )

    description = description or (
        f"Exported from live store session {session_id}: "
        f"{row_count} rows over {len(cycles)} cycles"
    )
    if unmapped:
        description += f"; {unmapped} observation(s) had no replayable shape and were dropped"

    doc: Dict[str, Any] = {
        "scenario_version": REPLAY_SCENARIO_VERSION,
        "scenario_id": scenario_id or f"export-{session_id}",
        "session_id": f"replay-{session_id}",
        "description": description,
        "labels": {},
        "config_overrides": {},
        "cycles": cycles,
    }
    return doc

