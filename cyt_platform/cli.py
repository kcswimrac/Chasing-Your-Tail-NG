"""D10 operator surface: status glance + incident disposition commands.

These commands wrap the incident engine's public API — operators never
write lifecycle rows directly. Errors exit 2 with a plain-language
message; success exits 0 and prints what changed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from cyt_platform.incidents import (
    ACTIVE_STATES,
    IncidentEngine,
    IncidentRef,
    IncidentStatus,
    transition,
)
from cyt_platform.led import read_status
from cyt_platform.status import effective_state
from cyt_platform.store import CytStore

# disposition verb -> terminal lifecycle state the operator asserts
_DISPOSITIONS = {
    "dismiss": IncidentStatus.FALSE_POSITIVE,
    "confirm": IncidentStatus.KNOWN_DEVICE,
    "resolve": IncidentStatus.RESOLVED,
}


class IncidentCliError(Exception):
    """An operator-facing error: printed as a message, exit 2."""


def status_report(config: dict, store: CytStore) -> dict:
    """One glance at the system: status.json state + store counts.

    status.json is authoritative when present (the service wrote it from
    the single status ladder); without it the CLI reports store counts
    and says the state is unknown rather than re-implementing a second
    composition that could drift from the service's.
    """
    status_file = Path(
        (config.get("status") or {}).get("file") or "data/run/status.json"
    )
    snap = read_status(status_file) or {}
    # S11: the CLI displays the effective (staleness-honoring) state, not
    # the raw snapshot state — a dead or parked publisher must not read
    # clear. Empty snapshot (no file) keeps the unknown-state path below.
    if snap:
        state, reason = effective_state(
            snap,
            now=time.time(),
            stale_seconds=float(
                (config.get("status") or {}).get("stale_seconds") or 150
            ),
        )
    else:
        state, reason = None, None
    inputs = store.get_status_inputs(
        float((config.get("status") or {}).get("hold_seconds") or 300)
    )
    active = store.active_phenomenon_incidents()
    return {
        "status_file": str(status_file),
        "state": state,
        "reason": reason,
        "counts": snap.get("counts"),
        "watch_open": inputs.watch_open,
        "alert_open": inputs.alert_open,
        "events_last_hour": inputs.events_last_hour,
        "last_heartbeat_ok": inputs.last_heartbeat_ok,
        "active_incidents": [
            {
                "incident_key": r["incident_key"],
                "lifecycle_state": r["lifecycle_state"],
                "confidence": r["confidence"],
                "severity": r["severity"],
                "last_seen": r["last_seen"],
            }
            for r in active
        ],
    }


def print_status(report: dict) -> None:
    if report["state"] is not None:
        print(f"state: {report['state']} ({report.get('reason')}) [status.json]")
    else:
        print(
            f"state: unknown (no status.json at {report['status_file']} — "
            "service not running?)"
        )
    print(
        f"open incidents: watch={report['watch_open']} alert={report['alert_open']}"
    )
    print(f"active phenomenon incidents: {len(report['active_incidents'])}")
    for inc in report["active_incidents"]:
        print(
            f"  {inc['lifecycle_state'] or '-':9} "
            f"conf={inc['confidence']} {inc['incident_key']}"
        )


def incident_detail(store: CytStore, key: str) -> dict:
    """Full incident row + timeline + contributions, JSON-ready."""
    row = store.get_incident_by_key(key)
    if row is None:
        raise IncidentCliError(f"no incident with key {key}")
    detail = dict(row)
    detail["timeline"] = [
        dict(entry) for entry in store.list_incident_timeline(int(row["id"]))
    ]
    detail["contributions"] = [
        dict(entry) for entry in store.list_incident_contributions(int(row["id"]))
    ]
    return detail


def _incident_ref(store: CytStore, key: str) -> IncidentRef:
    row = store.get_incident_by_key(key)
    if row is None:
        raise IncidentCliError(f"no incident with key {key}")
    state = row["lifecycle_state"]
    if state is None:
        raise IncidentCliError(
            f"incident {key} has no lifecycle row (detector-owned record); "
            "nothing to disposition"
        )
    return IncidentRef(
        incident_id=int(row["id"]),
        incident_key=key,
        lifecycle_state=IncidentStatus(state),
        confidence=float(row["confidence"] or 0.0),
        last_seen=float(row["last_seen"] or 0.0),
        disposition=row["disposition"],
    )


def dispose(store: CytStore, config: dict, key: str, verb: str, reason: str) -> dict:
    """Apply an operator disposition through the incident engine."""
    to_state = _DISPOSITIONS[verb]
    engine = IncidentEngine(store, config)
    plan = engine.dispose(
        key,
        to_state,
        time.time(),
        reason or f"operator:{verb}",
    )
    return {
        "incident_key": key,
        "from": plan.from_state.value,
        "to": plan.to_state.value,
        "reason": plan.reason,
    }


def reopen(store: CytStore, key: str, reason: str) -> dict:
    """Re-open a terminal incident as NEW via the deterministic transition."""
    ref = _incident_ref(store, key)
    if ref.lifecycle_state in ACTIVE_STATES:
        raise IncidentCliError(
            f"incident {key} is {ref.lifecycle_state.value} (active) — reopen "
            "applies to terminal incidents (resolved/false_positive/known_device)"
        )
    plan = transition(ref, IncidentStatus.NEW, reason or "operator:reopen", time.time())
    store.apply_transition(plan)
    return {
        "incident_key": key,
        "from": plan.from_state.value,
        "to": plan.to_state.value,
        "reason": plan.reason,
    }


def print_transition(result: dict) -> None:
    print(f"{result['incident_key']}: {result['from']} -> {result['to']}")
    print(f"  reason: {result['reason']}")


def load_json_result(payload: dict) -> None:
    """Machine-readable stdout for --json consumers."""
    print(json.dumps(payload, indent=2, sort_keys=True))
