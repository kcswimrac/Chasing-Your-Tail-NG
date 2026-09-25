"""Deterministic replay report builder (D7a).

The report is the replay's entire observable output: final incident state,
the full event audit trail, per-cycle detection summaries, and an
observation summary. Byte-identity of this document across two runs of the
same scenario is the determinism gate, so:

- incidents/events are read with stable ORDER BY and serialized with
  ``sort_keys=True`` (content-sorted; no sqlite rowids, no wall-clock
  fields, no uuids, no pids);
- ``recorded_ts`` (the wall-clock insert time of an observation) is
  deliberately excluded: it is operational metadata by D1 design, not
  evidence. Evidence time is the source-corrected ``ts``;
- incident and event rows are fetched with read-only SQL because no
  incident/event read API exists on CytStore yet (a read API is D2
  scope). The queries never write.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from cyt_platform.privacy import redact_evidence_object, redact_evidence_text
from cyt_platform.replay.scenario import ScenarioDocument

REPLAY_REPORT_VERSION = 1

# Upper bound on observations summarized in the report; scenario sessions are
# small. Matches the CytStore.query_observations maximum.
_OBS_LIMIT = 5000


def _fetch_incidents(store: Any) -> List[Dict[str, Any]]:
    rows = store.conn.execute(
        """
        SELECT i.incident_key, i.event_type, i.severity, i.status,
               i.window_label, i.session_id, i.first_seen, i.last_seen,
               i.observation_count, COALESCE(i.suppressed, 0) AS suppressed,
               e.entity_type, e.key AS entity_key
        FROM incidents i JOIN entities e ON e.id = i.entity_id
        ORDER BY i.incident_key
        """
    ).fetchall()
    return [dict(r) for r in rows]


def _fetch_events(store: Any) -> List[Dict[str, Any]]:
    rows = store.conn.execute(
        """
        SELECT ts, event_type, severity, summary, session_id, detail_json
        FROM events
        ORDER BY ts, event_type, summary, severity
        """
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        detail_json = d.pop("detail_json", None)
        if detail_json:
            try:
                d["detail"] = json.loads(detail_json)
            except json.JSONDecodeError:
                d["detail"] = None
        else:
            d["detail"] = None
        # D9: the report is a shareable artifact and the replay's entire
        # observable output — event summaries and detail (alert reasons,
        # device names can carry hostile SSID text) are redacted at this
        # boundary. Redaction is pure/deterministic, so byte-identity of
        # the report across runs is preserved.
        d["summary"] = redact_evidence_text(d.get("summary") or "")
        d["detail"] = redact_evidence_object(d.get("detail"))
        out.append(d)
    return out


def build_report(
    scenario: ScenarioDocument,
    store: Any,
    cycle_summaries: List[Dict[str, Any]],
    restarts: List[int],
) -> Dict[str, Any]:
    """Assemble the deterministic report from the replayed store."""
    observations = store.query_observations(limit=_OBS_LIMIT)
    by_kind: Dict[str, int] = {}
    for o in observations:
        by_kind[o["kind"]] = by_kind.get(o["kind"], 0) + 1

    incidents = sorted(
        _fetch_incidents(store), key=lambda i: str(i["incident_key"])
    )
    events = sorted(
        _fetch_events(store),
        key=lambda e: (e["ts"], e["event_type"], e["summary"], e["severity"]),
    )

    return {
        "replay_version": REPLAY_REPORT_VERSION,
        "scenario_id": scenario.scenario_id,
        "session_id": scenario.session_id,
        "description": scenario.description,
        "labels": scenario.labels,
        "restarts": list(restarts),
        "cycles": cycle_summaries,
        "observations": {
            "total": len(observations),
            "by_kind": {k: by_kind[k] for k in sorted(by_kind)},
        },
        "incidents": incidents,
        "events": events,
    }


def report_bytes(report: Dict[str, Any]) -> bytes:
    """Canonical byte serialization (the determinism contract)."""
    text = json.dumps(report, sort_keys=True, separators=(",", ":"))
    return (text + "\n").encode("utf-8")