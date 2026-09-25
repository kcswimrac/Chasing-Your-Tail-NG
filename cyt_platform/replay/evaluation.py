"""Corpus evaluation: run every labeled replay scenario and judge the gates.

The eval harness is the D7 regression instrument. It runs the whole labeled
corpus under ``scenarios/replay/`` through the production replay engine and
compares observed behavior against two things:

* per-scenario ``labels.expect`` blocks (detect/state/latency/incidents), and
* the calibrated aggregate thresholds in ``eval/gates.json``.

Zero-tolerance gates encode product promises from the build spec (no false
alerts on normal air, no silent misses on follower patterns, deterministic
output, restart equivalence, inert rendering of display fields). The single
calibrated knob is ``worst_latency_cycles`` — the corpus-wide slowest allowed
first-detection cycle — set from the initial corpus run (locked risk (e): no
permanently-red CI). Thresholds calibrate away variance; they never excuse a
product regression, and a red gate is a broken merge gate, not a waived one.

Exit codes (``cyt eval`` / ``python -m cyt_platform eval``):
    0  all gates green
    1  gate breach (behavior or threshold regression)
    2  harness error (unreadable corpus, malformed gates file)

Known finding carried by the corpus (not hidden by thresholds): raw SSID text
reaches *evidence* surfaces — event ``detail.reasons`` in replay reports and
``status.json`` incident evidence. Redaction (``privacy.redact_subject``) is a
detector-contract fix outside the corpus scope. The render gate below covers
the *display* fields only (summaries, entity keys, window labels): those must
stay SSID-free even under hostile-SSID input.
"""

from __future__ import annotations

import json
import math
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cyt_platform.replay.engine import ReplayEngine
from cyt_platform.replay.report import report_bytes
from cyt_platform.replay.scenario import (
    ScenarioDocument,
    ScenarioError,
    scenario_from_dict,
)

GATES_VERSION = 1
CORPUS_MIN_SCENARIOS = 25

# States that count as "detected" when measuring first-detection latency.
_DETECTED_STATES = frozenset({"watch", "alert"})

# Display fields of a report row — the surfaces a status glance or report
# renderer interpolates. Event/observation *detail* is deliberately excluded
# (raw-SSID evidence redaction is an open, separately-tracked detector fix).
_INCIDENT_DISPLAY_FIELDS = (
    "incident_key",
    "event_type",
    "severity",
    "status",
    "window_label",
    "entity_type",
    "entity_key",
)
_EVENT_DISPLAY_FIELDS = ("event_type", "severity", "summary")


class GatesError(ValueError):
    """Raised for malformed or structurally invalid gates files."""


@dataclass(frozen=True)
class Thresholds:
    """Aggregate gates over the corpus (eval/gates.json).

    Every field is a maximum allowed count of breaching scenarios;
    ``worst_latency_cycles`` is the maximum allowed slowest first-detection
    cycle across the suspicious corpus. All are calibrated from the initial
    corpus run — see the PR's calibration table.
    """

    false_alert_scenarios: int
    false_incident_scenarios: int
    missed_scenarios: int
    latency_breaches: int
    state_mismatch_scenarios: int
    entity_mismatch_scenarios: int
    excess_incident_scenarios: int
    determinism_breaches: int
    restart_breaches: int
    raw_render_breaches: int
    label_violations: int
    worst_latency_cycles: int


@dataclass(frozen=True)
class ScenarioVerdict:
    """Observed behavior of one scenario plus any label/gate violations."""

    scenario_id: str
    kind: str
    expect: Dict[str, Any]
    final_state: str
    latency_cycles: Optional[int]
    incident_count: int
    entity_keys: Tuple[str, ...]
    determinism_ok: bool
    restart_ok: bool
    render_ok: bool
    violations: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "kind": self.kind,
            "final_state": self.final_state,
            "latency_cycles": self.latency_cycles,
            "incident_count": self.incident_count,
            "entity_keys": list(self.entity_keys),
            "determinism_ok": self.determinism_ok,
            "restart_ok": self.restart_ok,
            "render_ok": self.render_ok,
            "violations": list(self.violations),
        }


def load_gates(path: Any) -> Tuple[Thresholds, Dict[str, Any]]:
    """Parse and strictly validate an eval/gates.json document.

    Unknown keys, missing keys, non-integer values, negative counts, a stale
    ``gate_version``, or a corpus floor below ``CORPUS_MIN_SCENARIOS`` all
    raise ``GatesError`` — a silently-ignored typo in a gates file must never
    read as a green run.
    """
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise GatesError("gates document must be a JSON object")
    version = doc.get("gate_version")
    if version != GATES_VERSION:
        raise GatesError(
            f"gate_version must be {GATES_VERSION}, got {version!r}"
        )
    threshold_fields = {f.name for f in Thresholds.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    keys = set(doc.keys()) - {"gate_version", "notes"}
    unknown = keys - threshold_fields
    if unknown:
        raise GatesError(f"unknown gates keys: {sorted(unknown)}")
    missing = threshold_fields - keys
    if missing:
        raise GatesError(f"missing gates keys: {sorted(missing)}")
    values: Dict[str, int] = {}
    for name in sorted(threshold_fields):
        value = doc[name]
        if not isinstance(value, int) or isinstance(value, bool):
            raise GatesError(f"gate {name} must be an integer, got {value!r}")
        if value < 0:
            raise GatesError(f"gate {name} must be >= 0, got {value}")
        values[name] = value
    if values["worst_latency_cycles"] < 1:
        raise GatesError("worst_latency_cycles must be >= 1")
    return Thresholds(**values), doc


def validate_labels(doc: ScenarioDocument) -> Tuple[str, ...]:
    """Check a scenario's labels block against the corpus schema.

    Returns every violation (empty tuple = well-labeled). detect=true labels
    must carry max_latency_cycles; detect=false labels must not carry
    detection-side fields; every scenario needs at least two cycles so the
    restart-equivalence injection has somewhere to restart.
    """
    problems: List[str] = []
    labels = doc.labels
    if not isinstance(labels, dict) or not labels:
        return ("labels block missing or empty",)
    kind = labels.get("kind")
    if kind not in ("normal", "suspicious", "edge"):
        problems.append(f"labels.kind must be normal|suspicious|edge, got {kind!r}")
    expect = labels.get("expect")
    if not isinstance(expect, dict):
        problems.append("labels.expect must be an object")
        return tuple(problems)
    detect = expect.get("detect")
    if not isinstance(detect, bool):
        problems.append(f"expect.detect must be a boolean, got {detect!r}")
        return tuple(problems)

    state = expect.get("state")
    if detect:
        if state not in ("watch", "alert", "degraded"):
            problems.append(
                f"detect=true expects state watch|alert|degraded, got {state!r}"
            )
        latency = expect.get("max_latency_cycles")
        if not isinstance(latency, int) or isinstance(latency, bool) or latency < 1:
            problems.append(
                f"detect=true requires max_latency_cycles >= 1, got {latency!r}"
            )
    else:
        if state not in ("clear", "degraded"):
            problems.append(
                f"detect=false expects state clear|degraded, got {state!r}"
            )
        for forbidden in ("max_latency_cycles", "entity_keys", "max_incidents"):
            if forbidden in expect:
                problems.append(f"detect=false must not set {forbidden}")

    if kind == "normal" and detect:
        problems.append("normal scenarios must label expect.detect=false")
    if kind == "suspicious" and not detect:
        problems.append("suspicious scenarios must label expect.detect=true")

    entity_keys = expect.get("entity_keys")
    if entity_keys is not None:
        if (
            not isinstance(entity_keys, list)
            or not entity_keys
            or not all(isinstance(k, str) and k for k in entity_keys)
        ):
            problems.append("expect.entity_keys must be a non-empty list of strings")
    max_incidents = expect.get("max_incidents")
    if max_incidents is not None:
        if not isinstance(max_incidents, int) or isinstance(max_incidents, bool) \
                or max_incidents < 1:
            problems.append("expect.max_incidents must be a positive integer")
    raw = expect.get("no_raw_strings")
    if raw is not None:
        if not isinstance(raw, list) or not raw or not all(
            isinstance(s, str) and s for s in raw
        ):
            problems.append("expect.no_raw_strings must be a non-empty list of strings")

    if len(doc.cycles) < 2:
        problems.append(
            f"scenario needs >= 2 cycles for restart-equivalence injection, "
            f"got {len(doc.cycles)}"
        )
    return tuple(problems)


def _first_detection_cycle(summaries: List[Dict[str, Any]]) -> Optional[int]:
    """1-based position of the first cycle whose state is watch/alert."""
    for idx, summary in enumerate(summaries, start=1):
        if summary.get("state") in _DETECTED_STATES:
            return idx
    return None


def _compare_runs(single: Dict[str, Any], other: Dict[str, Any]) -> List[str]:
    """Restart equivalence: incident identity/state and the full event stream
    must match a single-pass run exactly.

    Tolerated churn — ``observation_count`` and ``last_seen`` — covers
    detector-internal volatile memory: the deauth analyzer accumulates events
    in memory and re-observes its open attack each cycle, while a restart
    starts from a cold event list (watermarks keep processed history from
    replaying, so re-observation resumes only at the attack rate). Fewer
    re-observations after a restart is that documented behavior, not drift.
    A different incident KEY (duplicate filing), first_seen (history replay),
    status/severity (state drift), or a changed event stream is a breach.
    """
    problems: List[str] = []

    def identity_view(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            {
                k: row.get(k)
                for k in (
                    "incident_key",
                    "first_seen",
                    "status",
                    "severity",
                    "entity_type",
                    "entity_key",
                )
            }
            for row in incidents
        ]

    if identity_view(single["incidents"]) != identity_view(other["incidents"]):
        problems.append(
            "restart run incident identity/state differs from single-pass "
            "(observation_count/last_seen churn is tolerated; keys, first_seen, "
            "status, and severity are not)"
        )
    if single["events"] != other["events"]:
        problems.append("restart run event stream differs from single-pass")
    return problems


def _display_render_breaches(
    report: Dict[str, Any], needles: List[str]
) -> List[str]:
    """Hostile-text scan over the display fields of incidents and events."""
    hits: List[str] = []
    for incident in report["incidents"]:
        for field in _INCIDENT_DISPLAY_FIELDS:
            value = incident.get(field)
            if not isinstance(value, str):
                continue
            for needle in needles:
                if needle in value:
                    hits.append(
                        f"incident {incident.get('incident_key')!r} "
                        f"{field} carries raw text {needle!r}"
                    )
    for event in report["events"]:
        for field in _EVENT_DISPLAY_FIELDS:
            value = event.get(field)
            if not isinstance(value, str):
                continue
            for needle in needles:
                if needle in value:
                    hits.append(
                        f"event {event.get('event_type')!r} "
                        f"{field} carries raw text {needle!r}"
                    )
    return hits


def _evaluate_scenario(
    name: str, doc: ScenarioDocument
) -> Tuple[ScenarioVerdict, List[str]]:
    """Run one scenario (single-pass + determinism + restart) and judge its
    labels. Returns the verdict and non-label behavioral problems."""
    expect = doc.labels["expect"]
    problems: List[str] = []

    engine = ReplayEngine(doc)
    report = engine.run(restarts=[])
    single_bytes = report_bytes(report)

    rerun = ReplayEngine(doc).run(restarts=[])
    determinism_ok = report_bytes(rerun) == single_bytes
    if not determinism_ok:
        problems.append("second single-pass run is not byte-identical")

    declared = list(doc.restarts)
    points = declared or [math.floor(len(doc.cycles) / 2)]
    restart_report = ReplayEngine(doc).run(restarts=points)
    restart_ok = not _compare_runs(report, restart_report)
    if not restart_ok:
        problems.extend(_compare_runs(report, restart_report))

    needles = [s for s in (expect.get("no_raw_strings") or [])]
    render_hits = _display_render_breaches(report, needles) if needles else []
    render_ok = not render_hits
    problems.extend(render_hits)

    incidents = report["incidents"]
    # Labels express the SET of incident subjects (a subject with several
    # incidents is still one labeled entity).
    entity_keys = tuple(
        sorted({str(i["entity_key"]) for i in incidents if i.get("entity_key")})
    )
    latency = _first_detection_cycle(report["cycles"])

    violations = list(problems)

    if expect["detect"]:
        if not incidents:
            violations.append("expect.detect=true but no incident was filed")
        if latency is None:
            violations.append("expect.detect=true but no cycle reached watch/alert")
        else:
            max_latency = expect.get("max_latency_cycles")
            if isinstance(max_latency, int) and latency > max_latency:
                violations.append(
                    f"detected at cycle {latency}, label allows {max_latency}"
                )
    else:
        if incidents:
            violations.append(
                f"expect.detect=false but {len(incidents)} incident(s) filed"
            )

    labeled_state = expect.get("state")
    final_state = report["cycles"][-1]["state"] if report["cycles"] else "unknown"
    if labeled_state is not None and final_state != labeled_state:
        violations.append(
            f"final state {final_state!r} != labeled {labeled_state!r}"
        )

    labeled_entities = expect.get("entity_keys")
    if labeled_entities is not None:
        if sorted(labeled_entities) != list(entity_keys):
            violations.append(
                f"entities {list(entity_keys)} != labeled {labeled_entities}"
            )

    max_incidents = expect.get("max_incidents")
    if max_incidents is not None and len(incidents) > max_incidents:
        violations.append(
            f"{len(incidents)} incidents filed, label allows {max_incidents}"
        )

    verdict = ScenarioVerdict(
        scenario_id=doc.scenario_id or name,
        kind=doc.labels.get("kind", "unknown"),
        expect=expect,
        final_state=final_state,
        latency_cycles=latency,
        incident_count=len(incidents),
        entity_keys=entity_keys,
        determinism_ok=determinism_ok,
        restart_ok=restart_ok,
        render_ok=render_ok,
        violations=tuple(violations),
    )
    return verdict, []


def run_corpus(
    scenarios_dir: Any,
) -> Tuple[List[ScenarioVerdict], List[str], List[str]]:
    """Run every scenario under the directory; return verdicts plus harness
    errors (unreadable/malformed scenarios that must fail the run loudly).
    """
    directory = pathlib.Path(scenarios_dir)
    errors: List[str] = []
    verdicts: List[ScenarioVerdict] = []
    if not directory.is_dir():
        return [], [f"scenarios directory not found: {directory}"], []
    for path in sorted(directory.glob("*.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            doc = scenario_from_dict(raw)
        except (ScenarioError, json.JSONDecodeError, OSError) as exc:
            errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        try:
            verdict, scenario_errors = _evaluate_scenario(path.name, doc)
        except Exception as exc:  # noqa: BLE001 - one broken scenario must
            # surface as a harness error, not kill the whole corpus run.
            errors.append(
                f"{path.name}: engine raised {type(exc).__name__}: {exc}"
            )
            continue
        verdicts.append(verdict)
        errors.extend(f"{path.name}: {e}" for e in scenario_errors)
    return verdicts, errors, []


def evaluate_gates(
    verdicts: List[ScenarioVerdict],
    harness_errors: List[str],
    thresholds: Thresholds,
) -> Dict[str, Any]:
    """Aggregate verdicts into gate rows. Pure: no I/O, deterministic."""
    observed: Dict[str, int] = {
        "false_alert_scenarios": 0,
        "false_incident_scenarios": 0,
        "missed_scenarios": 0,
        "latency_breaches": 0,
        "state_mismatch_scenarios": 0,
        "entity_mismatch_scenarios": 0,
        "excess_incident_scenarios": 0,
        "determinism_breaches": 0,
        "restart_breaches": 0,
        "raw_render_breaches": 0,
        "label_violations": 0,
    }
    worst_latency = 0
    for verdict in verdicts:
        expect = verdict.expect
        detect = expect.get("detect") is True
        labeled_state = expect.get("state")
        if not detect:
            if verdict.final_state in _DETECTED_STATES:
                observed["false_alert_scenarios"] += 1
            if verdict.incident_count > 0:
                observed["false_incident_scenarios"] += 1
        else:
            if verdict.latency_cycles is None:
                observed["missed_scenarios"] += 1
            elif verdict.latency_cycles > worst_latency:
                worst_latency = verdict.latency_cycles
            max_latency = expect.get("max_latency_cycles")
            if (
                isinstance(max_latency, int)
                and verdict.latency_cycles is not None
                and verdict.latency_cycles > max_latency
            ):
                observed["latency_breaches"] += 1
        if (
            labeled_state is not None
            and verdict.final_state != labeled_state
        ):
            observed["state_mismatch_scenarios"] += 1
        labeled_entities = expect.get("entity_keys")
        if labeled_entities is not None:
            if sorted(labeled_entities) != list(verdict.entity_keys):
                observed["entity_mismatch_scenarios"] += 1
        max_incidents = expect.get("max_incidents")
        if (
            max_incidents is not None
            and verdict.incident_count > max_incidents
        ):
            observed["excess_incident_scenarios"] += 1
        if not verdict.determinism_ok:
            observed["determinism_breaches"] += 1
        if not verdict.restart_ok:
            observed["restart_breaches"] += 1
        if not verdict.render_ok:
            observed["raw_render_breaches"] += 1
        if verdict.violations:
            observed["label_violations"] += 1

    gate_rows = [
        {"gate": name, "observed": observed[name],
         "allowed": getattr(thresholds, name)}
        for name in sorted(observed)
    ]
    corpus_row = {
        "gate": "corpus_min_scenarios", "observed": len(verdicts),
        "allowed": CORPUS_MIN_SCENARIOS,
    }
    # Max-gates count breaches (observed must be <= allowed); the corpus
    # floor is the one minimum (observed must be >= allowed).
    corpus_ok = len(verdicts) >= CORPUS_MIN_SCENARIOS
    max_gates_ok = all(
        r["observed"] <= r["allowed"] for r in gate_rows
    )
    green = max_gates_ok and corpus_ok and not harness_errors
    by_kind: Dict[str, int] = {}
    for verdict in verdicts:
        by_kind[verdict.kind] = by_kind.get(verdict.kind, 0) + 1

    return {
        "gate_version": GATES_VERSION,
        "green": green,
        "scenarios": len(verdicts),
        "by_kind": by_kind,
        "worst_latency_cycles": worst_latency,
        "gates": gate_rows + [corpus_row],
        "verdicts": [v.as_dict() for v in verdicts],
        "harness_errors": harness_errors,
    }


def run_eval(
    scenarios_dir: Any, gates_path: Any
) -> Tuple[Dict[str, Any], int]:
    """Full evaluation: corpus run + gates judgment + exit code."""
    try:
        thresholds, gates_doc = load_gates(gates_path)
    except (GatesError, json.JSONDecodeError, OSError) as exc:
        return (
            {
                "gate_version": GATES_VERSION,
                "green": False,
                "error": f"gates file error: {type(exc).__name__}: {exc}",
            },
            2,
        )
    verdicts, harness_errors, _ = run_corpus(scenarios_dir)
    summary = evaluate_gates(verdicts, harness_errors, thresholds)
    summary["gates_file"] = {
        "notes": gates_doc.get("notes"),
        "worst_latency_cycles": thresholds.worst_latency_cycles,
    }
    if harness_errors:
        return summary, 2
    return summary, (0 if summary["green"] else 1)
