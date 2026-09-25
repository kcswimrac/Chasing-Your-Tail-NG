"""D7b evaluation harness: corpus gates, exit codes, label + gates validation.

The harness is the merge gate — its own tests must prove the failure paths,
not just the green path: a deliberately broken gate must exit non-zero
(acceptance criterion 3), a malformed corpus must fail loudly (exit 2), and
restart-equivalence comparison must tolerate detector-internal churn while
catching duplicate filing and history replay.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyt_platform.replay.evaluation import (
    GATES_VERSION,
    GatesError,
    ScenarioVerdict,
    evaluate_gates,
    load_gates,
    run_corpus,
    run_eval,
    validate_labels,
)
from cyt_platform.replay.scenario import scenario_from_dict

REPO = Path(__file__).resolve().parent.parent
SCENARIOS = REPO / "scenarios" / "replay"
GATES = REPO / "eval" / "gates.json"


# --- the green path: the real corpus against the real gates -------------------


def test_full_corpus_is_green_against_calibrated_gates():
    """The shipped corpus (>= 25 scenarios) must pass the shipped gates file.

    This is the calibration contract: gates.json was set from this corpus's
    observed behavior, so a red run here means behavior drifted (a regression
    to review), never a stale gate.
    """
    summary, code = run_eval(SCENARIOS, GATES)
    assert code == 0, json.dumps(summary["gates"], indent=1)
    assert summary["green"] is True
    assert summary["scenarios"] >= 25
    assert summary["harness_errors"] == []
    # Every correctness gate must be at zero — the calibrated knob is only
    # worst_latency_cycles.
    for row in summary["gates"]:
        if row["gate"] not in ("worst_latency_cycles", "corpus_min_scenarios"):
            assert row["observed"] == 0, f"{row['gate']} not calibrated to zero"
    assert summary["worst_latency_cycles"] <= 2


def test_eval_output_is_deterministic(tmp_path):
    """Two full eval runs must produce byte-identical summaries."""
    out_a, out_b = tmp_path / "a.json", tmp_path / "b.json"
    import subprocess
    import sys

    for out in (out_a, out_b):
        result = subprocess.run(
            [sys.executable, "-m", "cyt_platform", "eval",
             "--scenarios", str(SCENARIOS), "--gates", str(GATES),
             "--json-out", str(out)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
    assert out_a.read_bytes() == out_b.read_bytes()


# --- the red paths: gate breaches must exit non-zero --------------------------


def _suspicious_scenario_dict() -> dict:
    path = SCENARIOS / "cooperating-followers-deauth.json"
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_deliberate_false_alert_on_normal_corpus_exits_nonzero(tmp_path):
    """Relabel a follower scenario as normal traffic: the corpus now contains
    a false alert and `run_eval` must exit 1 — the acceptance test for the
    non-zero exit contract."""
    doc = _suspicious_scenario_dict()
    doc["labels"] = {
        "kind": "normal",
        "expect": {"detect": False, "state": "clear"},
    }
    doc["scenario_id"] = "broken-false-alert"
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    (scenarios / "broken-false-alert.json").write_text(json.dumps(doc))

    summary, code = run_eval(scenarios, GATES)
    assert code == 1
    assert summary["green"] is False
    rows = {r["gate"]: r for r in summary["gates"]}
    assert rows["false_alert_scenarios"]["observed"] == 1
    assert rows["false_incident_scenarios"]["observed"] == 1
    assert rows["label_violations"]["observed"] == 1


def test_deliberate_silent_miss_exits_nonzero(tmp_path):
    """Raise a suspicious scenario's latency label below observed behavior:
    the latency gate must breach and the run must exit 1."""
    doc = _suspicious_scenario_dict()
    doc["labels"]["expect"]["max_latency_cycles"] = 1
    doc["scenario_id"] = "broken-latency"
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    (scenarios / "broken-latency.json").write_text(json.dumps(doc))

    summary, code = run_eval(scenarios, GATES)
    # The relabeled scenario detects at cycle 2 > the label's 1: a latency
    # breach is a label violation and must fail the run.
    assert code == 1
    assert summary["green"] is False


def test_malformed_scenario_fails_loudly_with_exit_two(tmp_path):
    """An unreadable scenario is a harness error (exit 2), never a green run."""
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    (scenarios / "not-json.json").write_text("{definitely not json")

    summary, code = run_eval(scenarios, GATES)
    assert code == 2
    assert summary["green"] is False
    assert summary["harness_errors"]


# --- gates document validation ------------------------------------------------


def _write_gates(tmp_path, **overrides):
    base = {
        "gate_version": GATES_VERSION,
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
        "worst_latency_cycles": 2,
    }
    base.update(overrides)
    path = tmp_path / "gates.json"
    path.write_text(json.dumps(base))
    return path


def test_gates_reject_unknown_keys(tmp_path):
    path = _write_gates(tmp_path, Totally_Made_Up_Gate=1)
    with pytest.raises(GatesError, match="unknown gates keys"):
        load_gates(path)


def test_gates_reject_missing_keys(tmp_path):
    path = _write_gates(tmp_path)
    doc = json.loads(path.read_text())
    del doc["missed_scenarios"]
    path.write_text(json.dumps(doc))
    with pytest.raises(GatesError, match="missing gates keys"):
        load_gates(path)


def test_gates_reject_stale_version(tmp_path):
    path = _write_gates(tmp_path, gate_version=GATES_VERSION + 1)
    with pytest.raises(GatesError, match="gate_version"):
        load_gates(path)


def test_gates_reject_non_integer_thresholds(tmp_path):
    path = _write_gates(tmp_path, missed_scenarios="0")
    with pytest.raises(GatesError, match="must be an integer"):
        load_gates(path)


def test_gates_reject_negative_thresholds(tmp_path):
    path = _write_gates(tmp_path, missed_scenarios=-1)
    with pytest.raises(GatesError, match="must be >= 0"):
        load_gates(path)


def test_gates_reject_zero_latency_budget(tmp_path):
    path = _write_gates(tmp_path, worst_latency_cycles=0)
    with pytest.raises(GatesError, match="worst_latency_cycles"):
        load_gates(path)


# --- label validation ---------------------------------------------------------


def _label_doc(expect: dict, cycles: int = 3, kind: str = "suspicious") -> object:
    return scenario_from_dict(
        {
            "scenario_version": 1,
            "scenario_id": "label-probe",
            "session_id": "replay-label-probe",
            "labels": {"kind": kind, "expect": expect},
            "cycles": [
                {"cycle_id": i + 1, "clock_ts": 1700000000.0 + 60 * i, "rows": []}
                for i in range(cycles)
            ],
        }
    )


def test_detect_true_requires_max_latency_cycles():
    problems = validate_labels(_label_doc({"detect": True, "state": "watch"}))
    assert any("max_latency_cycles" in p for p in problems)


def test_normal_scenario_cannot_label_detect_true():
    problems = validate_labels(
        _label_doc({"detect": True, "state": "alert"}, kind="normal")
    )
    assert any("normal" in p for p in problems)


def test_detect_false_rejects_detection_fields():
    problems = validate_labels(
        _label_doc(
            {"detect": False, "state": "clear", "max_latency_cycles": 2}
        )
    )
    assert any("max_latency_cycles" in p for p in problems)


def test_scenario_needs_two_cycles_for_restart_injection():
    problems = validate_labels(
        _label_doc({"detect": False, "state": "clear"}, cycles=1)
    )
    assert any("restart" in p for p in problems)


# --- restart equivalence comparison -------------------------------------------


def _verdict(**overrides):
    base = {
        "scenario_id": "probe",
        "kind": "suspicious",
        "expect": {"detect": True, "state": "watch"},
        "final_state": "watch",
        "latency_cycles": 2,
        "incident_count": 1,
        "entity_keys": ("AA:BB:CC:00:00:01",),
        "determinism_ok": True,
        "restart_ok": True,
        "render_ok": True,
        "violations": (),
    }
    base.update(overrides)
    return ScenarioVerdict(**base)


def test_corpus_floor_is_a_minimum_not_a_maximum():
    """One scenario against a >=25 floor must breach the corpus gate even
    though every max-gate is at zero (regression: the floor compared as a
    maximum and 32 > 25 read as a breach while 1 < 25 passed)."""
    thresholds, _ = load_gates(GATES)
    summary = evaluate_gates([_verdict()], [], thresholds)
    assert summary["green"] is False
    rows = {r["gate"]: r for r in summary["gates"]}
    assert rows["corpus_min_scenarios"]["observed"] == 1
    assert rows["corpus_min_scenarios"]["allowed"] >= 25


def test_restart_churn_tolerates_last_seen_but_not_duplicates():
    """The deauth analyzer re-observes its open attack from in-memory event
    accumulation; a restart starts from a cold event list, so last_seen and
    observation_count legitimately lag. Identity (key, first_seen, status,
    severity, entity) must not change."""
    from cyt_platform.replay.evaluation import _compare_runs

    def row(last_seen, count):
        return {
            "incident_key": "deauth_attack|AA|deauth|s",
            "first_seen": 1699999997.0,
            "last_seen": last_seen,
            "observation_count": count,
            "status": "open",
            "severity": "watch",
            "entity_type": "wifi_mac",
            "entity_key": "AA:BB:CC:00:00:01",
        }

    single = {
        "incidents": [row(1700000052.0, 4)],
        "events": [{"event_type": "incident_opened", "ts": 1699999997.0}],
    }
    restarted = {
        "incidents": [row(1699999997.0, 2)],
        "events": [{"event_type": "incident_opened", "ts": 1699999997.0}],
    }
    assert _compare_runs(single, restarted) == []

    duplicate = {
        "incidents": [row(1700000052.0, 4), dict(row(1700000052.0, 1))],
        "events": single["events"],
    }
    assert _compare_runs(single, duplicate)  # duplicate filing is a breach


def test_restart_history_replay_is_a_breach():
    from cyt_platform.replay.evaluation import _compare_runs

    def row(first_seen, last_seen, count):
        return {
            "incident_key": "deauth_attack|AA|deauth|s",
            "first_seen": first_seen,
            "last_seen": last_seen,
            "observation_count": count,
            "status": "open",
            "severity": "watch",
            "entity_type": "wifi_mac",
            "entity_key": "AA:BB:CC:00:00:01",
        }

    single = {
        "incidents": [row(1699999997.0, 1700000052.0, 4)],
        "events": [{"event_type": "incident_opened", "ts": 1699999997.0}],
    }
    replayed = {
        # Restart re-filed history: earlier first_seen, new event row.
        "incidents": [row(1699999990.0, 1700000052.0, 6)],
        "events": [
            {"event_type": "incident_opened", "ts": 1699999990.0},
            {"event_type": "incident_opened", "ts": 1699999997.0},
        ],
    }
    problems = _compare_runs(single, replayed)
    assert any("identity/state differs" in p for p in problems)
    assert any("event stream" in p for p in problems)


# --- observed entity keys are the subject SET ---------------------------------


def test_entity_keys_compare_as_a_set():
    """Two incidents on one subject must still match a single labeled entity
    (regression: per-incident duplication made every multi-incident subject
    mismatch its label)."""
    thresholds, _ = load_gates(GATES)
    verdict = _verdict(
        incident_count=2,
        entity_keys=("AA:BB:CC:00:00:01",),
        expect={
            "detect": True,
            "state": "watch",
            "entity_keys": ["AA:BB:CC:00:00:01"],
        },
        violations=(),
    )
    summary = evaluate_gates([verdict], [], thresholds)
    rows = {r["gate"]: r for r in summary["gates"]}
    assert rows["entity_mismatch_scenarios"]["observed"] == 0


# --- the shipped corpus itself -------------------------------------------------


def test_shipped_corpus_runs_without_harness_errors():
    verdicts, errors, _ = run_corpus(SCENARIOS)
    assert errors == []
    assert len(verdicts) >= 25
    kinds = {v.kind for v in verdicts}
    assert kinds == {"normal", "suspicious", "edge"}


def test_shipped_corpus_covers_the_product_promises():
    """The corpus must contain both halves of the promise: normal scenarios
    that stay clear (false-alert protection) and suspicious ones that detect
    within labeled latency (silent-miss protection)."""
    verdicts, _, _ = run_corpus(SCENARIOS)
    normal = [v for v in verdicts if v.kind == "normal"]
    suspicious = [v for v in verdicts if v.kind == "suspicious"]
    assert normal and suspicious
    assert all(v.final_state == "clear" for v in normal)
    assert all(v.latency_cycles is not None for v in suspicious)
