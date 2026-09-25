"""D7a replay engine: scenario format, determinism, restart equivalence."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cyt_platform.replay.engine import ReplayEngine
from cyt_platform.replay.report import report_bytes
from cyt_platform.replay.scenario import ScenarioError, load_scenario

REPO = Path(__file__).resolve().parent.parent
SCENARIOS = REPO / "scenarios" / "replay"


def run_scenario(path: Path, tmp_path: Path, **kwargs):
    """Run a scenario file through the replay engine (store under tmp_path)."""
    scenario = load_scenario(str(path))
    engine = ReplayEngine(scenario, store_path=tmp_path / "cyt.db")
    return engine.run(**kwargs)


def incident_views(report: dict) -> list:
    """Final incident rows with the in-memory observation counter excluded
    (documented artifact: deauth events accumulate in memory between
    restarts; D2's session-independent incident keys retire the artifact)."""
    return [
        {k: v for k, v in inc.items() if k != "observation_count"}
        for inc in report["incidents"]
    ]


# --- determinism ---------------------------------------------------------------


def test_replay_is_byte_identical_within_process(tmp_path):
    path = SCENARIOS / "cafe-evil-twin.json"
    run_a = run_scenario(path, tmp_path / "a")
    run_b = run_scenario(path, tmp_path / "b")
    assert report_bytes(run_a) == report_bytes(run_b)


def test_replay_is_byte_identical_across_processes(tmp_path):
    """Same input + scenario clock -> identical output under different hash
    seeds (PYTHONHASHSEED affects set iteration order; the report must not
    leak it). Exercises the `replay` CLI end to end."""
    path = SCENARIOS / "cafe-evil-twin.json"
    outs = []
    envs = [{"PYTHONHASHSEED": "1"}, {"PYTHONHASHSEED": "99"}]
    for i, env in enumerate(envs):
        out_file = tmp_path / f"out-{i}.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cyt_platform",
                "replay",
                "--session",
                str(path),
                "--store-path",
                str(tmp_path / f"store-{i}"),
                "--json-out",
                str(out_file),
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO),
            env={**env},
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        outs.append(out_file.read_bytes())
    assert outs[0] == outs[1]
    report = json.loads(outs[0])
    assert report["scenario_id"] == "cafe-evil-twin"
    assert report["restarts"] == [2]


def test_quiet_scenario_reports_no_incidents(tmp_path):
    report = run_scenario(SCENARIOS / "commute-quiet.json", tmp_path)
    assert report["incidents"] == []
    assert report["observations"]["total"] > 0
    assert report["observations"]["by_kind"].get("deauth_alert") is None
    assert report["labels"]["expect"]["detect"] is False


def test_scenario_clock_drives_detection_not_wall_clock(tmp_path):
    """Detection must run on scenario time: the fixture's alerts are dated
    ~2023 (epoch 1.7e9), far outside any wall-clock catch-up window, so any
    residual wall-clock read would miss them entirely."""
    report = run_scenario(SCENARIOS / "commute-deauth-burst.json", tmp_path)
    assert len(report["incidents"]) == 1
    incident = report["incidents"][0]
    assert incident["event_type"] == "deauth_attack"
    assert incident["severity"] == "watch"
    # Evidence time is the alert timestamp, not a wall clock.
    assert incident["first_seen"] == pytest.approx(1699999994.0)
    assert incident["last_seen"] == pytest.approx(1699999997.0)
    assert incident["session_id"] == "replay-commute-deauth-burst"


def test_observations_carry_provenance(tmp_path):
    report = run_scenario(SCENARIOS / "commute-quiet.json", tmp_path)
    assert report["observations"]["by_kind"].get("wifi_device", 0) == 3
    assert report["observations"]["by_kind"].get("gps_fix", 0) == 2
    # Provenance refs are scenario-derived (stable), not path/uuid-derived.
    assert all(
        inc["session_id"] == "replay-commute-quiet"
        for inc in report["incidents"]
    )


# --- restart equivalence --------------------------------------------------------


def test_restart_equivalence_events_and_status(tmp_path):
    """Injecting a service restart mid-scenario must not change final incident
    state: events, severity, first/last seen identical; only the in-memory
    observation counter may differ (documented artifact)."""
    path = SCENARIOS / "commute-deauth-burst.json"
    full = run_scenario(path, tmp_path / "full", restarts=[])
    with_restart = run_scenario(path, tmp_path / "restart")  # declared [3]
    assert incident_views(full) == incident_views(with_restart)
    assert full["events"] == with_restart["events"]
    assert full["incidents"][0]["status"] == "open"


def test_declared_restart_matches_injected_restart(tmp_path):
    """Scenario-level `restarts: [3]` and run(restarts=[3]) are the same
    replay."""
    path = SCENARIOS / "commute-deauth-burst.json"
    declared = run_scenario(path, tmp_path / "declared")
    injected = run_scenario(path, tmp_path / "injected", restarts=[3])
    assert report_bytes(declared) == report_bytes(injected)


def test_rogue_alert_does_not_refile_after_restart(tmp_path):
    """Re-observations of a rogue AP after a restart must not duplicate the
    incident: the pre-restart row is suppressed by the persisted watermark,
    while a genuinely fresh re-observation (ts past the watermark) re-observes
    the SAME incident instead of opening a second one."""
    report = run_scenario(SCENARIOS / "cafe-evil-twin.json", tmp_path)
    assert len(report["incidents"]) == 1
    incident = report["incidents"][0]
    assert incident["event_type"] == "rogue_ap"
    assert incident["severity"] == "alert"
    assert incident["entity_key"] == "BB:BB:CC:00:99:99"
    assert incident["first_seen"] == pytest.approx(1700000015.0)
    # The post-restart re-observation (cycle 4) updates the same incident:
    # one incident, two observations, fresh last_seen.
    assert incident["observation_count"] == 2
    assert incident["last_seen"] == pytest.approx(1700000055.0)


# --- device-row detector scenarios (BLE, co-travel) ------------------------------


def test_ble_scenario_detects_tracker(tmp_path):
    report = run_scenario(SCENARIOS / "walk-ble-tracker.json", tmp_path)
    assert len(report["incidents"]) == 1
    incident = report["incidents"][0]
    assert incident["event_type"] == "ble_tracker"
    assert incident["severity"] == "alert"
    assert incident["entity_key"] == "DD:DD:DD:DD:DD:01"
    # observed_at is the cycle clock, not a device timestamp.
    assert incident["first_seen"] == pytest.approx(1700000000.0)


def test_cotravel_scenario_detects_follower(tmp_path):
    report = run_scenario(SCENARIOS / "walk-cotravel.json", tmp_path)
    cotravel = [i for i in report["incidents"] if i["event_type"] == "cotravel"]
    assert len(cotravel) == 2  # follower + operator's own device (self-identity is out of scope)
    follower = next(
        i for i in cotravel if i["entity_key"] == "AA:BB:CC:00:00:99"
    )
    assert follower["severity"] == "watch"
    assert follower["first_seen"] == pytest.approx(1700000060.0)
    # Operator path crosses two distinct places (A then B) — the gps stats
    # in the cycle summaries carry the fix sequence.
    fixes = [c["detection"]["gps"] for c in report["cycles"]]
    assert fixes[0] == {"lat": 33.4, "lon": -112.0}
    assert fixes[1] == {"lat": 33.41, "lon": -112.01}


def test_device_row_scenarios_deterministic(tmp_path):
    for name in ("walk-ble-tracker", "walk-cotravel"):
        path = SCENARIOS / f"{name}.json"
        run_a = run_scenario(path, tmp_path / f"{name}-a")
        run_b = run_scenario(path, tmp_path / f"{name}-b")
        assert report_bytes(run_a) == report_bytes(run_b), name


def test_lifecycle_scenarios_deterministic(tmp_path):
    """Engine-enabled scenarios are deterministic too: phenomenon rows,
    transitions, and contributions carry no wall-clock or hash-ordering
    leakage (same input + scenario clock -> byte-identical report)."""
    for name in ("cotravel-deauth-merge",):
        path = SCENARIOS / f"{name}.json"
        run_a = run_scenario(path, tmp_path / f"{name}-a")
        run_b = run_scenario(path, tmp_path / f"{name}-b")
        assert report_bytes(run_a) == report_bytes(run_b), name


# --- D2 lifecycle: same-subject merge ------------------------------------------


def test_merge_scenario_one_incident_two_contributions(tmp_path):
    """The D2 acceptance scenario: co-travel AND deauth evidence on the same
    MAC must produce ONE phenomenon incident with TWO contributions from
    different evidence classes, escalated stepwise on the fused confidence —
    and the merge is the lifecycle engine's doing (engine off = two separate
    detector incidents)."""
    from cyt_platform.store import CytStore

    path = SCENARIOS / "cotravel-deauth-merge.json"
    store_path = tmp_path / "cyt.db"
    report = run_scenario(path, tmp_path)

    phenomena = [
        i for i in report["incidents"] if i["event_type"] == "phenomenon"
    ]
    follower = [p for p in phenomena if p["entity_key"] == "AA:BB:CC:00:00:99"]
    assert len(follower) == 1, phenomena  # one phenomenon for the subject
    assert follower[0]["incident_key"] == "ph:wifi_mac:AA:BB:CC:00:00:99"
    assert follower[0]["severity"] == "watch"  # stepwise: alert gate demotes
    assert follower[0]["status"] == "open"

    # Contributions persist through the store API (not in the legacy report
    # view): cotravel + deauth, different evidence classes, one incident.
    store = CytStore.open({"path": str(store_path), "mode": "durable"})
    try:
        row = store.get_incident_by_key("ph:wifi_mac:AA:BB:CC:00:00:99")
        assert row is not None
        contributions = store.list_incident_contributions(int(row["id"]))
        assert {c["detector"] for c in contributions} == {
            "cotravel",
            "deauth_attack",
        }
        # Timeline: opened -> observing -> watch (fused confidence drove
        # every step; the deauth-only assessment was alert-gated to watch).
        states = [
            (t["from_state"], t["to_state"])
            for t in store.list_incident_timeline(int(row["id"]))
        ]
        assert states == [
            (None, "new"),
            ("new", "observing"),
            ("observing", "watch"),
        ]
        # Audit events exist for the opening and every transition.
        kinds = [e["event_type"] for e in report["events"]]
        assert "incident_opened" in kinds
        assert kinds.count("incident_transition") >= 2
    finally:
        store.close()


def test_merge_scenario_engine_off_files_separate_incidents(tmp_path):
    """The contrast case: identical session with incidents_v2 disabled keeps
    the pre-D2 behavior — cotravel and deauth are separate detector
    incidents (the merge is the engine's, not an artifact of the scenario)."""
    doc = json.loads((SCENARIOS / "cotravel-deauth-merge.json").read_text())
    doc["config_overrides"].pop("incidents_v2")
    doc["session_id"] = "replay-cotravel-deauth-merge-engine-off"
    alt = tmp_path / "engine-off.json"
    alt.write_text(json.dumps(doc))

    report = run_scenario(alt, tmp_path)
    kinds = {i["event_type"] for i in report["incidents"]}
    assert "phenomenon" not in kinds
    assert {i["event_type"] for i in report["incidents"]} >= {
        "cotravel",
        "deauth_attack",
    }
    # And no lifecycle summary key rides on engine-off cycles.
    assert all("lifecycle_transitions" not in c for c in report["cycles"])


# --- scenario validation ---------------------------------------------------------


def write_scenario(tmp_path: Path, doc) -> Path:
    path = tmp_path / "scenario.json"
    if isinstance(doc, str):
        path.write_text(doc)
    else:
        path.write_text(json.dumps(doc))
    return path


def test_validation_rejects_unknown_top_level_key(tmp_path):
    doc = {"scenario_version": 1, "scenario_id": "x", "cycles": [], "nope": 1}
    with pytest.raises(ScenarioError, match="unknown keys.*nope"):
        load_scenario(str(write_scenario(tmp_path, doc)))


def test_validation_rejects_unknown_row_source(tmp_path):
    doc = {
        "scenario_version": 1,
        "scenario_id": "x",
        "cycles": [
            {"cycle_id": 1, "clock_ts": 1.0, "rows": [{"source": "cellular", "row": {}}]}
        ],
    }
    with pytest.raises(ScenarioError, match="source"):
        load_scenario(str(write_scenario(tmp_path, doc)))


def test_validation_rejects_missing_cycle_timestamp(tmp_path):
    doc = {
        "scenario_version": 1,
        "scenario_id": "x",
        "cycles": [{"cycle_id": 1, "rows": []}],
    }
    with pytest.raises(ScenarioError, match="clock_ts"):
        load_scenario(str(write_scenario(tmp_path, doc)))


def test_validation_rejects_empty_session(tmp_path):
    doc = {"scenario_version": 1, "scenario_id": "x", "cycles": []}
    with pytest.raises(ScenarioError, match="cycle"):
        load_scenario(str(write_scenario(tmp_path, doc)))


def test_validation_rejects_malformed_json(tmp_path):
    with pytest.raises(ScenarioError, match="invalid JSON"):
        load_scenario(str(write_scenario(tmp_path, "{not json")))


def test_validation_defaults_session_id_from_scenario_id(tmp_path):
    doc = {
        "scenario_version": 1,
        "scenario_id": "x",
        "cycles": [{"cycle_id": 1, "clock_ts": 1.0, "rows": []}],
    }
    scenario = load_scenario(str(write_scenario(tmp_path, doc)))
    assert scenario.session_id == "replay-x"


def test_validation_rejects_wrong_version(tmp_path):
    doc = {"scenario_version": 2, "scenario_id": "x", "cycles": []}
    with pytest.raises(ScenarioError, match="scenario_version"):
        load_scenario(str(write_scenario(tmp_path, doc)))


def test_validation_rejects_bad_restart_cycle(tmp_path):
    doc = {
        "scenario_version": 1,
        "scenario_id": "x",
        "restarts": [9],
        "cycles": [{"cycle_id": 1, "clock_ts": 1.0, "rows": []}],
    }
    with pytest.raises(ScenarioError, match="restart"):
        load_scenario(str(write_scenario(tmp_path, doc)))


# --- D6 detector_failure: a dead detector is never "no threat" ------------------


def test_detector_failure_scenario_degrades_but_never_detects(tmp_path):
    """The detector_failure scenario: the deauth detector fails every cycle
    while the air is quiet. The replay must read degraded every cycle —
    never clean, never "no threat" — and open no incidents (detect=false)."""
    report = run_scenario(SCENARIOS / "detector_failure.json", tmp_path)
    assert report["labels"]["expect"] == {"detect": False, "state": "degraded"}
    assert report["incidents"] == []
    assert len(report["cycles"]) == 3
    for cycle in report["cycles"]:
        assert cycle["state"] == "degraded"
        assert cycle["state"] != "clear"
        failed = cycle["detection"]["detector_failures"]
        assert "detector:deauth" in failed
        assert "fault_injected" in failed["detector:deauth"]
    # The failure survives the mid-scenario restart (fault re-applied to
    # the rebuilt runner) — degraded is not a boot-time artifact.
    assert report["cycles"][-1]["state"] == "degraded"
    assert report["restarts"] == [2]


def test_report_state_matches_expect_state_labels(tmp_path):
    """Per-cycle state is composed with the production ladder; the existing
    scenarios' expect.state labels hold on the final cycle."""
    for name, expected in (
        ("commute-quiet.json", "clear"),
        ("commute-deauth-burst.json", "watch"),
        ("cafe-evil-twin.json", "alert"),
    ):
        report = run_scenario(SCENARIOS / name, tmp_path / name)
        assert report["cycles"][-1]["state"] == expected, name


def test_fault_activates_from_declared_cycle(tmp_path):
    """A fault is dormant before its from_cycle: cycle 1 runs healthy and
    reads clear; the faulting cycles read degraded."""
    doc = {
        "scenario_version": 1,
        "scenario_id": "fault-late",
        "labels": {"expect": {"detect": False}},
        "faults": [
            {"component": "detector:rogue", "from_cycle": 2, "error": "late_fault"}
        ],
        "cycles": [
            {"cycle_id": 1, "clock_ts": 1700000000.0, "rows": []},
            {"cycle_id": 2, "clock_ts": 1700000015.0, "rows": []},
        ],
    }
    report = run_scenario(
        write_scenario(tmp_path, doc), tmp_path / "late"
    )
    assert report["cycles"][0]["state"] == "clear"
    assert report["cycles"][1]["state"] == "degraded"
    assert (
        report["cycles"][1]["detection"]["detector_failures"]["detector:rogue"]
        == "RuntimeError: fault_injected: late_fault"
    )


def test_validation_rejects_unknown_fault_component(tmp_path):
    doc = {
        "scenario_version": 1,
        "scenario_id": "x",
        "faults": [{"component": "detector:cellular", "from_cycle": 1}],
        "cycles": [{"cycle_id": 1, "clock_ts": 1.0, "rows": []}],
    }
    with pytest.raises(ScenarioError, match="replayable"):
        load_scenario(str(write_scenario(tmp_path, doc)))


def test_validation_rejects_fault_from_unknown_cycle(tmp_path):
    doc = {
        "scenario_version": 1,
        "scenario_id": "x",
        "faults": [{"component": "detector:deauth", "from_cycle": 9}],
        "cycles": [{"cycle_id": 1, "clock_ts": 1.0, "rows": []}],
    }
    with pytest.raises(ScenarioError, match="fault"):
        load_scenario(str(write_scenario(tmp_path, doc)))