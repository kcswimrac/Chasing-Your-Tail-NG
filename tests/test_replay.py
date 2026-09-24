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
SCENARIOS = REPO / "tests" / "fixtures" / "replay"


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