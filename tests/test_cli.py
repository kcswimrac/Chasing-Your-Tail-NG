"""D10 CLI smoke tests over the full subcommand set (fixture environment).

Contract under test:
- every subcommand parses and dispatches (status, doctor, config check,
  replay, eval, baseline, incident show/dismiss/confirm/resolve/reopen);
- `cyt` and `cyt-analyzer` console scripts are declared;
- operator errors are messages with distinct exit codes, never tracebacks;
- the incident state machine stays authoritative through the CLI (an
  operator cannot make an illegal move, e.g. resolve a NEW incident).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from cyt_platform.__main__ import main
from cyt_platform.config import DEFAULTS
from cyt_platform.store import CytStore

REPO = Path(__file__).resolve().parent.parent
SCENARIOS = REPO / "scenarios" / "replay"
INCIDENT_KEY = "ph:wifi_mac:aa:bb:cc:dd:ee:ff"


@pytest.fixture
def env(tmp_path: Path) -> Path:
    """Fixture deployment: config + kismet capture + store + one incident."""
    kismet = tmp_path / "kismet"
    kismet.mkdir()
    cfg = copy.deepcopy(DEFAULTS)
    cfg["paths"]["kismet_logs"] = str(kismet / "*.kismet")
    cfg["paths"]["data_dir"] = str(tmp_path / "data")
    cfg["paths"]["runtime_dir"] = str(tmp_path / "run")
    cfg["store"]["path"] = str(tmp_path / "data" / "cyt.db")
    cfg["status"]["file"] = str(tmp_path / "run" / "status.json")
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=1), encoding="utf-8")

    store = CytStore.open(cfg.get("store") or {})
    try:
        store.ensure_phenomenon_incident(
            incident_key=INCIDENT_KEY,
            entity_type="wifi_mac",
            subject="aa:bb:cc:dd:ee:ff",
            ts=1000.0,
            session_id="fixture",
        )
    finally:
        store.close()
    return cfg_path


def _reset_to_new(cfg_path: Path, key: str) -> None:
    """Drive the fixture incident back to NEW through the state machine."""
    from cyt_platform.incidents import (
        ALLOWED,
        IncidentRef,
        IncidentStatus,
        transition,
    )

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    store = CytStore.open(cfg.get("store") or {})
    try:
        row = store.get_incident_by_key(key)
        state = IncidentStatus(row["lifecycle_state"])
        if state is IncidentStatus.NEW:
            return
        assert IncidentStatus.NEW in ALLOWED[state], state
        plan = transition(
            IncidentRef(
                incident_id=int(row["id"]),
                incident_key=key,
                lifecycle_state=state,
                confidence=0.0,
                last_seen=1000.0,
            ),
            IncidentStatus.NEW,
            "test reset",
            1001.0,
        )
        store.apply_transition(plan)
    finally:
        store.close()


# --- the entry point surface -------------------------------------------------


def test_cyt_console_script_declared():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'cyt = "cyt_platform.__main__:main"' in pyproject


def test_cyt_analyzer_console_script_kept():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'cyt-analyzer = "cyt_platform.__main__:main"' in pyproject


def test_unknown_subcommand_is_rejected_not_crashed(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"])
    assert exc.value.code == 2  # argparse usage error


@pytest.mark.parametrize(
    "argv",
    [
        ["status"],
        ["doctor"],
        ["config", "check"],
        ["incident", "show", INCIDENT_KEY],
        ["incident", "dismiss", INCIDENT_KEY, "--reason", "r"],
        ["incident", "confirm", INCIDENT_KEY],
        ["incident", "reopen", INCIDENT_KEY],
        ["baseline", "list"],
        [
            "replay",
            "--session",
            str(SCENARIOS / "commute-quiet.json"),
        ],
        ["eval", "--scenarios", str(SCENARIOS), "--gates",
         str(REPO / "eval" / "gates.json")],
    ],
)
def test_subcommands_parse_and_dispatch(env: Path, argv, capsys):
    """Every documented form reaches its handler — no argparse rejection."""
    try:
        code = main(["-c", str(env), *argv])
    except SystemExit as e:  # argparse errors surface as SystemExit(2)
        pytest.fail(f"argparse rejected {argv}: {e}")
    # Dispositions and reopen may legally be refused by the state machine
    # (exit 2 with a message); what must NOT happen is an argparse error
    # or an unhandled crash.
    assert code in (0, 1, 2)


# --- status -------------------------------------------------------------------


def test_status_smoke(env: Path, capsys):
    assert main(["-c", str(env), "status"]) == 0
    out = capsys.readouterr().out
    assert "active phenomenon incidents" in out
    assert INCIDENT_KEY in out


def test_status_json_smoke(env: Path, capsys):
    assert main(["-c", str(env), "status", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["active_incidents"][0]["incident_key"] == INCIDENT_KEY


def test_status_without_store(tmp_path: Path, capsys):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["store"]["path"] = str(tmp_path / "data" / "cyt.db")
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    assert main(["-c", str(cfg_path), "status"]) == 0
    assert "no store yet" in capsys.readouterr().out


# --- config check ----------------------------------------------------------------


def test_config_check_ok(env: Path, capsys):
    assert main(["-c", str(env), "config", "check"]) == 0
    assert "config check: OK" in capsys.readouterr().out


def test_config_check_rejects_invalid_with_key(tmp_path: Path, capsys):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["store"]["retention_days"] = 0
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    assert main(["-c", str(cfg_path), "config", "check"]) == 1
    out = capsys.readouterr()
    assert "config check: FAIL" in out.out
    assert "store.retention_days" in out.out  # key + reason + range in message


def test_config_check_missing_file(tmp_path: Path, capsys):
    assert main(["-c", str(tmp_path / "nope.json"), "config", "check"]) == 1
    assert "config check: FAIL" in capsys.readouterr().out


# --- incident show / dispositions / reopen --------------------------------------


def test_incident_show_smoke(env: Path, capsys):
    assert main(["-c", str(env), "incident", "show", INCIDENT_KEY]) == 0
    out = capsys.readouterr().out
    assert "state: new" in out
    assert "first_observation" in out  # the opening timeline row


def test_incident_show_json(env: Path, capsys):
    assert main(["-c", str(env), "incident", "show", INCIDENT_KEY, "--json"]) == 0
    detail = json.loads(capsys.readouterr().out)
    assert detail["incident_key"] == INCIDENT_KEY
    assert detail["timeline"][0]["reason"] == "first_observation"


def test_incident_dismiss_then_reopen_flow(env: Path, capsys):
    assert main(["-c", str(env), "incident", "dismiss", INCIDENT_KEY,
                 "--reason", "my own router"]) == 0
    out = capsys.readouterr().out
    assert f"{INCIDENT_KEY}: new -> false_positive" in out

    # The disposition is persisted with the reason on the audit timeline.
    cfg = json.loads(env.read_text(encoding="utf-8"))
    store = CytStore.open(cfg.get("store") or {})
    try:
        row = store.get_incident_by_key(INCIDENT_KEY)
        assert row["lifecycle_state"] == "false_positive"
        assert row["disposition"] == "false_positive"
        timeline = store.list_incident_timeline(int(row["id"]))
        assert timeline[-1]["reason"] == "my own router"
    finally:
        store.close()

    assert main(["-c", str(env), "incident", "reopen", INCIDENT_KEY,
                 "--reason", "still seeing it"]) == 0
    out = capsys.readouterr().out
    assert f"{INCIDENT_KEY}: false_positive -> new" in out


def test_dismiss_and_confirm_apply_from_new(env: Path):
    assert main(["-c", str(env), "incident", "dismiss", INCIDENT_KEY,
                 "--reason", "smoke dismiss"]) == 0
    _reset_to_new(env, INCIDENT_KEY)
    assert main(["-c", str(env), "incident", "confirm", INCIDENT_KEY,
                 "--reason", "smoke confirm"]) == 0
    cfg = json.loads(env.read_text(encoding="utf-8"))
    store = CytStore.open(cfg.get("store") or {})
    try:
        row = store.get_incident_by_key(INCIDENT_KEY)
        assert row["disposition"] == "known_device"
    finally:
        store.close()


def test_resolve_from_new_is_refused_by_the_state_machine(env: Path, capsys):
    # RESOLVED means "staleness-closed after progression" — a brand-new
    # incident cannot be resolved, and the CLI must say so, not crash.
    assert main(["-c", str(env), "incident", "resolve", INCIDENT_KEY]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_resolve_after_progression_applies(env: Path, capsys):
    from cyt_platform.incidents import IncidentRef, IncidentStatus, transition

    cfg = json.loads(env.read_text(encoding="utf-8"))
    store = CytStore.open(cfg.get("store") or {})
    try:
        row = store.get_incident_by_key(INCIDENT_KEY)
        plan = transition(
            IncidentRef(
                incident_id=int(row["id"]),
                incident_key=INCIDENT_KEY,
                lifecycle_state=IncidentStatus(row["lifecycle_state"]),
                confidence=0.0,
                last_seen=1000.0,
            ),
            IncidentStatus.OBSERVING,
            "test progression",
            1002.0,
        )
        store.apply_transition(plan)
    finally:
        store.close()

    assert main(["-c", str(env), "incident", "resolve", INCIDENT_KEY,
                 "--reason", "smoke resolve"]) == 0
    out = capsys.readouterr().out
    assert f"{INCIDENT_KEY}: observing -> resolved" in out


def test_incident_unknown_key_exit_2(env: Path, capsys):
    assert main(["-c", str(env), "incident", "dismiss", "ph:nope:none"]) == 2
    assert "unknown incident" in capsys.readouterr().err


def test_incident_reopen_on_active_is_rejected_with_the_rule(env: Path, capsys):
    assert main(["-c", str(env), "incident", "reopen", INCIDENT_KEY]) == 2
    err = capsys.readouterr().err
    assert "reopen applies to terminal incidents" in err


def test_incident_invalid_config_is_not_a_traceback(tmp_path: Path, capsys):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["push"]["min_severity"] = "bogus"
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    assert main(["-c", str(cfg_path), "incident", "show", INCIDENT_KEY]) == 1
    err = capsys.readouterr().err
    assert "push.min_severity" in err
    assert "Traceback" not in err


# --- replay / eval stay first-class subcommands ----------------------------------


def test_replay_smoke(env: Path, capsys):
    assert main(["-c", str(env), "replay", "--session",
                 str(SCENARIOS / "commute-quiet.json")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "scenario_id" in report


def test_eval_smoke_full_corpus(env: Path, capsys):
    assert main(["-c", str(env), "eval"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["green"] is True
