"""D10 doctor: per-check results on a fixture environment.

The acceptance contract: doctor runs against a fixture environment in
tests, reports PASS/WARN/FAIL per check, and at least one check
demonstrably fails.
"""

from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest

from cyt_platform.config import DEFAULTS
from cyt_platform.doctor import (
    FAIL,
    PASS,
    WARN,
    CheckResult,
    doctor,
    run_checks,
)

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def env(tmp_path: Path) -> Path:
    """A runnable fixture environment: config + kismet capture + store."""
    kismet = tmp_path / "kismet"
    kismet.mkdir()
    # Kismet captures are sqlite files; an empty one satisfies the resolver.
    sqlite3.connect(str(kismet / "capture.kismet")).close()

    cfg = copy.deepcopy(DEFAULTS)
    cfg["paths"]["kismet_logs"] = str(kismet / "*.kismet")
    cfg["paths"]["data_dir"] = str(tmp_path / "data")
    cfg["paths"]["runtime_dir"] = str(tmp_path / "run")
    cfg["store"]["path"] = str(tmp_path / "data" / "cyt.db")
    cfg["status"]["file"] = str(tmp_path / "run" / "status.json")
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=1), encoding="utf-8")

    # The store is created the way the service does (idempotent migration).
    from cyt_platform.store import CytStore

    store = CytStore.open(cfg.get("store") or {})
    store.close()
    return cfg_path


def by_name(results) -> dict:
    return {r.name: r for r in results}


def test_doctor_all_pass_on_fixture_env(env: Path):
    results = run_checks(str(env))
    checks = by_name(results)
    assert set(checks) == {
        "config",
        "store",
        "kismet",
        "status_path",
        "led_path",
        "detectors",
    }
    failing = [r for r in results if r.status == FAIL]
    assert not failing, failing
    assert checks["store"].status == PASS
    assert "v4" in checks["store"].detail
    assert checks["detectors"].status == PASS


def test_doctor_exit_zero_when_all_pass(env: Path, capsys):
    assert doctor(str(env)) == 0
    out = capsys.readouterr().out
    assert "doctor:" in out


def test_doctor_store_check_fails_on_wrong_schema_version(
    env: Path, monkeypatch
):
    # Simulate a store written by a future/other schema version.
    import cyt_platform.doctor as doctor_mod

    monkeypatch.setattr(doctor_mod, "SUPPORTED_SCHEMA_VERSION", 99)
    results = run_checks(str(env))
    store = by_name(results)["store"]
    assert store.status == FAIL
    assert "v4" in store.detail and "v99" in store.detail


def test_doctor_status_path_check_demonstrably_fails(
    tmp_path: Path, env: Path
):
    # Block the status dir with a regular FILE: ensure_dir cannot create
    # it, so the status_path check must FAIL (and doctor exit non-zero).
    cfg = json.loads(env.read_text(encoding="utf-8"))
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    cfg["status"]["file"] = str(blocker / "status.json")
    env.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    results = run_checks(str(env))
    check = by_name(results)["status_path"]
    assert check.status == FAIL
    assert doctor(str(env)) == 1


def test_doctor_kismet_check_fails_on_unreadable_pattern(tmp_path: Path, env: Path):
    cfg = json.loads(env.read_text(encoding="utf-8"))
    cfg["paths"]["kismet_logs"] = str(tmp_path / "missing-dir" / "x.kismet")
    env.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    # A nonexistent parent for the glob itself: resolver reports no files.
    # Depending on resolver behavior this is WARN (blind) or FAIL.
    results = run_checks(str(env))
    assert by_name(results)["kismet"].status in (WARN, FAIL)


def test_doctor_kismet_warns_when_no_captures_yet(tmp_path: Path, env: Path):
    # Fresh deployment: the glob dir exists but no capture has appeared.
    cfg = json.loads(env.read_text(encoding="utf-8"))
    (tmp_path / "kismet" / "capture.kismet").unlink()
    env.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    results = run_checks(str(env))
    assert by_name(results)["kismet"].status == WARN
    assert "blind" in by_name(results)["kismet"].detail
    # A warning must not fail the deployment.
    assert doctor(str(env)) == 0


def test_doctor_store_warns_when_absent(tmp_path: Path, env: Path):
    cfg = json.loads(env.read_text(encoding="utf-8"))
    (tmp_path / "data" / "cyt.db").unlink()
    env.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    results = run_checks(str(env))
    assert by_name(results)["store"].status == WARN
    assert "no store yet" in by_name(results)["store"].detail
    # But the detectors check says why it cannot probe.
    assert by_name(results)["detectors"].status == FAIL


def test_doctor_invalid_config_fails_everything(tmp_path: Path):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["store"]["retention_days"] = 0  # invalid
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    results = run_checks(str(cfg_path))
    checks = by_name(results)
    assert checks["config"].status == FAIL
    assert "store.retention_days" in checks["config"].detail
    # The remaining checks say they are not runnable — they do not
    # disappear from the report.
    for name in ("store", "kismet", "status_path", "led_path", "detectors"):
        assert checks[name].status == FAIL
        assert "not runnable" in checks[name].detail
    assert doctor(str(cfg_path)) == 1


def test_doctor_missing_config_file(tmp_path: Path):
    results = run_checks(str(tmp_path / "nope.json"))
    checks = by_name(results)
    assert checks["config"].status == FAIL
    assert doctor(str(tmp_path / "nope.json")) == 1


def test_doctor_warns_when_all_detectors_disabled(tmp_path: Path, env: Path):
    cfg = json.loads(env.read_text(encoding="utf-8"))
    cfg["rf"] = {"deauth_enabled": False, "rogue_enabled": False}
    cfg["ie_fingerprint"]["enabled"] = False
    cfg["ble_tracker"]["enabled"] = False
    cfg["gps_fusion"]["enabled"] = False
    env.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
    results = run_checks(str(env))
    check = by_name(results)["detectors"]
    assert check.status == WARN
    assert "all detectors disabled" in check.detail


def test_checkresult_is_a_plain_value():
    r = CheckResult("name", PASS, "detail")
    assert r.status == PASS and r.name == "name" and r.detail == "detail"
