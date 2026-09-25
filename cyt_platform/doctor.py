"""D10 doctor: per-check environment report (PASS/WARN/FAIL with detail).

Doctor answers one operator question: will this deployment work? Every
check reports one of three outcomes —

- PASS   verified working this run
- WARN   degraded but runnable (e.g. no Kismet capture yet — detection is
         blind until one appears, and a safety device must say so)
- FAIL   the service cannot run correctly; doctor exits non-zero

Checks are read-only against the deployment (the store open runs the same
idempotent migration the service runs at startup; no data is written
beyond that).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from cyt_platform.config import ConfigError, load_json
from cyt_platform.crypto import sealed_path_for
from cyt_platform.health import ComponentFailureRegistry
from cyt_platform.kismet_resolve import KismetDbResolver
from cyt_platform.privacy import ensure_dir, sanitize_error
from cyt_platform.rf_plugins import RFPluginRunner
from cyt_platform.store import CytStore

# The store schema this binary understands (store.migrate target).
SUPPORTED_SCHEMA_VERSION = 4

PASS = "pass"
WARN = "warn"
FAIL = "fail"


@dataclass
class CheckResult:
    name: str
    status: str  # PASS | WARN | FAIL
    detail: str


def _check_writable_dir(path: Path, name: str, purpose: str) -> CheckResult:
    """Directory exists (created if needed) and is writable."""
    try:
        ensure_dir(path, 0o750)
    except OSError as e:
        return CheckResult(name, FAIL, f"cannot create {purpose} {path}: {sanitize_error(e)}")
    if not os.access(path, os.W_OK):
        return CheckResult(name, FAIL, f"{purpose} {path} is not writable")
    return CheckResult(name, PASS, f"{purpose} writable: {path}")


def _check_store(config: dict) -> Tuple[CheckResult, Optional[CytStore]]:
    store_cfg = config.get("store") or {}
    logical = Path(store_cfg.get("path") or "data/cyt.db")
    if not logical.exists() and not sealed_path_for(logical).exists():
        return (
            CheckResult("store", WARN, f"no store yet (first service run creates it): {logical}"),
            None,
        )
    try:
        store = CytStore.open(store_cfg)
    except Exception as e:  # noqa: BLE001 - doctor reports, never crashes
        return CheckResult("store", FAIL, f"cannot open store: {sanitize_error(e)}"), None
    try:
        row = store.conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'"
        ).fetchone()
    except Exception as e:  # noqa: BLE001
        return CheckResult("store", FAIL, f"cannot read schema version: {sanitize_error(e)}"), store
    version = int(row["value"]) if row else 0
    if version != SUPPORTED_SCHEMA_VERSION:
        detail = (
            f"schema v{version} at {logical} (this build supports v"
            f"{SUPPORTED_SCHEMA_VERSION})"
        )
        return CheckResult("store", FAIL, detail), store
    return CheckResult("store", PASS, f"schema v{version} at {logical}"), store


def _check_kismet(config: dict) -> CheckResult:
    pattern = (config.get("paths") or {}).get("kismet_logs") or ""
    if not pattern:
        return CheckResult("kismet", WARN, "paths.kismet_logs not configured")
    try:
        path = KismetDbResolver(pattern).resolve()
    except FileNotFoundError:
        return CheckResult(
            "kismet",
            WARN,
            f"no capture files match {pattern} — detection is blind until "
            "Kismet writes one",
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult("kismet", FAIL, sanitize_error(e))
    return CheckResult("kismet", PASS, f"newest capture: {Path(path).name}")


def _check_status_path(config: dict) -> CheckResult:
    status_file = Path(
        (config.get("status") or {}).get("file") or "data/run/status.json"
    )
    result = _check_writable_dir(status_file.parent, "status_path", "status dir")
    if result.status != PASS or not status_file.exists():
        return result
    if not os.access(status_file, os.W_OK):
        return CheckResult("status_path", FAIL, f"{status_file} is not writable")
    return CheckResult("status_path", PASS, f"publish path writable: {status_file}")


def _check_led_paths(config: dict) -> CheckResult:
    runtime = Path((config.get("paths") or {}).get("runtime_dir") or "data/run")
    result = _check_writable_dir(runtime, "led_path", "runtime dir")
    if result.status != PASS:
        return result
    # Optional hardware backend: configured sysfs brightness must sit in a
    # writable location, or the LED glance silently stops reflecting state.
    sysfs = (config.get("led") or {}).get("sysfs_brightness")
    if sysfs:
        sp = Path(sysfs)
        if not sp.parent.is_dir():
            return CheckResult("led_path", WARN, f"sysfs parent missing: {sp.parent}")
        if not os.access(sp.parent, os.W_OK):
            return CheckResult("led_path", WARN, f"sysfs not writable: {sp}")
    return CheckResult("led_path", PASS, f"LED state dir writable: {runtime}")


def _enabled_detectors(config: dict) -> set:
    rf = config.get("rf") or {}
    enabled = set()
    if rf.get("deauth_enabled", True):
        enabled.add("deauth")
    if rf.get("rogue_enabled", True):
        enabled.add("rogue")
    if (config.get("ie_fingerprint") or {}).get("enabled", True):
        enabled.add("ie")
    if (config.get("ble_tracker") or {}).get("enabled", True):
        enabled.add("ble")
    if (config.get("gps_fusion") or {}).get("enabled", True):
        enabled.add("gps")
    return enabled


def _check_detectors(
    config: dict, store: Optional[CytStore]
) -> CheckResult:
    enabled = _enabled_detectors(config)
    if store is None:
        # A missing store already reported its own check; without it the
        # registration probe cannot run.
        return CheckResult(
            "detectors", FAIL, "not runnable: store unavailable"
            if enabled else "not runnable: store unavailable (and all detectors disabled)"
        )
    registry = ComponentFailureRegistry()
    try:
        runner = RFPluginRunner(store, config, registry)
    except Exception as e:  # noqa: BLE001
        return CheckResult("detectors", FAIL, f"runner init failed: {sanitize_error(e)}")
    registered = [
        name
        for name, attr in (
            ("deauth", runner.deauth),
            ("rogue", runner.rogue),
            ("ie", runner.ie),
            ("ble", runner.ble),
            ("gps", runner.gps),
        )
        if attr is not None
    ]
    failures = registry.failures()  # component -> sanitized reason
    if not enabled:
        return CheckResult(
            "detectors", WARN, "all detectors disabled in config"
        )
    if not registered:
        return CheckResult(
            "detectors",
            FAIL,
            f"none of {sorted(enabled)} registered; init failures: {failures or '{}'}",
        )
    missing = sorted(enabled - set(registered))
    detail = f"registered: {', '.join(sorted(registered))}"
    if missing:
        detail += f"; NOT registered: {', '.join(missing)}"
    if failures:
        detail += f"; init failures: {failures}"
    if missing or failures:
        return CheckResult("detectors", WARN, detail)
    return CheckResult("detectors", PASS, detail)


def _skipped(names) -> list:
    return [CheckResult(name, FAIL, "not runnable: config invalid") for name in names]


def run_checks(config_path: Optional[str] = None) -> list:
    """Run every doctor check; returns results in reporting order.

    The config check gates the rest: an invalid config is the one failure
    that makes the remaining checks unrunnable, and each says so instead
    of disappearing from the report.
    """
    try:
        config = load_json(config_path)
    except ConfigError as e:
        return [
            CheckResult("config", FAIL, str(e)),
            *_skipped(("store", "kismet", "status_path", "led_path", "detectors")),
        ]
    except (OSError, ValueError) as e:
        return [
            CheckResult("config", FAIL, f"cannot load config: {sanitize_error(e)}"),
            *_skipped(("store", "kismet", "status_path", "led_path", "detectors")),
        ]

    results: list = [CheckResult("config", PASS, "valid")]
    store_result, store = _check_store(config)
    results.append(store_result)
    results.append(_check_kismet(config))
    results.append(_check_status_path(config))
    results.append(_check_led_paths(config))
    results.append(_check_detectors(config, store))
    if store is not None:
        store.close()
    return results


def print_report(results: list) -> None:
    width = max(len(r.name) for r in results)
    for r in results:
        print(f"{r.status.upper():4}  {r.name:{width}}  {r.detail}")
    counts = {s: sum(1 for r in results if r.status == s) for s in (PASS, WARN, FAIL)}
    print(
        f"doctor: {counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail"
    )


def doctor(config_path: Optional[str] = None) -> int:
    """CLI entry: print the report, exit 0 only when nothing failed."""
    results = run_checks(config_path)
    print_report(results)
    return 0 if not any(r.status == FAIL for r in results) else 1
