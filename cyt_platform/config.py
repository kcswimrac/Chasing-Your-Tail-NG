"""Config-only loader for the headless analyzer (no credential manager)."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

DEFAULTS: Dict[str, Any] = {
    "paths": {
        "base_dir": ".",
        "log_dir": "logs",
        "kismet_logs": "/var/log/kismet/*.kismet",
        "ignore_lists_dir": "ignore_lists",
        "ignore_lists": {
            "mac": "mac_list.json",
            "ssid": "ssid_list.json",
        },
        "data_dir": "data",
        "runtime_dir": "data/run",
    },
    "timing": {
        "check_interval": 60,
        "list_update_interval": 5,
        "time_windows": {
            "recent": 5,
            "medium": 10,
            "old": 15,
            "oldest": 20,
        },
    },
    "store": {
        "path": "data/cyt.db",
        "synchronous": "NORMAL",
        "retention_days": 14,
        "heartbeat_keep_days": 7,
        "entity_retention_days": 30,
        "allow_recreate_on_corrupt": False,
        "mode": "durable",
        "encryption": {
            "enabled": False,
            "sealed": True,
            "field_encrypt": True,
            "key_file": None,
            "salt_file": "data/store_salt.bin",
            "runtime_dir": None,
        },
        "seal_every_cycles": 10,
    },
    "baseline": {
        "enabled": False,
        "min_sightings": 5,
        "current_place": None,
        "places": {},
    },
    "led": {
        "sysfs_brightness": None,
        "gpio": {"enabled": False, "pin": None},
    },
    "push": {
        "enabled": False,
        "backend": "ntfy",  # ntfy | log
        "min_severity": "alert",
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "",
        "ntfy_token": "",
        "max_attempts": 8,
        "cooldown_seconds": 300,
    },
    "gps_fusion": {
        "enabled": True,
        "cluster_meters": 100,
        "min_locations_for_cotravel": 2,
        "min_span_seconds": 900,
        "incident_score_threshold": 0.55,
        # D5 location-independence geometry (None -> location.py defaults):
        # haversine merge radius for places, revisit gap that splits
        # re-entries into distinct visits, feasibility cap, and how far
        # back co-travel scoring looks.
        "merge_radius_m": None,
        "revisit_gap_s": 600,
        "max_speed_mps": 35,
        "cotravel_lookback_s": 21600,
        "density_window_s": 300,
    },
    "ie_fingerprint": {
        "enabled": True,
        "min_probe_ssids": 1,
        # D3 identity hypothesis policy floors. Signal weights are fixed in
        # cyt_platform.identity (locked decision 8 — transparent, auditable
        # scoring); these are the configurable policy knobs.
        "candidate_floor": 0.30,
        "link_threshold": 0.70,
        "relink_alert_floor": 0.95,
        "min_support": 2,
        "co_window_s": 30.0,
        "handoff_max_s": 300.0,
    },
    "ble_tracker": {
        "enabled": True,
        "min_score": 0.5,
    },
    "fusion": {
        # D4 confidence fusion (locked decision 8: transparent, fixed,
        # config-owned weights — no learned model). Supporting evidence
        # lines combine by noisy-OR (monotone in evidence, saturating);
        # contradicting lines multiply the support down, so every contra
        # line strictly lowers confidence. A weight is the contribution of
        # one fully-satisfied evidence line of that kind; every rendered
        # number cites its evidence kind + line, so names must stay
        # traceable to this table.
        "min_independent_kinds": 2,
        # Repetition alone never alerts (product principle): an alert
        # needs at least this many DISTINCT independent evidence kinds.
        # Repeats of the same kind still raise confidence but never
        # satisfy this gate.
        "max_confidence": 0.99,
        # Evidence is never certainty: fused confidence caps here.
        "default_weight": 0.10,
        # Kinds missing from the weight table get this conservative
        # contribution and never count as independent evidence (a new
        # detector's kinds must be deliberately listed to gain
        # alertability).
        "self_ref_kinds": ["score"],
        # Kinds that restate the detector's own computed conclusion rather
        # than describe an observed phenomenon: they contribute weight but
        # never count toward the independent-evidence alert gate.
        "weights": {
            # Observed deauth/disassoc management-frame pattern toward a
            # target (Kismet alert-derived): a distinct RF attack class.
            "deauth_pattern": 0.35,
            # Attack type + frame-count signature: a separate classifier
            # dimension of the same alert family.
            "attack_signature": 0.20,
            # The capture layer's own severity classification (Kismet is
            # a trusted sensor per the EDC design doc).
            "source_severity": 0.15,
            # One Kismet rogue/evil-twin alert reason. All of an alert's
            # reasons share this kind, so repeats never raise the
            # independent-kind count.
            "rogue_reason": 0.25,
            # BLE tracker signal: name/manuf/metadata token match.
            "ble_signal": 0.25,
            # D5 location geometry: a distinct visit on the operator path.
            "independent_visits": 0.30,
            # The detector's own computed score (self-reference; weight
            # only, never independent evidence).
            "score": 0.10,
            # Ambient density at the observation site — the canonical
            # contra kind: crowded places discount tracking confidence.
            "density": 0.06,
        },
    },
    "rf": {
        "deauth_enabled": True,
        "rogue_enabled": True,
    },
    "deauth_detection": {
        "enabled": True,
        "burst_threshold": 10,
        "burst_window_seconds": 60,
        "min_events_for_attack": 5,
        "protected_macs": [],
    },
    "rogue_ap_detection": {
        "enabled": True,
        "auto_learn": True,
        "monitored_ssids": [],
        "trusted_aps": [],
    },
    "incidents": {
        "close_after_seconds": 600,
    },
    "status": {
        "file": "data/run/status.json",
        "stale_seconds": 150,
        "hold_seconds": 300,
        "deaf_seconds": 180,
        "deaf_is_fail": True,
        "quiet_is_watch": False,
        "http_enabled": False,
        "http_bind": "127.0.0.1",
        "http_port": 8787,
        "expose_total_opens": False,
        "window_to_severity": {
            "5-10": "watch",
            "10-15": "watch",
            "15-20": "alert",
        },
    },
    "service": {
        "legacy_log_file": False,
        "legacy_log_redact": True,
        "sd_notify": True,
        "consecutive_fail_threshold": 5,
        "exit_on_consecutive_fail": False,
        "kismet_proc_check": True,
        "watchdog_sec_hint": 180,
    },
    "privacy": {
        "require_fde_notice": True,
        "sanitize_errors": True,
        "status_path_basename_only": True,
        "fde_ack_path": "/etc/cyt/fde_ack",
    },
    "search": {
        "lat_min": 31.3,
        "lat_max": 37.0,
        "lon_min": -114.8,
        "lon_max": -109.0,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = deepcopy(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def resolve_config_path(cli_path: Optional[str] = None) -> Path:
    if cli_path:
        return Path(cli_path)
    env = os.environ.get("CYT_CONFIG")
    if env:
        return Path(env)
    return Path("config.json")


def load_json(path: Optional[str] = None) -> Dict[str, Any]:
    """Load config JSON only — never constructs SecureCredentialManager."""
    cfg_path = resolve_config_path(path)
    if not cfg_path.is_file():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    with open(cfg_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("Config root must be a JSON object")
    return _deep_merge(DEFAULTS, raw)


def ignore_list_paths(config: dict) -> Tuple[Path, Path]:
    paths = config.get("paths") or {}
    base = Path(paths.get("base_dir") or ".")
    ignore_dir = paths.get("ignore_lists_dir")
    if ignore_dir:
        idir = Path(ignore_dir)
        if not idir.is_absolute():
            idir = base / idir
    else:
        idir = base / "ignore_lists"
    names = paths.get("ignore_lists") or {}
    mac_name = names.get("mac", "mac_list.json")
    ssid_name = names.get("ssid", "ssid_list.json")
    return idir / mac_name, idir / ssid_name


def ensure_runtime_dirs(config: dict) -> None:
    from cyt_platform.privacy import ensure_dir

    paths = config.get("paths") or {}
    store = config.get("store") or {}
    status = config.get("status") or {}

    data_dir = paths.get("data_dir") or "data"
    ensure_dir(data_dir, 0o700)
    runtime = paths.get("runtime_dir") or "data/run"
    ensure_dir(runtime, 0o750)
    log_dir = paths.get("log_dir") or "logs"
    ensure_dir(log_dir, 0o700)

    # parent of store path
    sp = Path(store.get("path") or "data/cyt.db")
    if sp.parent and str(sp.parent) not in (".", ""):
        ensure_dir(sp.parent, 0o700)
    sf = Path(status.get("file") or "data/run/status.json")
    if sf.parent and str(sf.parent) not in (".", ""):
        ensure_dir(sf.parent, 0o750)
