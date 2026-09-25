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
        "self_ref_kinds": [
            "attack_signature",
            "score",
            "source_severity",
        ],
        # Kinds that restate the detector's own computed conclusion or its
        # input facets rather than describe an observed phenomenon: they
        # contribute weight but never count toward the independent-evidence
        # alert gate. S1: one deauth alert row is ONE observation — its
        # severity label (source_severity) and type/frame signature
        # (attack_signature) are facets of that same row, not independent
        # corroboration; counting them let a single alert row satisfy the
        # kinds gate by itself.
        "weights": {
            # Observed deauth/disassoc management-frame pattern toward a
            # target (Kismet alert-derived): a distinct RF attack class.
            "deauth_pattern": 0.35,
            # Attack type + frame-count signature: a facet of the same
            # alert row as deauth_pattern — contributes weight, never
            # independent kinds (self_ref_kinds).
            "attack_signature": 0.20,
            # The capture layer's own severity classification (Kismet is
            # a trusted sensor per the EDC design doc): a restated
            # conclusion, so weight-only (self_ref_kinds).
            "source_severity": 0.15,
            # One Kismet rogue/evil-twin alert reason. All of an alert's
            # reasons share this kind, so repeats never raise the
            # independent-kind count.
            "rogue_reason": 0.25,
            # BLE tracker signal: name/manuf/metadata token match.
            "ble_signal": 0.25,
            # D5 co-travel geometry (gps_live._cotravel_result): the device
            # is co-present with the operator at a place, and its sightings
            # span the operator's travel (multi-place tracking). Together
            # these are the facets of "independent visits"; listing them is
            # what makes the primary follower scenario alertable at all.
            "copresence": 0.30,
            "travel_span": 0.25,
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
        # B4: events older than this are pruned from the analyzer's memory
        # and excluded from attack classification, so severity tracks recent
        # frame rates — never process lifetime — and a restarted process
        # classifies like a long-lived one. Keep it <=
        # catchup_window_seconds (the deepest look-back any scan can read).
        "attack_window_seconds": 1800,
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


class ConfigError(ValueError):
    """Configuration rejected before use.

    The message names every invalid key with its reason and acceptable
    range — the operator fixes all problems in one round-trip instead of
    a fix-one-rerun loop. ``errors`` carries the individual lines.
    """

    def __init__(self, errors: list):
        self.errors = list(errors)
        joined = "\n  ".join(self.errors)
        super().__init__(
            f"invalid configuration ({len(self.errors)} problem(s)):\n  {joined}"
        )


# --- validation primitives -------------------------------------------------
#
# Each helper appends one actionable error line per bad value and never
# raises: validate_config collects every problem before failing. Dotted
# keys name the exact path into the config document.


def _get_at(cfg: dict, dotted: str):
    node: Any = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _add(errors: list, key: str, reason: str, got: Any) -> None:
    errors.append(f"{key}: {reason} (got {got!r})")


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _num(
    cfg: dict,
    errors: list,
    key: str,
    *,
    ok,
    desc: str,
    allow_none: bool = False,
) -> None:
    found, v = _get_at(cfg, key)
    if not found or (v is None and allow_none):
        return
    if not _is_number(v) or not ok(float(v)):
        _add(errors, key, f"must be a number {desc}", v)


def _bool(cfg: dict, errors: list, key: str) -> None:
    found, v = _get_at(cfg, key)
    if not found:
        return
    if not isinstance(v, bool):
        _add(errors, key, "must be true or false", v)


def _str(
    cfg: dict,
    errors: list,
    key: str,
    *,
    allow_none: bool = False,
    allow_empty: bool = False,
) -> None:
    found, v = _get_at(cfg, key)
    if not found or (v is None and allow_none):
        return
    if not isinstance(v, str):
        _add(errors, key, "must be a string", v)
    elif not allow_empty and not v.strip():
        _add(errors, key, "must be a non-empty string", v)


def _enum(
    cfg: dict, errors: list, key: str, allowed, *, allow_none: bool = False
) -> None:
    found, v = _get_at(cfg, key)
    if not found or (v is None and allow_none):
        return
    text = str(v).lower() if isinstance(v, str) else v
    if text not in allowed:
        _add(errors, key, f"must be one of {sorted(allowed)}", v)


def _str_list(cfg: dict, errors: list, key: str) -> None:
    found, v = _get_at(cfg, key)
    if not found or v is None:
        return
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        _add(errors, key, "must be a list of strings", v)


def _section_is_object(cfg: dict, errors: list, key: str) -> None:
    found, v = _get_at(cfg, key)
    if found and not isinstance(v, dict):
        _add(errors, key, "must be an object", v)


# Sections whose children are user-defined (place names, window labels)
# are skipped by the unknown-key walk and shape-checked separately.
_FREE_FORM = {
    "baseline.places",
    "status.window_to_severity",
}


def _known_tree() -> dict:
    """The closed set of valid config keys, as a nested tree.

    ``incidents_v2`` and the GPS dropout knobs are consumed by code but
    absent from DEFAULTS; they are known all the same. The incidents
    import is lazy: incidents -> confidence -> config is a module-level
    import chain, and config must not load it at import time.
    """
    from cyt_platform.incidents import INCIDENTS_V2_DEFAULTS

    tree: Dict[str, Any] = {}
    for section, val in DEFAULTS.items():
        if isinstance(val, dict):
            tree[section] = _subtree(val)
        else:
            tree[section] = True
    tree["incidents_v2"] = _subtree(INCIDENTS_V2_DEFAULTS)
    gps = tree.get("gps_fusion")
    if isinstance(gps, dict):
        gps["dropout_seconds"] = True
        gps["dropout_min_cycles"] = True
    return tree


def _subtree(section: dict) -> dict:
    out: Dict[str, Any] = {}
    for k, v in section.items():
        out[k] = _subtree(v) if isinstance(v, dict) else True
    return out


def _unknown_keys(cfg: dict, tree: dict, prefix: str = "") -> list:
    out: list = []
    for k, v in cfg.items():
        path = f"{prefix}{k}"
        if k not in tree:
            out.append(path)
            continue
        sub = tree[k]
        if (
            isinstance(sub, dict)
            and isinstance(v, dict)
            and path not in _FREE_FORM
        ):
            out.extend(_unknown_keys(v, sub, prefix=f"{path}."))
    return out


def _validate_fusion_weights(cfg: dict, errors: list) -> None:
    found, weights = _get_at(cfg, "fusion.weights")
    if found and isinstance(weights, dict):
        if not weights:
            _add(errors, "fusion.weights", "must define at least one weight", weights)
        for kind, w in weights.items():
            key = f"fusion.weights.{kind}"
            if not isinstance(kind, str) or not kind.strip():
                _add(errors, key, "must be a named evidence kind", kind)
            elif not _is_number(w) or not 0.0 < float(w) <= 1.0:
                _add(errors, key, "must be a number in (0, 1]", w)


def _validate_baseline_places(cfg: dict, errors: list) -> None:
    found, places = _get_at(cfg, "baseline.places")
    if not found or not isinstance(places, dict):
        return
    for name, place in places.items():
        key = f"baseline.places.{name}"
        if not isinstance(place, dict):
            _add(errors, key, "must be an object", place)
            continue
        radius = place.get("radius_m")
        if radius is not None and (not _is_number(radius) or radius <= 0):
            _add(errors, f"{key}.radius_m", "must be a number > 0", radius)
        hours = place.get("hours")
        if hours is None:
            continue
        if not isinstance(hours, list):
            _add(errors, f"{key}.hours", "must be a list of [start, end] pairs", hours)
            continue
        for window in hours:
            bad = (
                not isinstance(window, (list, tuple))
                or len(window) != 2
                or not all(_is_number(x) for x in window)
            )
            if bad or not (
                0 <= float(window[0]) <= 24 and 0 <= float(window[1]) <= 24
            ):
                _add(
                    errors,
                    f"{key}.hours",
                    "must be [start_hour, end_hour] pairs within 0..24",
                    window,
                )


def _validate_window_severities(cfg: dict, errors: list) -> None:
    found, mapping = _get_at(cfg, "status.window_to_severity")
    if not found or not isinstance(mapping, dict):
        return
    allowed = {"info", "watch", "alert"}
    for label, sev in mapping.items():
        if str(sev).lower() not in allowed:
            _add(
                errors,
                f"status.window_to_severity.{label}",
                f"must be one of {sorted(allowed)}",
                sev,
            )


def validate_config(cfg: dict) -> None:
    """Reject an invalid config with every problem named.

    Raises :class:`ConfigError` whose message lists each bad key, why it
    is bad, and the acceptable range (spec D10: actionable errors, not
    tracebacks). Valid configs return None. Both shipped configs
    (``config.json``, ``config.edc.json``) must validate clean — pinned
    by tests.
    """
    errors: list = []

    # Sections themselves must be objects before the dotted checks below
    # can mean anything.
    for section in DEFAULTS:
        _section_is_object(cfg, errors, section)
    _section_is_object(cfg, errors, "incidents_v2")

    # Unknown keys are rejected outright: a typo'd key silently doing
    # nothing is the "silent wrong-config behavior" failure mode.
    unknown = _unknown_keys(cfg, _known_tree())
    for key in unknown:
        _add(errors, key, "unknown configuration key (remove it or fix the typo)", key)

    # paths — filesystem locations
    for key in (
        "paths.base_dir",
        "paths.log_dir",
        "paths.kismet_logs",
        "paths.ignore_lists_dir",
        "paths.ignore_lists.mac",
        "paths.ignore_lists.ssid",
        "paths.data_dir",
        "paths.runtime_dir",
    ):
        _str(cfg, errors, key)

    # timing — cycle and window geometry
    _num(cfg, errors, "timing.check_interval", ok=lambda n: n > 0, desc="> 0 (seconds)")
    _num(
        cfg, errors, "timing.list_update_interval",
        ok=lambda n: n >= 0, desc=">= 0 (seconds)",
    )
    for w in ("recent", "medium", "old", "oldest"):
        _num(
            cfg, errors, f"timing.time_windows.{w}",
            ok=lambda n: n > 0, desc="> 0 (minutes)",
        )
    found, recent = _get_at(cfg, "timing.time_windows.recent")
    if found and _is_number(recent):
        prev = recent
        prev_key = "recent"
        for w in ("medium", "old", "oldest"):
            found_w, val = _get_at(cfg, f"timing.time_windows.{w}")
            if found_w and _is_number(val):
                if float(val) <= float(prev):
                    _add(
                        errors,
                        f"timing.time_windows.{w}",
                        f"must be > timing.time_windows.{prev_key} ({prev})",
                        val,
                    )
                prev, prev_key = val, w

    # store — durability, retention, sealing, encryption
    _str(cfg, errors, "store.path")
    _enum(
        cfg, errors, "store.synchronous",
        allowed={"off", "normal", "full", "extra"},
    )
    _num(cfg, errors, "store.retention_days", ok=lambda n: n >= 1, desc=">= 1 (days)")
    _num(
        cfg, errors, "store.heartbeat_keep_days",
        ok=lambda n: n >= 1, desc=">= 1 (days)",
    )
    _num(
        cfg, errors, "store.entity_retention_days",
        ok=lambda n: n >= 1, desc=">= 1 (days)",
    )
    _bool(cfg, errors, "store.allow_recreate_on_corrupt")
    _enum(cfg, errors, "store.mode", allowed={"durable", "ephemeral_events"})
    _num(
        cfg, errors, "store.seal_every_cycles",
        ok=lambda n: n >= 1, desc=">= 1 (cycles)",
    )
    _bool(cfg, errors, "store.encryption.enabled")
    _bool(cfg, errors, "store.encryption.sealed")
    _bool(cfg, errors, "store.encryption.field_encrypt")
    _str(cfg, errors, "store.encryption.key_file", allow_none=True)
    _str(cfg, errors, "store.encryption.salt_file", allow_none=True)
    _str(cfg, errors, "store.encryption.runtime_dir", allow_none=True)

    # baseline — learning policy
    _bool(cfg, errors, "baseline.enabled")
    _num(
        cfg, errors, "baseline.min_sightings",
        ok=lambda n: n >= 1, desc=">= 1 (sightings)",
    )
    _str(cfg, errors, "baseline.current_place", allow_none=True, allow_empty=True)
    _validate_baseline_places(cfg, errors)

    # led — glanceable output paths
    _str(cfg, errors, "led.sysfs_brightness", allow_none=True, allow_empty=True)
    _bool(cfg, errors, "led.gpio.enabled")
    found, pin = _get_at(cfg, "led.gpio.pin")
    if found and pin is not None and (isinstance(pin, bool) or not isinstance(pin, int)):
        _add(errors, "led.gpio.pin", "must be a GPIO pin number or null", pin)

    # push — notification policy
    _bool(cfg, errors, "push.enabled")
    _enum(cfg, errors, "push.backend", allowed={"ntfy", "log"})
    _enum(
        cfg, errors, "push.min_severity",
        allowed={"watch", "alert", "fail", "critical"},
    )
    _str(cfg, errors, "push.ntfy_url")
    _str(cfg, errors, "push.ntfy_topic", allow_empty=True)
    _str(cfg, errors, "push.ntfy_token", allow_empty=True)
    _num(cfg, errors, "push.max_attempts", ok=lambda n: n >= 1, desc=">= 1")
    _num(
        cfg, errors, "push.cooldown_seconds",
        ok=lambda n: n >= 0, desc=">= 0 (seconds)",
    )

    # gps_fusion — location-independence geometry (D5)
    _bool(cfg, errors, "gps_fusion.enabled")
    _num(
        cfg, errors, "gps_fusion.cluster_meters",
        ok=lambda n: n > 0, desc="> 0 (meters)",
    )
    _num(
        cfg, errors, "gps_fusion.min_locations_for_cotravel",
        ok=lambda n: n >= 2, desc=">= 2 (co-travel needs at least 2 locations)",
    )
    _num(
        cfg, errors, "gps_fusion.min_span_seconds",
        ok=lambda n: n >= 0, desc=">= 0 (seconds)",
    )
    _num(
        cfg, errors, "gps_fusion.incident_score_threshold",
        ok=lambda n: 0.0 <= n <= 1.0, desc="in [0, 1]",
    )
    _num(
        cfg, errors, "gps_fusion.merge_radius_m",
        ok=lambda n: n > 0, desc="a number > 0 (meters) or null", allow_none=True,
    )
    _num(
        cfg, errors, "gps_fusion.revisit_gap_s",
        ok=lambda n: n >= 0, desc=">= 0 (seconds)",
    )
    _num(
        cfg, errors, "gps_fusion.max_speed_mps",
        ok=lambda n: n > 0, desc="> 0 (meters/second)",
    )
    _num(
        cfg, errors, "gps_fusion.cotravel_lookback_s",
        ok=lambda n: n >= 0, desc=">= 0 (seconds)",
    )
    _num(
        cfg, errors, "gps_fusion.density_window_s",
        ok=lambda n: n > 0, desc="> 0 (seconds)",
    )
    _num(
        cfg, errors, "gps_fusion.dropout_seconds",
        ok=lambda n: n > 0, desc="> 0 (seconds)",
    )
    _num(
        cfg, errors, "gps_fusion.dropout_min_cycles",
        ok=lambda n: n >= 0, desc=">= 0 (cycles)",
    )

    # ie_fingerprint — identity hypothesis policy (D3)
    _bool(cfg, errors, "ie_fingerprint.enabled")
    _num(
        cfg, errors, "ie_fingerprint.min_probe_ssids",
        ok=lambda n: n >= 1, desc=">= 1 (SSIDs)",
    )
    for key in ("candidate_floor", "link_threshold", "relink_alert_floor"):
        _num(
            cfg, errors, f"ie_fingerprint.{key}",
            ok=lambda n: 0.0 <= n <= 1.0, desc="in [0, 1]",
        )
    _num(
        cfg, errors, "ie_fingerprint.min_support",
        ok=lambda n: n >= 1, desc=">= 1 (observations)",
    )
    _num(
        cfg, errors, "ie_fingerprint.co_window_s",
        ok=lambda n: n > 0, desc="> 0 (seconds)",
    )
    _num(
        cfg, errors, "ie_fingerprint.handoff_max_s",
        ok=lambda n: n > 0, desc="> 0 (seconds)",
    )
    found, cf = _get_at(cfg, "ie_fingerprint.candidate_floor")
    found_lt, lt = _get_at(cfg, "ie_fingerprint.link_threshold")
    found_ra, ra = _get_at(cfg, "ie_fingerprint.relink_alert_floor")
    if all((found, found_lt, found_ra)) and all(
        _is_number(x) for x in (cf, lt, ra)
    ):
        if not float(cf) <= float(lt) <= float(ra):
            _add(
                errors,
                "ie_fingerprint.link_threshold",
                "must satisfy candidate_floor <= link_threshold <= "
                f"relink_alert_floor (got {cf} <= {lt} <= {ra})",
                lt,
            )

    # ble_tracker
    _bool(cfg, errors, "ble_tracker.enabled")
    _num(
        cfg, errors, "ble_tracker.min_score",
        ok=lambda n: 0.0 <= n <= 1.0, desc="in [0, 1]",
    )

    # fusion — transparent confidence model (D4, locked decision 8)
    _num(
        cfg, errors, "fusion.min_independent_kinds",
        ok=lambda n: n >= 1, desc=">= 1 (distinct evidence kinds)",
    )
    _num(
        cfg, errors, "fusion.max_confidence",
        ok=lambda n: 0.0 < n <= 1.0, desc="in (0, 1]",
    )
    _num(
        cfg, errors, "fusion.default_weight",
        ok=lambda n: 0.0 <= n <= 1.0, desc="in [0, 1]",
    )
    _str_list(cfg, errors, "fusion.self_ref_kinds")
    _validate_fusion_weights(cfg, errors)

    # rf + detectors
    _bool(cfg, errors, "rf.deauth_enabled")
    _bool(cfg, errors, "rf.rogue_enabled")
    _bool(cfg, errors, "deauth_detection.enabled")
    _num(
        cfg, errors, "deauth_detection.burst_threshold",
        ok=lambda n: n >= 1, desc=">= 1 (frames)",
    )
    _num(
        cfg, errors, "deauth_detection.burst_window_seconds",
        ok=lambda n: n > 0, desc="> 0 (seconds)",
    )
    _num(
        cfg, errors, "deauth_detection.min_events_for_attack",
        ok=lambda n: n >= 1, desc=">= 1 (events)",
    )
    _num(
        cfg, errors, "deauth_detection.attack_window_seconds",
        ok=lambda n: n > 0, desc="> 0 (seconds)",
    )
    _str_list(cfg, errors, "deauth_detection.protected_macs")
    _bool(cfg, errors, "rogue_ap_detection.enabled")
    _bool(cfg, errors, "rogue_ap_detection.auto_learn")
    _str_list(cfg, errors, "rogue_ap_detection.monitored_ssids")
    _str_list(cfg, errors, "rogue_ap_detection.trusted_aps")

    # incidents — legacy dedup window
    _num(
        cfg, errors, "incidents.close_after_seconds",
        ok=lambda n: n > 0, desc="> 0 (seconds)",
    )

    # incidents_v2 — the lifecycle engine's thresholds (mirror the
    # engine's own validation, with key + range in the message). There is
    # no ``enabled`` key: the engine is always on (B1) — a config that
    # still carries the obsolete key now fails as an unknown key, which
    # is the honest outcome for a switch that would no longer do what it
    # claims.
    for key in ("watch_confidence", "alert_confidence"):
        _num(
            cfg, errors, f"incidents_v2.{key}",
            ok=lambda n: 0.0 <= n <= 1.0, desc="in [0, 1]",
        )
    found, watch = _get_at(cfg, "incidents_v2.watch_confidence")
    found_a, alert = _get_at(cfg, "incidents_v2.alert_confidence")
    if (
        found and found_a
        and _is_number(watch) and _is_number(alert)
        and float(alert) < float(watch)
    ):
        _add(
            errors,
            "incidents_v2.alert_confidence",
            f"must be >= watch_confidence ({watch})",
            alert,
        )
    _num(
        cfg, errors, "incidents_v2.alert_min_detectors",
        ok=lambda n: n >= 1, desc=">= 1 (detectors)",
    )
    for key in ("close_after_s", "decay_grace_s", "reopen_resolved_s", "reopen_disposition_s"):
        _num(
            cfg, errors, f"incidents_v2.{key}",
            ok=lambda n: n >= 0.0, desc=">= 0 (seconds)",
        )

    # status — glance file composition
    _str(cfg, errors, "status.file")
    for key in ("stale_seconds", "hold_seconds", "deaf_seconds"):
        _num(cfg, errors, f"status.{key}", ok=lambda n: n > 0, desc="> 0 (seconds)")
    _bool(cfg, errors, "status.deaf_is_fail")
    _bool(cfg, errors, "status.quiet_is_watch")
    _bool(cfg, errors, "status.http_enabled")
    _str(cfg, errors, "status.http_bind")
    _num(
        cfg, errors, "status.http_port",
        ok=lambda n: 1 <= n <= 65535, desc="in [1, 65535]",
    )
    _bool(cfg, errors, "status.expose_total_opens")
    _validate_window_severities(cfg, errors)

    # service
    _bool(cfg, errors, "service.legacy_log_file")
    _bool(cfg, errors, "service.legacy_log_redact")
    _bool(cfg, errors, "service.sd_notify")
    _num(
        cfg, errors, "service.consecutive_fail_threshold",
        ok=lambda n: n >= 1, desc=">= 1 (cycles)",
    )
    _bool(cfg, errors, "service.exit_on_consecutive_fail")
    _bool(cfg, errors, "service.kismet_proc_check")
    _num(
        cfg, errors, "service.watchdog_sec_hint",
        ok=lambda n: n >= 0, desc=">= 0 (seconds)",
    )

    # privacy
    _bool(cfg, errors, "privacy.require_fde_notice")
    _bool(cfg, errors, "privacy.sanitize_errors")
    _bool(cfg, errors, "privacy.status_path_basename_only")
    _str(cfg, errors, "privacy.fde_ack_path")

    # search — geographic bounds
    for key in ("lat_min", "lat_max"):
        _num(
            cfg, errors, f"search.{key}",
            ok=lambda n: -90.0 <= n <= 90.0, desc="in [-90, 90] (latitude)",
        )
    for key in ("lon_min", "lon_max"):
        _num(
            cfg, errors, f"search.{key}",
            ok=lambda n: -180.0 <= n <= 180.0, desc="in [-180, 180] (longitude)",
        )
    found, lat_min = _get_at(cfg, "search.lat_min")
    found_max, lat_max = _get_at(cfg, "search.lat_max")
    if (
        found and found_max
        and _is_number(lat_min) and _is_number(lat_max)
        and float(lat_min) > float(lat_max)
    ):
        _add(
            errors,
            "search.lat_max",
            f"must be >= search.lat_min ({lat_min})",
            lat_max,
        )
    found, lon_min = _get_at(cfg, "search.lon_min")
    found_max, lon_max = _get_at(cfg, "search.lon_max")
    if (
        found and found_max
        and _is_number(lon_min) and _is_number(lon_max)
        and float(lon_min) > float(lon_max)
    ):
        _add(
            errors,
            "search.lon_max",
            f"must be >= search.lon_min ({lon_min})",
            lon_max,
        )

    if errors:
        raise ConfigError(errors)


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
    merged = _deep_merge(DEFAULTS, raw)
    validate_config(merged)
    return merged


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
