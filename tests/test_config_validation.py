"""D10 config validation: invalid values rejected with key + reason + range.

Every error must be actionable: the message names the exact config key,
why it is wrong, and the acceptable range — never a bare traceback. The
shipped configs are pinned as valid so a deployed install cannot be
stranded by the validator, and DEFAULTS are pinned as self-consistent.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from cyt_platform.config import (
    DEFAULTS,
    ConfigError,
    load_json,
    validate_config,
)

REPO = Path(__file__).resolve().parent.parent


def overridden(**sections) -> dict:
    """DEFAULTS with whole sections (or dotted leaves) replaced.

    Dotted paths may name sections DEFAULTS does not carry (the
    incidents_v2 engine knobs) — missing intermediates are created.
    """
    cfg = copy.deepcopy(DEFAULTS)
    for dotted, value in sections.items():
        node = cfg
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return cfg


def assert_actionable(exc: ConfigError, key_fragment: str, range_fragment: str):
    """The error names the key and states the acceptable range."""
    text = str(exc)
    assert key_fragment in text, text
    assert range_fragment in text, text


# --- the shipped configurations and defaults stay valid ----------------------


def test_defaults_validate_clean():
    validate_config(copy.deepcopy(DEFAULTS))


def test_shipped_config_json_validates_clean():
    load_json(str(REPO / "config.json"))


def test_shipped_config_edc_json_validates_clean():
    load_json(str(REPO / "config.edc.json"))


def test_valid_config_returns_none():
    validate_config(copy.deepcopy(DEFAULTS))  # must not raise


# --- the error contract ------------------------------------------------------


def test_errors_name_key_reason_and_range():
    cfg = overridden(**{"store.retention_days": 0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "store.retention_days", ">= 1")


def test_all_problems_reported_in_one_message():
    cfg = overridden(
        **{
            "store.retention_days": 0,
            "fusion.weights": {"deauth_pattern": 0.35, "density": 1.5},
        }
    )
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    text = str(exc.value)
    assert "store.retention_days" in text
    assert "fusion.weights.density" in text


def test_configerror_is_a_valueerror():
    # load_json callers already catch ValueError; ConfigError must ride
    # that contract, not invent a new one.
    assert issubclass(ConfigError, ValueError)


def test_load_json_rejects_invalid_file(tmp_path: Path):
    bad = copy.deepcopy(DEFAULTS)
    bad["status"]["http_port"] = 70000
    path = tmp_path / "config.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_json(str(path))
    assert "status.http_port" in str(exc.value)


# --- fusion weights (D4) ------------------------------------------------------


@pytest.mark.parametrize("weight", [0, -0.2, 1.01, "high", True])
def test_fusion_weight_out_of_unit_interval_rejected(weight):
    cfg = overridden(**{"fusion.weights": {"deauth_pattern": weight}})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "fusion.weights.deauth_pattern", "(0, 1]")


def test_fusion_weight_of_one_is_valid():
    validate_config(overridden(**{"fusion.weights": {"deauth_pattern": 1.0}}))


def test_empty_fusion_weights_rejected():
    cfg = overridden(**{"fusion.weights": {}})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "fusion.weights", "at least one")


@pytest.mark.parametrize(
    "key, bad",
    [
        ("fusion.max_confidence", 0.0),
        ("fusion.max_confidence", 1.5),
        ("fusion.default_weight", -0.1),
        ("fusion.default_weight", 1.2),
    ],
)
def test_fusion_scalars_out_of_range_rejected(key, bad):
    section, leaf = key.split(".")
    cfg = overridden(**{f"{section}.{leaf}": bad})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert key in str(exc.value)


def test_min_independent_kinds_below_one_rejected():
    cfg = overridden(**{"fusion.min_independent_kinds": 0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "fusion.min_independent_kinds", ">= 1")


def test_self_ref_kinds_must_be_strings():
    cfg = overridden(**{"fusion.self_ref_kinds": ["score", 7]})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "fusion.self_ref_kinds", "list of strings")


# --- retention / seal windows -------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "store.retention_days",
        "store.heartbeat_keep_days",
        "store.entity_retention_days",
        "store.seal_every_cycles",
    ],
)
def test_retention_windows_below_one_rejected(key):
    section, leaf = key.split(".")
    cfg = overridden(**{f"{section}.{leaf}": 0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, key, ">= 1")


def test_unknown_store_synchronous_rejected():
    # The store would otherwise silently fall back to NORMAL — the exact
    # silent-wrong-config behavior this validation exists to kill.
    cfg = overridden(**{"store.synchronous": "Sometimes"})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "store.synchronous", "normal")


def test_unknown_store_mode_rejected():
    cfg = overridden(**{"store.mode": "persistent"})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "store.mode", "durable")


# --- replay / incident windows -------------------------------------------------


@pytest.mark.parametrize("bad", [0, -1])
def test_close_after_seconds_positive(bad):
    cfg = overridden(**{"incidents.close_after_seconds": bad})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "incidents.close_after_seconds", "> 0")


@pytest.mark.parametrize(
    "key",
    ["close_after_s", "decay_grace_s", "reopen_resolved_s", "reopen_disposition_s"],
)
def test_incidents_v2_windows_non_negative(key):
    cfg = overridden(**{f"incidents_v2.{key}": -1.0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, f"incidents_v2.{key}", ">= 0")


def test_incidents_v2_alert_below_watch_rejected():
    cfg = overridden(
        **{
            "incidents_v2.enabled": True,
            "incidents_v2.watch_confidence": 0.5,
            "incidents_v2.alert_confidence": 0.3,
        }
    )
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "incidents_v2.alert_confidence", ">= watch_confidence")


@pytest.mark.parametrize("bad", [-0.1, 1.1])
def test_incidents_v2_confidences_in_unit_interval(bad):
    cfg = overridden(**{"incidents_v2.watch_confidence": bad})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "incidents_v2.watch_confidence", "[0, 1]")


# --- detection thresholds ------------------------------------------------------


def test_gps_fusion_threshold_bounds():
    for bad in (-0.01, 1.01):
        cfg = overridden(**{"gps_fusion.incident_score_threshold": bad})
        with pytest.raises(ConfigError) as exc:
            validate_config(cfg)
        assert "gps_fusion.incident_score_threshold" in str(exc.value)


def test_min_locations_for_cotravel_needs_two():
    cfg = overridden(**{"gps_fusion.min_locations_for_cotravel": 1})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "gps_fusion.min_locations_for_cotravel", ">= 2")


def test_max_speed_must_be_positive():
    cfg = overridden(**{"gps_fusion.max_speed_mps": 0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "gps_fusion.max_speed_mps", "> 0")


def test_merge_radius_allows_null_but_not_zero():
    validate_config(overridden(**{"gps_fusion.merge_radius_m": None}))
    with pytest.raises(ConfigError) as exc:
        validate_config(overridden(**{"gps_fusion.merge_radius_m": 0}))
    assert "gps_fusion.merge_radius_m" in str(exc.value)


def test_ble_min_score_bounds():
    for bad in (-0.1, 1.5):
        cfg = overridden(**{"ble_tracker.min_score": bad})
        with pytest.raises(ConfigError) as exc:
            validate_config(cfg)
        assert "ble_tracker.min_score" in str(exc.value)


def test_deauth_burst_threshold_positive():
    cfg = overridden(**{"deauth_detection.burst_threshold": 0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "deauth_detection.burst_threshold", ">= 1")


# --- identity hypothesis floors (D3) -------------------------------------------


def test_identity_floor_ordering_enforced():
    cfg = overridden(
        **{
            "ie_fingerprint.candidate_floor": 0.5,
            "ie_fingerprint.link_threshold": 0.4,
            "ie_fingerprint.relink_alert_floor": 0.9,
        }
    )
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "ie_fingerprint.link_threshold", "candidate_floor")


def test_identity_floors_unit_interval():
    cfg = overridden(**{"ie_fingerprint.link_threshold": 1.4})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "ie_fingerprint.link_threshold", "[0, 1]")


# --- timing windows -------------------------------------------------------------


def test_time_windows_must_be_strictly_increasing():
    cfg = overridden(
        **{
            "timing.time_windows": {
                "recent": 5,
                "medium": 10,
                "old": 8,
                "oldest": 20,
            }
        }
    )
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "timing.time_windows.old", "medium")


# --- push policy -----------------------------------------------------------------


def test_push_min_severity_enum():
    # An unknown severity ranks 0 in push._sev_rank: everything would
    # enqueue. Rejected outright.
    cfg = overridden(**{"push.min_severity": "urgent"})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "push.min_severity", "watch")


def test_push_backend_enum():
    cfg = overridden(**{"push.backend": "telegram"})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "push.backend", "ntfy")


# --- status composition ------------------------------------------------------------


def test_http_port_range():
    for bad in (0, 65536):
        cfg = overridden(**{"status.http_port": bad})
        with pytest.raises(ConfigError) as exc:
            validate_config(cfg)
        assert "status.http_port" in str(exc.value)


def test_window_to_severity_values_constrained():
    cfg = overridden(
        **{"status.window_to_severity": {"5-10": "watch", "10-15": "catastrophic"}}
    )
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "status.window_to_severity.10-15", "watch")


def test_window_to_severity_labels_are_free_form():
    # Window labels are user-defined; a custom label with a valid
    # severity must not be flagged.
    cfg = overridden(**{"status.window_to_severity": {"3-7": "watch"}})
    validate_config(cfg)


# --- search bounds -------------------------------------------------------------------


def test_search_latitude_bounds():
    cfg = overridden(**{"search.lat_min": 91.0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "search.lat_min", "[-90, 90]")


def test_search_lon_max_below_lon_min_rejected():
    cfg = overridden(**{"search.lon_min": -100.0, "search.lon_max": -110.0})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "search.lon_max", "lon_min")


# --- baseline places -----------------------------------------------------------------


def test_place_hours_within_day_bounds():
    cfg = copy.deepcopy(DEFAULTS)
    cfg["baseline"]["places"]["home"] = {
        "name": "Home",
        "radius_m": 150,
        "hours": [[25, 2]],
    }
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "baseline.places.home.hours", "0..24")


def test_place_radius_positive():
    cfg = copy.deepcopy(DEFAULTS)
    cfg["baseline"]["places"]["work"] = {"radius_m": -5}
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "baseline.places.work.radius_m", "> 0")


# --- unknown keys ----------------------------------------------------------------------


def test_unknown_top_level_key_rejected():
    cfg = overridden(**{"kismet_db_path": "/tmp/x.kismet"})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "kismet_db_path", "unknown configuration key")


def test_unknown_nested_key_rejected():
    cfg = overridden(**{"store": {**DEFAULTS["store"], "retention_day": 14}})
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "store.retention_day", "unknown configuration key")


def test_known_extra_keys_are_not_flagged():
    # incidents_v2 thresholds and the GPS dropout knobs are consumed by
    # code though absent from DEFAULTS — they must validate, not reject.
    # (The engine is always on now; the obsolete "enabled" key is rejected.)
    cfg = overridden(
        **{
            "incidents_v2": {"watch_confidence": 0.30},
            "gps_fusion": {**DEFAULTS["gps_fusion"], "dropout_seconds": 900.0},
        }
    )
    validate_config(cfg)


def test_non_object_section_rejected():
    cfg = copy.deepcopy(DEFAULTS)
    cfg["push"] = "enabled"
    with pytest.raises(ConfigError) as exc:
        validate_config(cfg)
    assert_actionable(exc.value, "push", "must be an object")
