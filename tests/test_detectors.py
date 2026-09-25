"""D6 detector contracts: DetectionResult + EvidenceLine + incident_fields."""

from __future__ import annotations

import json

import pytest

from cyt_platform.detectors import (
    DetectionResult,
    EvidenceLine,
    incident_fields,
)


def make_result(**overrides):
    kwargs = {
        "detector": "ble_tracker",
        "kind": "ble_tracker",
        "subject": "AA:BB:CC:DD:EE:FF",
        "subject_type": "ble_tracker",
        "window_label": "ble",
        "severity": "alert",
        "observed_at": 1700000000.0,
        "summary": "ble_tracker score=0.80",
        "detail": {"score": 0.8},
        "evidence": (
            EvidenceLine("ble_phy", "BLE/BTLE PHY", obs_ids=(3, 7), weight=0.25),
            EvidenceLine("tracker_name_match", "name/manuf matches tracker pattern"),
        ),
        "contra": (EvidenceLine("density", "42 other devices co-observed"),),
        "confidence": 0.8,
        "subject_fp": 12345,
    }
    kwargs.update(overrides)
    return DetectionResult(**kwargs)


# --- capture-scan adapters (rf_plugins) ------------------------------------------


def _deauth_attack(**overrides):
    from types import SimpleNamespace

    kwargs = {
        "target_mac": "AA:BB:CC:00:00:42",
        "attacker_mac": "de:ad:be:ef:00:01",
        "attack_type": "deauth_flood",
        "total_frames": 27,
        "severity": "HIGH",
        "last_seen": 1699999994.0,
    }
    kwargs.update(overrides)
    return SimpleNamespace(**kwargs)


def test_deauth_result_maps_attack_to_contract():
    from cyt_platform.rf_plugins import _deauth_result

    result = _deauth_result(_deauth_attack(), now=1700000000.0)
    assert result.detector == "deauth"
    assert result.kind == "deauth_attack"
    assert result.subject == "AA:BB:CC:00:00:42"
    assert result.subject_type == "wifi_mac"
    assert result.window_label == "deauth"
    assert result.severity == "alert"
    assert result.observed_at == 1699999994.0
    assert result.detail == {
        "attacker": "DE:AD:BE:EF:00:01",
        "frames": 27,
        "severity_raw": "HIGH",
    }
    assert [line.kind for line in result.evidence] == [
        "deauth_pattern",
        "attack_signature",
        "source_severity",
    ]
    assert result.confidence is None


def test_deauth_result_severity_and_clock_fallbacks():
    from cyt_platform.rf_plugins import _deauth_result

    result = _deauth_result(
        _deauth_attack(severity="LOW", last_seen=0.0), now=1700000000.0
    )
    assert result.severity == "watch"
    # Falsy last_seen falls back to the cycle clock (pre-contract behavior).
    assert result.observed_at == 1700000000.0


def test_deauth_result_reasons_are_the_precontract_strings():
    from cyt_platform.rf_plugins import _deauth_result

    result = _deauth_result(_deauth_attack(), now=1700000000.0)
    fields = incident_fields(result, session_id="s")
    assert fields["evidence"]["reasons"] == [
        "Deauth/disassoc pattern toward AA:BB:CC:00:00:42",
        "type=deauth_flood frames=27",
        "source severity=HIGH",
    ]


# --- validation ---------------------------------------------------------------


def test_evidence_line_defaults():
    line = EvidenceLine("copresence", "co-located at 2 distinct places")
    assert line.obs_ids == ()
    assert line.weight == 0.0


def test_evidence_line_rejects_blank_fields():
    with pytest.raises(ValueError, match="kind"):
        EvidenceLine("  ", "detail")
    with pytest.raises(ValueError, match="detail"):
        EvidenceLine("kind", "")


def test_detection_result_rejects_empty_required_fields():
    for field_name in (
        "detector",
        "kind",
        "subject",
        "subject_type",
        "window_label",
        "severity",
        "summary",
    ):
        with pytest.raises(ValueError, match=field_name):
            make_result(**{field_name: "  "})


def test_detection_result_rejects_nonfinite_observed_at():
    with pytest.raises(ValueError, match="observed_at"):
        make_result(observed_at=float("nan"))


def test_detection_result_rejects_out_of_range_confidence():
    with pytest.raises(ValueError, match="confidence"):
        make_result(confidence=1.5)
    with pytest.raises(ValueError, match="confidence"):
        make_result(confidence=-0.1)


def test_detection_result_confidence_none_is_allowed():
    # Detectors without a computed score (deauth/rogue) carry None until the
    # D4 confidence model assigns one.
    result = make_result(confidence=None)
    assert result.confidence is None


def test_detection_result_copies_detail():
    detail = {"score": 0.8}
    result = make_result(detail=detail)
    detail["score"] = 0.1
    assert result.detail["score"] == 0.8


# --- incident_fields conversion -------------------------------------------------


def test_incident_fields_maps_all_observe_incident_kwargs():
    fields = incident_fields(make_result(), session_id="sess-1")
    assert fields["event_type"] == "ble_tracker"
    assert fields["subject"] == "AA:BB:CC:DD:EE:FF"
    assert fields["entity_type"] == "ble_tracker"
    assert fields["window_label"] == "ble"
    assert fields["severity"] == "alert"
    assert fields["session_id"] == "sess-1"
    assert fields["observed_at"] == 1700000000.0
    assert fields["summary"] == "ble_tracker score=0.80"
    assert fields["detail"] == {"score": 0.8}


def test_incident_fields_reasons_track_evidence_details():
    result = make_result()
    fields = incident_fields(result, session_id="s")
    assert fields["evidence"]["reasons"] == [
        line.detail for line in result.evidence
    ]


def test_incident_fields_evidence_lines_are_json_safe():
    fields = incident_fields(make_result(), session_id="s")
    lines = fields["evidence"]["evidence_lines"]
    assert lines[0] == {
        "kind": "ble_phy",
        "detail": "BLE/BTLE PHY",
        "obs_ids": [3, 7],
        "weight": 0.25,
    }
    assert fields["evidence"]["contra"] == [
        {
            "kind": "density",
            "detail": "42 other devices co-observed",
            "obs_ids": [],
            "weight": 0.0,
        }
    ]
    # The whole evidence payload must survive a JSON round-trip (store writes
    # it as evidence_json).
    assert json.loads(json.dumps(fields["evidence"])) == fields["evidence"]


def test_incident_fields_subject_fp_omitted_when_none():
    fields = incident_fields(make_result(subject_fp=None), session_id="s")
    assert "subject_fp" not in fields["evidence"]
    assert incident_fields(make_result(), session_id="s")["evidence"][
        "subject_fp"
    ] == 12345
