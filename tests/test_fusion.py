"""D4 confidence fusion: monotonicity, contradiction, alert gate, block.

Covers the acceptance criteria for the explainability core:
  1. fused confidence is monotone in supporting evidence (property test);
  2. the same detections plus one contradictory line fuse to strictly
     lower confidence with a non-empty Against block;
  3. the why/against block renders in alert output (stored evidence ->
     status.json top hits, push body) with every number citing a named
     evidence line, RF-sourced text escaped;
  4. a repetition-only detection never reaches alert severity — the
     product principle, enforced by ``alert_gate`` at fusion level.
"""

from __future__ import annotations

import json
import random
import time
from types import SimpleNamespace

import pytest

from cyt_platform.confidence import (
    FusionConfig,
    alert_gate,
    fuse,
    fuse_by_subject,
)
from cyt_platform.detectors import DetectionResult, EvidenceLine, incident_fields
from cyt_platform.fused_evidence import (
    attach as attach_fusion,
)
from cyt_platform.fused_evidence import (
    fused_evidence,
    render_confidence_block,
)
from input_validation import InputValidator

SUBJECT = "AA:BB:CC:DD:EE:01"


def _result(
    detector="deauth",
    subject=SUBJECT,
    subject_type="wifi_mac",
    kinds=("deauth_pattern", "attack_signature", "source_severity"),
    contra=(),
    confidence=None,
    observed_at=1700000000.0,
    severity="alert",
    **overrides,
):
    """Build a DetectionResult with one evidence line per kind in ``kinds``."""
    kwargs = dict(
        detector=detector,
        kind=overrides.pop("kind", detector),
        subject=subject,
        subject_type=subject_type,
        window_label=overrides.pop("window_label", "test"),
        severity=severity,
        observed_at=observed_at,
        summary=overrides.pop("summary", f"{detector} summary"),
        evidence=tuple(
            EvidenceLine(kind, f"{kind} detail {i}")
            for i, kind in enumerate(kinds)
        ),
        contra=tuple(contra),
        confidence=confidence,
    )
    kwargs.update(overrides)
    return DetectionResult(**kwargs)


# --- 1. monotonicity -------------------------------------------------------------


def test_fused_confidence_is_monotone_in_supporting_evidence():
    """Property: adding supporting evidence never lowers fused confidence."""
    rng = random.Random(1701)  # fixed seed: the property test is deterministic
    table = FusionConfig.from_config(None).weights
    base = fuse([_result()])
    assert base.confidence > 0.0
    results = [_result()]
    for _ in range(50):
        kind = rng.choice(sorted(table))
        results.append(
            _result(
                detector=f"detector{len(results)}",
                kinds=(kind,),
                observed_at=1700000000.0 + len(results),
            )
        )
        fused = fuse(results)
        assert fused.confidence >= base.confidence
        base = fused


def test_repetition_raises_confidence_but_not_independence():
    """More lines of the same kind: confidence rises, kind count does not."""
    first = _result(
        detector="rogue",
        subject="BB:BB:CC:00:11:01",
        subject_type="wifi_ap",
        kinds=("rogue_reason",),
        severity="alert",
    )
    again = _result(
        detector="rogue",
        subject="BB:BB:CC:00:11:01",
        subject_type="wifi_ap",
        kinds=("rogue_reason",),
        severity="alert",
        observed_at=1700000060.0,
        summary="rogue re-observation",
    )
    once = fuse([first])
    twice = fuse([first, again])
    assert twice.confidence > once.confidence
    assert twice.independent_kinds == once.independent_kinds == ("rogue_reason",)
    assert not twice.may_alert


# --- 2. contradiction -------------------------------------------------------------


def test_contradiction_lowers_confidence_and_populates_against():
    """Same detections + one contradictory line: strictly lower confidence,
    non-empty Against."""
    density = EvidenceLine("density", "high ambient density at location #2")
    context = _result(
        detector="context",
        subject_type="wifi_mac",
        kinds=(),
        contra=(density,),
        severity="info",
        summary="ambient context",
    )
    baseline = fuse([_result()])
    contradicted = fuse([_result(), context])
    assert contradicted.against
    assert contradicted.against[0].line.kind == "density"
    assert contradicted.against[0].line.weight < 0
    assert contradicted.confidence < baseline.confidence


def test_contra_line_of_full_weight_zeroes_confidence():
    """A contra weight of 1.0 is a veto: survival reaches zero."""
    context = _result(
        detector="context",
        kinds=(),
        contra=(EvidenceLine("density", "hard veto"),),
        severity="info",
        summary="veto context",
    )
    config = {"fusion": {"weights": {"density": 1.0}}}
    fused = fuse([_result(), context], config=config)
    assert fused.confidence == 0.0


# --- determinism (locked decision 4) -----------------------------------------------


def test_fusion_is_order_independent_and_render_stable():
    """Shuffled input order fuses to identical numbers, ordering, and text."""
    results = [
        _result(),
        _result(
            detector="ble",
            subject_type="ble_tracker",
            kinds=("ble_signal",),
            severity="watch",
        ),
        _result(
            detector="context",
            kinds=(),
            contra=(EvidenceLine("density", "high ambient density"),),
            severity="info",
            summary="ambient context",
        ),
    ]
    forward = fuse(results)
    for permutation in ([2, 0, 1], [1, 2, 0], [2, 1, 0]):
        shuffled = fuse([results[i] for i in permutation])
        assert shuffled.confidence == forward.confidence
        assert shuffled.why == forward.why
        assert shuffled.against == forward.against
        assert shuffled.independent_kinds == forward.independent_kinds
        assert render_confidence_block(shuffled) == render_confidence_block(forward)


# --- 4. repetition-only never alerts -----------------------------------------------


def test_repetition_only_detection_cannot_alert():
    """A single-kind detection may not alert, however many times restated."""
    fused = fuse(
        [
            _result(
                detector="rogue",
                subject="BB:BB:CC:00:11:01",
                subject_type="wifi_ap",
                kinds=("rogue_reason",) * 4,
                severity="alert",
            )
        ]
    )
    assert fused.confidence > 0.0
    assert not fused.may_alert
    assert alert_gate(fused, "alert") == "watch"


def test_multi_kind_detection_survives_the_alert_gate():
    """Deauth-style evidence spans 3 kinds: the gate does not demote."""
    fused = fuse([_result()])
    assert fused.may_alert
    assert alert_gate(fused, "alert") == "alert"


def test_alert_gate_never_upgrades_and_ignores_non_alert():
    """The gate only demotes alerts; watch/info severities pass through."""
    fused = fuse(
        [_result(detector="rogue", subject_type="wifi_ap", kinds=("rogue_reason",))]
    )
    assert not fused.may_alert
    assert alert_gate(fused, "watch") == "watch"
    assert alert_gate(fused, "info") == "info"
    multi = fuse([_result()])
    assert alert_gate(multi, "watch") == "watch"


def test_self_reference_kind_never_counts_as_independent():
    """A detector's own computed score is not evidence for itself."""
    fused = fuse(
        [
            _result(
                detector="ble",
                subject="CC:DD:EE:00:00:01",
                subject_type="ble_tracker",
                kinds=("ble_signal", "score"),
                severity="alert",
            )
        ]
    )
    assert fused.independent_kinds == ("ble_signal",)
    assert not fused.may_alert
    assert alert_gate(fused, "alert") == "watch"


def test_unknown_evidence_kind_is_conservative():
    """Kinds missing from the table contribute weight but not alertability."""
    fused = fuse([_result(kinds=("novel_signal",))])
    assert fused.confidence > 0.0
    assert fused.independent_kinds == ()
    assert not fused.may_alert


# --- config ownership (locked decision 8) ------------------------------------------


def test_weights_are_config_owned():
    """Overrides touch only the kinds they name and change the outcome."""
    default = fuse([_result()])
    boosted = fuse(
        [_result()], config={"fusion": {"weights": {"deauth_pattern": 0.9}}}
    )
    assert boosted.confidence > default.confidence
    rogue = dict(
        detector="rogue",
        subject="BB:BB:CC:00:11:01",
        subject_type="wifi_ap",
        kinds=("rogue_reason",),
    )
    overridden = fuse([_result(**rogue)], config={"fusion": {"weights": {"deauth_pattern": 0.9}}})
    untouched = fuse([_result(**rogue)])
    assert overridden.confidence == untouched.confidence


def test_invalid_fusion_config_names_the_key():
    with pytest.raises(ValueError, match="fusion.weights.deauth_pattern"):
        fuse([_result()], config={"fusion": {"weights": {"deauth_pattern": 2.0}}})
    with pytest.raises(ValueError, match="fusion.min_independent_kinds"):
        fuse([_result()], config={"fusion": {"min_independent_kinds": 0}})
    with pytest.raises(ValueError, match="fusion.max_confidence"):
        fuse([_result()], config={"fusion": {"max_confidence": 1.5}})


# --- 3. the explainable block -------------------------------------------------------


def test_explain_block_renders_named_evidence_lines():
    """Every number in the block cites a named evidence line (kind + weight)."""
    fused = fuse(
        [
            _result(),
            _result(
                detector="context",
                kinds=(),
                contra=(EvidenceLine("density", "high ambient density at location #2"),),
                severity="info",
                summary="ambient context",
            ),
        ]
    )
    block = render_confidence_block(fused)
    lines = block.splitlines()
    assert lines[0].startswith("Confidence: ")
    assert f"{fused.confidence:.0%}" in lines[0]
    assert "Why:" in lines
    assert "Against:" in lines
    for contribution in fused.why:
        expected = f"  + {contribution.line.kind} {contribution.line.weight:+.2f}"
        assert expected in block
        assert contribution.line.detail in block
    for contribution in fused.against:
        expected = f"  - {contribution.line.kind} {contribution.line.weight:+.2f}"
        assert expected in block
        assert contribution.line.detail in block


def test_explain_block_escapes_hostile_rf_text():
    """Script/CDATA/markdown-link payloads render inert (escaped)."""
    hostile = (
        "<script>alert(1)</script> never]]>gone [link](https://evil.example)"
    )
    fused = fuse([_result(kinds=(hostile,))])
    block = render_confidence_block(fused)
    assert "<script>" not in block
    assert "]]>" not in block
    assert "[link](" not in block
    assert InputValidator.escape_markdown_text(hostile) in block


def test_fused_evidence_block_is_json_safe_and_preserves_keys():
    """The stored block adds keys without touching legacy evidence fields."""
    fields = incident_fields(_result(), session_id="s")
    original_reasons = fields["evidence"]["reasons"]
    attach_fusion(fields, _result())
    block = fields["evidence"]["fusion"]
    assert fields["evidence"]["reasons"] == original_reasons
    assert fields["evidence"]["kind"] == "deauth"
    assert json.loads(json.dumps(fields)) == fields
    assert block["may_alert"] is True
    assert 0.0 < block["confidence"] <= 0.99
    assert block["independent_kinds"] == [
        "attack_signature",
        "deauth_pattern",
        "source_severity",
    ]
    # The stored block is exactly the module's block for the fused
    # assessment (deterministic fusion makes the fresh rebuild equal).
    assert block == fused_evidence(fuse([_result()]))


# --- alert output surfaces -----------------------------------------------------------


def test_fused_block_reaches_status_alert_output(tmp_path):
    """The block an operator sees via status.json's evidence carries the
    fused why/against with weights intact."""
    from cyt_platform.store import CytStore

    store = CytStore.open({"path": str(tmp_path / "fusion.db")})
    now = time.time()
    fields = incident_fields(
        _result(observed_at=now, severity="alert"), session_id="s"
    )
    attach_fusion(fields, _result(observed_at=now, severity="alert"))
    store.observe_incident(**fields)

    top_hits = store.list_open_incident_evidence(hold_seconds=300, limit=5)
    assert top_hits, "incident must be visible in the status evidence window"
    block = top_hits[0]["evidence"]["fusion"]
    assert block["may_alert"] is True
    assert block["confidence"] > 0.0
    assert any(line["kind"] == "deauth_pattern" for line in block["why"])
    assert "Confidence:" in block["text"]
    store.close()


def test_runner_emit_carries_fused_block(tmp_path):
    """Wiring: a deauth attack through RFPluginRunner stores the block."""
    from cyt_platform.rf_plugins import RFPluginRunner
    from cyt_platform.store import CytStore

    store = CytStore.open({"path": str(tmp_path / "runner.db")})
    config = {
        "rf": {"deauth_enabled": False, "rogue_enabled": False},
        "ie_fingerprint": {"enabled": False},
        "ble_tracker": {"enabled": False},
        "gps_fusion": {"enabled": False},
    }
    runner = RFPluginRunner(store, config)
    attack = SimpleNamespace(
        target_mac="AA:BB:CC:00:00:42",
        attacker_mac="de:ad:be:ef:00:01",
        attack_type="deauth_flood",
        total_frames=27,
        severity="HIGH",
        last_seen=1700000000.0,
    )
    runner.deauth = SimpleNamespace(
        last_scan_error=None,
        scan_kismet_db=lambda db_path, now=None: [],
        analyze_attacks=lambda: [attack],
    )
    runner.run_cycle(kdb=None, db_path="unused", now=1700000000.0)

    row = store.conn.execute(
        "SELECT evidence_json FROM incidents WHERE event_type='deauth_attack'"
    ).fetchone()
    assert row is not None
    block = json.loads(row["evidence_json"])["fusion"]
    assert block["may_alert"] is True
    assert block["detectors"] == ["deauth"]
    assert any(line["kind"] == "attack_signature" for line in block["why"])
    store.close()


def test_push_body_renders_alert_with_fusion_block_present(tmp_path):
    """The push path renders legacy reasons; the fusion block coexists."""
    from cyt_platform.push import PushQueue
    from cyt_platform.store import CytStore

    store = CytStore.open({"path": str(tmp_path / "push.db")})
    queue = PushQueue(
        store,
        {"push": {"enabled": True, "backend": "log", "min_severity": "alert"}},
    )
    fields = incident_fields(
        _result(observed_at=time.time(), severity="alert"), session_id="s"
    )
    attach_fusion(fields, _result(observed_at=time.time(), severity="alert"))
    snapshot = {
        "state": "alert",
        "reason": "test",
        "counts": {"alert_open": 1, "watch_open": 0},
        "evidence": [
            {
                "severity": "alert",
                "summary": fields["summary"],
                "evidence": fields["evidence"],
            }
        ],
    }
    assert queue.enqueue_from_status(snapshot) == 1
    store.close()


# --- fuse_by_subject / validation -----------------------------------------------------


def test_fuse_by_subject_groups_and_fuses():
    ble = _result(
        detector="ble",
        subject="CC:DD:EE:00:00:01",
        subject_type="ble_tracker",
        kinds=("ble_signal",),
    )
    context = _result(
        detector="context",
        kinds=(),
        contra=(EvidenceLine("density", "dense"),),
        severity="info",
        summary="ctx",
    )
    fused = fuse_by_subject([_result(), ble, context])
    assert set(fused) == {SUBJECT, "CC:DD:EE:00:00:01"}
    assert fused[SUBJECT].against  # the context contra landed on its subject
    assert fused[SUBJECT].may_alert
    assert not fused["CC:DD:EE:00:00:01"].may_alert


def test_fuse_rejects_mixed_subjects_and_empty():
    with pytest.raises(ValueError, match="one subject"):
        fuse([_result(), _result(subject="DD:EE:FF:00:00:01")])
    assert fuse([]) is None
