"""D9 evidence redaction: hostile subject text must be inert in evidence.

The finding (D7b worker, flagged in PR #14): hostile SSID/device-name
markup reached replay event evidence and status.json incident evidence
unredacted — ``privacy.redact_subject`` had no evidence-path callers.
These tests plant adversarial payloads (script tags, CDATA terminators,
markdown links, control characters, bidi overrides, homoglyph names) via
fixture SSIDs and device names and assert the stored/rendered forms are
redacted or neutralized across the three evidence surfaces:

* replay event evidence (``replay/report.py`` event summary + detail),
* status.json incident evidence (``store.list_open_incident_evidence``),
* fused evidence blocks (``fused_evidence`` JSON + rendered text).

Redaction composes with PR #3's display-field escaping
(``escape_markdown_text``) — it does not replace it; that layer keeps its
own test module (``tests/test_render_escaping.py``).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import escalate_lifecycle
from cyt_platform.detectors import DetectionResult, EvidenceLine, incident_fields
from cyt_platform.fused_evidence import attach as attach_fusion
from cyt_platform.fused_evidence import fused_evidence, render_confidence_block
from cyt_platform.privacy import (
    redact_evidence_object,
    redact_evidence_text,
    redact_subject,
)
from cyt_platform.replay.report import build_report, report_bytes
from cyt_platform.replay.scenario import load_scenario
from cyt_platform.status import StatusEngine
from cyt_platform.store import CytStore

EVIL_SCRIPT = "<script>alert(1)</script>"
EVIL_CDATA = "never]]>gone"
EVIL_LINK = "[link](https://evil.example)"
EVIL_CTRL = "bad\x00\x1f\x07text"
EVIL_BIDI = "dir\u202Egrene\u202C"  # RTL overrides — direction spoof
EVIL_HOMOGLYPH = "аiddеn"  # Cyrillic а/е inside a Latin-looking name

# Payloads whose in-flight form is markup/control text: after evidence
# redaction none of them may survive verbatim, and no markup metacharacter
# may survive at all. (The homoglyph is deliberately NOT here: it is not
# markup, so free-text neutralization leaves its letters — the subject-key
# redaction path is what removes it; see the dedicated tests below.)
HOSTILE_PAYLOADS = [
    EVIL_SCRIPT,
    EVIL_CDATA,
    EVIL_LINK,
    EVIL_CTRL,
    EVIL_BIDI,
]

_MARKUP_CHARS = ("<", ">", "[", "]", "`")


def _assert_no_raw_payloads(rendered: str) -> None:
    """No markup/control payload survives verbatim (safe on JSON dumps)."""
    for payload in HOSTILE_PAYLOADS:
        assert payload not in rendered
    for codepoint in ("\x00", "\x1f", "\u202e", "\u200b"):
        assert codepoint not in rendered


def _assert_inert(rendered: str) -> None:
    """Value-level inertness: no payload, no markup metachar. For
    individual string values / rendered text — NOT for JSON dumps, whose
    own syntax contains brackets."""
    _assert_no_raw_payloads(rendered)
    for char in _MARKUP_CHARS:
        assert char not in rendered


def _iter_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _iter_strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _iter_strings(value)


def _assert_all_strings_inert(obj) -> None:
    """Every string value in evidence-shaped data is inert."""
    for text in _iter_strings(obj):
        _assert_inert(text)


def _hostile_result(observed_at: float, severity: str = "alert") -> DetectionResult:
    """A rogue-AP style result whose free text is fully hostile.

    Models the real ingress: Kismet alert reasons and BLE device names are
    attacker-controlled, and the pre-redaction contract carried them
    verbatim in evidence lines and detail dicts.
    """
    reasons = [
        f"Hostile AP '{EVIL_SCRIPT}' advertising",
        f"beacon text {EVIL_CDATA} embedded",
        f"name/manuf matches tracker pattern ({EVIL_HOMOGLYPH})",
    ]
    return DetectionResult(
        detector="rogue",
        kind="rogue_ap",
        subject="AA:BB:CC:DD:EE:FF",
        subject_type="wifi_ap",
        window_label="ap",
        severity=severity,
        observed_at=observed_at,
        summary=f"rogue_ap ssid_present {EVIL_LINK}",
        detail={
            "ssid_len": len(EVIL_SCRIPT),
            "name": EVIL_HOMOGLYPH,
            "reasons": reasons,
        },
        evidence=tuple(
            EvidenceLine("rogue_reason", reason) for reason in reasons
        ),
        confidence=None,
    )


# --- redact_subject: stable identity redaction --------------------------------------


def test_redact_subject_ssid_digest_is_sha1_derived():
    """The SSID token's digest is sha1-derived, not builtin hash().

    Python's hash() is salted per process (PYTHONHASHSEED); a salted
    digest inside replayed evidence would break byte-identical replay.
    Pins the derivation: 16-bit big-endian sha1 prefix, 4 hex digits.
    """
    subject = "CafeNet"
    digest = hashlib.sha1(subject.encode("utf-8")).digest()
    expected_h = f"{int.from_bytes(digest[:2], 'big'):04x}"
    assert redact_subject(subject, "ssid") == f"ssid(len=7,h={expected_h})"


def test_redact_subject_is_stable_across_hash_seeds():
    """Two processes with different PYTHONHASHSEED agree on the token."""
    code = (
        "from cyt_platform.privacy import redact_subject; "
        "print(redact_subject('CafeNet', 'ssid'))"
    )
    outputs = []
    for seed in ("1", "99"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        run = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        outputs.append(run.stdout.strip())
    assert outputs[0] == outputs[1]
    assert outputs[0].startswith("ssid(len=")


def test_redact_subject_removes_all_hostile_text_including_homoglyphs():
    """Subject fields get the full token treatment: nothing survives."""
    for payload in HOSTILE_PAYLOADS + [EVIL_HOMOGLYPH]:
        token = redact_subject(payload, "ssid")
        assert payload not in token
        _assert_inert(token)


def test_redact_subject_mac_keeps_correlation_suffix():
    assert redact_subject("AA:BB:CC:DD:EE:FF", "mac") == "AA:BB:xx:xx:xx:FF"


def test_redact_subject_empty_is_placeholder():
    assert redact_subject("", "ssid") == "?"


# --- redact_evidence_text: the free-text evidence policy ----------------------------


@pytest.mark.parametrize("payload", HOSTILE_PAYLOADS)
def test_redact_evidence_text_neutralizes_payload(payload):
    out = redact_evidence_text(f"device observed ({payload}) nearby")
    _assert_inert(out)
    # The prose around the payload survives so evidence stays readable.
    assert "device observed" in out


def test_redact_evidence_text_masks_mac_tokens():
    out = redact_evidence_text("device AA:BB:CC:DD:EE:FF near operator")
    assert "AA:BB:CC" not in out  # middle octets gone
    assert "xx:xx" in out
    assert "near operator" in out


def test_redact_evidence_text_collapses_injected_newlines():
    out = redact_evidence_text("line one\x02\x0aFAKE LOG LINE\x0bline two")
    assert "\n" not in out
    assert out == "line one FAKE LOG LINE line two"


def test_redact_evidence_text_passthrough_clean_prose():
    text = "Deauth/disassoc pattern toward AA:BB:xx:xx:xx:FF, 27 frames"
    assert redact_evidence_text(text) == text


# --- fused evidence blocks (Why/Against) ---------------------------------------------


def _assessment(result: DetectionResult):
    from cyt_platform.confidence import fuse

    return fuse([result])


def test_fused_json_block_is_inert():
    result = _hostile_result(time.time())
    block = fused_evidence(_assessment(result))
    _assert_no_raw_payloads(json.dumps(block))
    _assert_all_strings_inert(block)
    # The why lines still cite kinds and weights — redaction must not
    # strip the explainable structure.
    assert block["why"], "hostile payload must not empty the evidence"
    assert any(line["kind"] == "rogue_reason" for line in block["why"])


def test_fused_render_composes_redaction_with_escaping():
    """Order proof: redaction strips markup, escape still runs after it.

    ``&`` is not stripped by redaction but IS escaped by the PR #3 helper
    — its escaped form in the render proves escaping still applies on top
    of redaction.
    """
    result = _hostile_result(time.time())
    text = render_confidence_block(_assessment(result))
    _assert_inert(text)
    assert "Confidence:" in text
    assert "Why:" in text

    amp_result = DetectionResult(
        detector="rogue",
        kind="rogue_ap",
        subject="AA:BB:CC:DD:EE:FF",
        subject_type="wifi_ap",
        window_label="ap",
        severity="watch",
        observed_at=1700000000.0,
        summary="rogue_ap amp",
        detail={},
        evidence=(EvidenceLine("rogue_reason", "signal & noise"),),
        confidence=None,
    )
    amp_text = render_confidence_block(_assessment(amp_result))
    assert "\\&" in amp_text, "escape_markdown_text must still run after redaction"


def test_fused_render_is_deterministic():
    result = _hostile_result(1700000000.0)
    assert render_confidence_block(_assessment(result)) == (
        render_confidence_block(_assessment(result))
    )


def test_attach_block_on_incident_fields_is_inert():
    result = _hostile_result(time.time())
    fields = incident_fields(result, session_id="s")
    attach_fusion(fields, result)
    block = fields["evidence"]["fusion"]
    _assert_no_raw_payloads(json.dumps(block))
    _assert_all_strings_inert(block)


# --- status.json incident evidence path ----------------------------------------------


def _seed_hostile_incident(store: CytStore, now: float) -> None:
    fields = incident_fields(_hostile_result(now), session_id="s")
    attach_fusion(fields, _hostile_result(now))
    store.observe_incident(**fields)


def test_store_evidence_read_redacts_summary_and_block(tmp_path):
    store = CytStore.open({"path": str(tmp_path / "redact.db")})
    try:
        now = time.time()
        _seed_hostile_incident(store, now)
        hits = store.list_open_incident_evidence(hold_seconds=300, limit=5)
        assert hits, "incident must be visible in the evidence window"
        _assert_no_raw_payloads(json.dumps(hits))
        _assert_all_strings_inert(hits)
        # Structure survives redaction.
        block = hits[0]["evidence"]["fusion"]
        assert block["why"], "why lines must survive redaction"
        assert any(line["kind"] == "rogue_reason" for line in block["why"])
        # Free-text reasons stay readable after neutralization (the
        # homoglyph name's letters are inert prose here; the subject-key
        # redaction path is exercised by the replay report test below).
        assert "name/manuf matches tracker pattern" in json.dumps(hits)
    finally:
        store.close()


def test_status_json_written_evidence_is_inert(tmp_path):
    status_path = tmp_path / "run" / "status.json"
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    config = {
        "status": {
            "file": str(status_path),
            "hold_seconds": 300,
            "stale_seconds": 150,
            "deaf_seconds": 180,
            "deaf_is_fail": True,
            "quiet_is_watch": False,
        }
    }
    try:
        store.begin_session()
        with store.transaction():
            store.write_heartbeat("analyzer", ok=True, cycle=1)
        now = time.time()
        _seed_hostile_incident(store, now)
        # B2: detector rows no longer drive status — escalate the
        # phenomenon so the evidence window is hot (watch/alert state).
        with store.transaction():
            escalate_lifecycle(store, "AA:BB:CC:DD:EE:FF", now, "watch")
        engine = StatusEngine(store, config)
        snap = engine.publish(
            cycle=1,
            db_label="x.kismet",
            freshness={
                "max_last_time": now,
                "recent_device_count": 5,
                "age_s": 5,
            },
            consecutive_fails=0,
        )
        assert snap["state"] in ("watch", "alert")
        raw = status_path.read_text()
        _assert_no_raw_payloads(raw)
        _assert_all_strings_inert(json.loads(raw))
    finally:
        store.close()


# --- replay event evidence path -------------------------------------------------------


def _load_corpus_scenario(name: str):
    scenarios_dir = (
        Path(__file__).resolve().parent.parent / "scenarios" / "replay"
    )
    return load_scenario(str(scenarios_dir / name))


def test_replay_report_events_are_inert(tmp_path):
    """Event summary + detail in the replay report are redacted.

    Seeds a real store the way the pipeline does (observe_incident writes
    the events table), then builds the deterministic report over a real
    corpus scenario document.
    """
    scenario = _load_corpus_scenario("cafe-evil-twin.json")
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    try:
        _seed_hostile_incident(store, 1700000000.0)
        report = build_report(scenario, store, [], [])
        assert report["events"], "seeded event must appear in the report"
        _assert_no_raw_payloads(json.dumps(report["events"]))
        _assert_all_strings_inert(report["events"])
        # Subject-key fields inside event detail (BLE-style device names)
        # get the full redact_subject treatment, homoglyphs included.
        assert "ssid(len=" in json.dumps(report["events"])
    finally:
        store.close()


def test_replay_report_bytes_stay_deterministic_with_redaction(tmp_path):
    """Redaction is pure — the report contract keeps its byte-identity."""
    scenario = _load_corpus_scenario("cafe-evil-twin.json")
    store = CytStore.open({"path": str(tmp_path / "cyt.db")})
    try:
        _seed_hostile_incident(store, 1700000000.0)
        report_a = build_report(scenario, store, [], [])
        report_b = build_report(scenario, store, [], [])
        assert report_bytes(report_a) == report_bytes(report_b)
        _assert_no_raw_payloads(report_bytes(report_a).decode("utf-8"))
        _assert_all_strings_inert(report_a)
    finally:
        store.close()


# --- object walker edge cases ----------------------------------------------------------


def test_redact_evidence_object_walks_nested_shapes():
    obj = {
        "reasons": [f"a {EVIL_SCRIPT} b", {"name": EVIL_HOMOGLYPH, "n": 3}],
        "score": 0.9,
        "none": None,
        "ssid": EVIL_LINK,
    }
    out = redact_evidence_object(obj)
    _assert_no_raw_payloads(json.dumps(out))
    _assert_all_strings_inert(out)
    assert out["score"] == 0.9 and out["none"] is None
    assert out["reasons"][1]["n"] == 3
    assert out["ssid"].startswith("ssid(len=")  # subject key fully redacted
    assert out["reasons"][1]["name"].startswith("ssid(len=")
    assert EVIL_HOMOGLYPH not in json.dumps(out)  # name key fully redacted


def test_redact_evidence_object_is_idempotent():
    obj = {"reasons": [f"hostile {EVIL_CDATA}"], "count": 2}
    once = redact_evidence_object(obj)
    twice = redact_evidence_object(once)
    assert json.dumps(twice, sort_keys=True) == json.dumps(once, sort_keys=True)


# --- regression guard: detection semantics untouched -----------------------------------


def test_redaction_does_not_touch_detection_fields():
    """Redaction lives at the evidence surfaces; the stored result's
    severity, confidence, subject identity, and summary stay faithful
    (evidence fidelity is what replay and correlation need)."""
    result = _hostile_result(1700000000.0)
    fields = incident_fields(result, session_id="s")
    assert fields["severity"] == "alert"
    assert fields["subject"] == "AA:BB:CC:DD:EE:FF"
    assert fields["event_type"] == "rogue_ap"
    assert fields["summary"].startswith("rogue_ap ssid_present")
