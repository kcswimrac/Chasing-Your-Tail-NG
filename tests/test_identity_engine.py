"""D3 engine tests — IEFingerprintEngine over the hypothesis store.

Acceptance 5 (task todo_p3CrtoSG): ``ie_relink`` confidence maps from the
hypothesis score — the incident detail carries the stored hypothesis
confidence and the severity follows ``identity.relink_severity``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyt_platform.identity import (
    STATUS_CANDIDATE,
    STATUS_LINKED,
    STATUS_REJECTED,
    relink_severity,
)
from cyt_platform.ie_fingerprint import IEFingerprintEngine
from cyt_platform.store import CytStore

MAC_A = "AA:BB:CC:00:00:01"
MAC_B = "AA:BB:CC:00:00:02"


def _dev(mac, ssids=("HomeNet", "CafeWiFi", "GymWiFi"), first=None, last=None):
    dot11 = {
        "dot11.device.probed_ssid_map": {
            s: {"dot11.probedssid.ssid": s} for s in ssids
        },
        "dot11.device.last_probed_ssid_record": {"dot11.probedssid.ssid": ssids[0]},
        # simple top-level tag plus a nested tag map: exercises the walker's
        # recursion (the old ``pass`` placeholder dropped these)
        "dot11.device.ie_tag": 1,
        "dot11.device.ie_tag_map": {
            "tag_a": {"tag_number": 5},
            "tag_b": {"tag_number": 7},
        },
    }
    if first is not None:
        dot11["kismet.device.base.first_time"] = first
    if last is not None:
        dot11["kismet.device.base.last_time"] = last
    return {"mac": mac, "device_data": {"dot11.device": dot11}}


@pytest.fixture
def store(tmp_path: Path):
    s = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    s.begin_session()
    yield s
    s.close()


def _relink_incidents(store):
    rows = store.conn.execute(
        "SELECT severity, detail_json, evidence_json FROM incidents "
        "WHERE event_type = 'ie_relink'"
    ).fetchall()
    return [
        {
            "severity": r["severity"],
            "detail": json.loads(r["detail_json"]),
            "evidence": json.loads(r["evidence_json"]),
        }
        for r in rows
    ]


def test_ie_relink_confidence_maps_from_hypothesis(store):
    eng = IEFingerprintEngine(store, {"ie_fingerprint": {"enabled": True, "min_probe_ssids": 1}})
    with store.transaction():
        n1 = eng.process_devices([_dev(MAC_A, first=1000.0, last=1000.0)], now=1000.0)
        n2 = eng.process_devices([_dev(MAC_B, first=1100.0, last=1100.0)], now=1100.0)
    assert n1 >= 1 and n2 >= 1  # first-sighting entity-fingerprint links

    hyps = store.list_identity_hypotheses(status=STATUS_LINKED)
    assert len(hyps) == 1
    hyp = hyps[0]
    assert {hyp["key_a"], hyp["key_b"]} == {MAC_A, MAC_B}

    incidents = _relink_incidents(store)
    assert len(incidents) == 1
    inc = incidents[0]
    # confidence and severity derive from the stored hypothesis score
    assert inc["detail"]["confidence"] == pytest.approx(hyp["confidence"], abs=1e-6)
    assert inc["severity"] == relink_severity(hyp["confidence"], hyp["reasons"])
    assert inc["severity"] == "watch"  # 0.45+0.12+0.25+0.075 = 0.895, no spatial
    # evidence cites hypothesis ids and carries no MAC/SSID text
    assert hyp["hypothesis_id"] in inc["evidence"]["hypothesis_ids"]
    blob = json.dumps(inc)
    assert MAC_A not in blob and MAC_B not in blob
    assert "HomeNet" not in blob and "CafeWiFi" not in blob

    # entity-fingerprint bookkeeping rows carry the earned confidence
    conf = store.conn.execute(
        "SELECT MAX(confidence) AS c FROM entity_fingerprints"
    ).fetchone()["c"]
    assert conf == pytest.approx(hyp["confidence"], abs=1e-6)


def test_collision_pair_stays_candidate_without_relink(store):
    eng = IEFingerprintEngine(store, {"ie_fingerprint": {"enabled": True, "min_probe_ssids": 1}})
    with store.transaction():
        n1 = eng.process_devices(
            [_dev(MAC_A, ssids=("Solo",), first=1000.0, last=1000.0)], now=1000.0
        )
        n2 = eng.process_devices(
            [_dev(MAC_B, ssids=("Solo",), first=1100.0, last=1100.0)], now=1100.0
        )
    assert n1 >= 1 and n2 >= 1
    hyps = store.list_identity_hypotheses()
    assert len(hyps) == 1
    assert hyps[0]["status"] == STATUS_CANDIDATE  # one shared SSID: collision
    assert _relink_incidents(store) == []


def test_config_override_raises_link_threshold(store):
    eng = IEFingerprintEngine(
        store,
        {"ie_fingerprint": {"enabled": True, "min_probe_ssids": 1, "link_threshold": 0.95}},
    )
    with store.transaction():
        eng.process_devices([_dev(MAC_A, first=1000.0, last=1000.0)], now=1000.0)
        eng.process_devices([_dev(MAC_B, first=1100.0, last=1100.0)], now=1100.0)
    hyps = store.list_identity_hypotheses()
    assert len(hyps) == 1
    assert hyps[0]["status"] == STATUS_CANDIDATE  # 0.895 < raised threshold
    assert _relink_incidents(store) == []


def test_co_observed_history_vetoes_link(store):
    """Observation-store history that shows co-presence vetoes the link."""
    eng = IEFingerprintEngine(store, {"ie_fingerprint": {"enabled": True, "min_probe_ssids": 1}})
    with store.transaction():
        # both identities observed live at the same time in prior cycles
        for mac in (MAC_A, MAC_B):
            store.record_observation(
                source="kismet.devices",
                kind="wifi_device",
                identity_key=mac,
                ts=900.0,
                cycle_id=1,
                source_ref=f"kismet:fixture:{mac}",
                input_digest=f"digest-{mac}",
                payload={"ssid_count": 3},
            )
        eng.process_devices([_dev(MAC_A)], now=1000.0)
        eng.process_devices([_dev(MAC_B)], now=1100.0)

    # S15: the veto is persisted as a sticky rejected hypothesis — the
    # contradiction must outlive observation retention — but it never links
    # and never files a relink incident.
    hyps = store.list_identity_hypotheses()
    assert len(hyps) == 1
    assert hyps[0]["status"] == STATUS_REJECTED
    assert _relink_incidents(store) == []


def test_disabled_engine_is_inert(store):
    eng = IEFingerprintEngine(store, {"ie_fingerprint": {"enabled": False}})
    with store.transaction():
        assert eng.process_devices([_dev(MAC_A)], now=1000.0) == 0
    assert store.list_identity_hypotheses() == []
    assert _relink_incidents(store) == []
