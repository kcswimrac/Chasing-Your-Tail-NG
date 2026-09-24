"""D3 identity hypothesis layer tests — scoring rules + persistence.

Acceptance mapping (task todo_p3CrtoSG):
  1. strong-signal pair links >= threshold        -> test_strong_pair_links
  2. weak pair stays candidate                    -> test_weak_pair_stays_candidate
  3. co-observed pair never links                 -> test_co_observed_pair_never_links
  4. single-shared-SSID collision stays candidate -> test_single_shared_ssid_collision_stays_candidate
  5. ie_relink confidence maps from hypothesis    -> tests in test_identity_engine.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cyt_platform.identity import (
    CANDIDATE_FLOOR,
    LINK_THRESHOLD,
    RELINK_ALERT_FLOOR,
    STATUS_CANDIDATE,
    STATUS_LINKED,
    STATUS_REJECTED,
    DeviceView,
    LinkContext,
    hypothesis_id,
    relink_severity,
    score_link,
)
from cyt_platform.store import CytStore

# Fixed clock so every assertion is deterministic.
CTX = LinkContext(now=1000.0)


def _view(
    mac: str,
    *,
    ssids: tuple = (),
    tags: tuple = (),
    first=None,
    last=None,
    count=None,
    locs: tuple = (),
) -> DeviceView:
    return DeviceView(
        identity_key=mac,
        probe_ssids=ssids,
        ie_tags=tags,
        first_ts=first,
        last_ts=last,
        seen_count=count
        if count is not None
        else (1 if (first is not None or last is not None or ssids) else 0),
        locations=locs,
    )


# --- acceptance 1: strong pair links ---------------------------------------


def test_strong_pair_links():
    a = _view("AA", ssids=("home", "cafe", "gym"), tags=(1, 5, 11), first=100.0, last=100.0)
    b = _view("BB", ssids=("home", "cafe", "gym"), tags=(1, 5, 11), first=200.0, last=200.0)
    hyp = score_link(a, b, CTX)
    assert hyp is not None
    assert hyp.status == STATUS_LINKED
    assert hyp.confidence >= LINK_THRESHOLD
    # hypothesis id is order-independent and deterministic
    assert hyp.hypothesis_id == hypothesis_id("BB", "AA")
    # reasons cite the evidence that produced the number
    assert any("probe-SSID Jaccard" in r for r in hyp.reasons)
    assert all("CafeWiFi" not in r for r in hyp.reasons)  # no raw SSID text


def test_strong_pair_links_with_presence_corroboration():
    # fingerprint evidence + temporal handoff + spatial continuity -> near-certain
    a = _view(
        "AA",
        ssids=("home", "cafe", "gym"),
        tags=(1, 5, 11),
        first=100.0,
        last=400.0,
        count=4,
        locs=((33.4, -112.0),),
    )
    b = _view(
        "BB",
        ssids=("home", "cafe", "gym"),
        tags=(1, 5, 11),
        first=450.0,
        last=750.0,
        count=4,
        locs=((33.4, -112.0), (33.4001, -112.0001)),
    )
    hyp = score_link(a, b, CTX)
    assert hyp is not None
    assert hyp.status == STATUS_LINKED
    assert hyp.confidence > 0.9
    assert relink_severity(hyp.confidence, hyp.reasons) == "alert"


# --- acceptance 2: weak pair stays candidate --------------------------------


def test_weak_pair_stays_candidate():
    # one shared SSID pair of several, one shared tag: some signal, not enough
    a = _view("AA", ssids=("home", "cafe", "office"), tags=(1,), first=100.0, last=100.0)
    b = _view("BB", ssids=("cafe", "gym", "market"), tags=(1,), first=200.0, last=200.0)
    hyp = score_link(a, b, CTX)
    assert hyp is not None
    assert hyp.status == STATUS_CANDIDATE
    assert CANDIDATE_FLOOR <= hyp.confidence < LINK_THRESHOLD


def test_below_floor_returns_none():
    a = _view("AA", ssids=("a", "b"), first=100.0, last=100.0)
    b = _view("BB", ssids=("c", "d"), first=200.0, last=200.0)
    assert score_link(a, b, CTX) is None


def test_scoring_is_deterministic_and_symmetric():
    a = _view("AA", ssids=("home", "cafe"), tags=(1, 5, 11), first=100.0, last=100.0)
    b = _view("BB", ssids=("home", "cafe"), tags=(1, 5, 11), first=200.0, last=200.0)
    h1 = score_link(a, b, CTX)
    h2 = score_link(a, b, CTX)
    hb = score_link(b, a, CTX)
    assert h1 == h2  # same inputs -> identical hypothesis
    assert hb is not None and h1 is not None
    assert hb.hypothesis_id == h1.hypothesis_id
    assert hb.confidence == h1.confidence
    assert hb.reasons == h1.reasons


def test_confidence_varies_with_evidence_strength():
    weak = score_link(
        _view("AA", ssids=("home", "cafe"), tags=(1,)),
        _view("BB", ssids=("cafe", "gym"), tags=(1,)),
        CTX,
    )
    strong = score_link(
        _view("AA", ssids=("home", "cafe", "gym", "work"), tags=(1, 5, 11)),
        _view("BB", ssids=("home", "cafe", "gym", "work"), tags=(1, 5, 11)),
        CTX,
    )
    assert weak is not None and strong is not None
    assert weak.confidence < strong.confidence
    assert weak.status == STATUS_CANDIDATE
    assert strong.status == STATUS_LINKED


# --- acceptance 3: co-observed pair never links ------------------------------


def test_co_observed_pair_never_links():
    # overlapping presence spans: two radios seen live can never be one device
    a = _view("AA", ssids=("home", "cafe", "gym"), tags=(1, 5, 11), first=100.0, last=180.0)
    b = _view("BB", ssids=("home", "cafe", "gym"), tags=(1, 5, 11), first=150.0, last=260.0)
    assert score_link(a, b, CTX) is None


def test_within_co_window_pair_never_links():
    # even identical fingerprints with a 10s gap: effectively simultaneous
    a = _view("AA", ssids=("home", "cafe"), tags=(1, 5), first=100.0, last=100.0)
    b = _view("BB", ssids=("home", "cafe"), tags=(1, 5), first=110.0, last=110.0)
    assert score_link(a, b, CTX) is None


def test_temporal_handoff_scores_but_long_gap_does_not():
    a = _view("AA", ssids=("home", "cafe"), tags=(1, 5), first=100.0, last=100.0)
    near = _view("BB", ssids=("home", "cafe"), tags=(1, 5), first=200.0, last=200.0)
    far = _view(
        "BB", ssids=("home", "cafe"), tags=(1, 5), first=100.0 + 3600.0, last=100.0 + 3600.0
    )
    hyp_near = score_link(a, near, CTX)
    assert hyp_near is not None
    assert any("temporal handoff" in r for r in hyp_near.reasons)
    hyp_far = score_link(a, far, CTX)
    assert hyp_far is not None
    assert not any("temporal handoff" in r for r in hyp_far.reasons)


# --- acceptance 4: single-shared-SSID collision ------------------------------


def test_single_shared_ssid_collision_stays_candidate():
    # identical single-SSID probe sets (default-router collision): never links
    a = _view("AA", ssids=("linksys",), tags=(1, 5), first=100.0, last=100.0)
    b = _view("BB", ssids=("linksys",), tags=(1, 5), first=200.0, last=200.0)
    hyp = score_link(a, b, CTX)
    assert hyp is not None
    assert hyp.status == STATUS_CANDIDATE

    # even with every other signal maximized, one shared SSID cannot link
    c = _view(
        "CC", ssids=("linksys",), tags=(1, 5), first=100.0, last=400.0, count=4,
        locs=((33.4, -112.0),),
    )
    d = _view(
        "DD", ssids=("linksys",), tags=(1, 5), first=450.0, last=750.0, count=4,
        locs=((33.4, -112.0),),
    )
    hyp2 = score_link(c, d, CTX)
    assert hyp2 is not None
    # non-SSID evidence (spatial + cadence + handoff) can push raw confidence
    # past the threshold, but the min_support guard keeps the collision from
    # linking: one shared SSID is never sufficient for LINKED status.
    assert hyp2.status == STATUS_CANDIDATE
    assert hyp2.confidence < 1.0


# --- severity mapping --------------------------------------------------------


def test_relink_severity_mapping():
    assert relink_severity(0.5, []) == "info"
    # fingerprint evidence alone: watch even when confidence is very high
    assert relink_severity(0.80, ["probe-SSID Jaccard 1.00 (3 shared)"]) == "watch"
    assert relink_severity(0.99, ["probe-SSID Jaccard 1.00 (4 shared)"]) == "watch"
    # alert needs presence corroboration (temporal or spatial) on top
    assert (
        relink_severity(
            0.99, ["probe-SSID Jaccard 1.00 (4 shared)", "temporal handoff x2 (gap within 300s)"]
        )
        == "alert"
    )
    assert relink_severity(RELINK_ALERT_FLOOR, ["spatial continuity 1.00 (within 50m)"]) == "alert"


# --- store persistence (additive CytStore methods) ---------------------------


@pytest.fixture
def store(tmp_path: Path):
    s = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    yield s
    s.close()


def test_hypothesis_persistence_merge_rules(store):
    first = store.upsert_identity_hypothesis(
        key_a="AA:01",
        key_b="BB:02",
        confidence=0.45,
        status=STATUS_CANDIDATE,
        reasons=["probe-SSID Jaccard 0.33 (1 shared)"],
        ts=100.0,
    )
    assert first["status"] == STATUS_CANDIDATE
    assert first["created_ts"] == 100.0
    assert first["key_a"] == "AA:01" and first["key_b"] == "BB:02"

    # reversed key order lands on the same row (canonical pair id)
    second = store.upsert_identity_hypothesis(
        key_a="BB:02",
        key_b="AA:01",
        confidence=0.85,
        status=STATUS_LINKED,
        reasons=["probe-SSID Jaccard 1.00 (3 shared)"],
        ts=200.0,
    )
    assert second["hypothesis_id"] == first["hypothesis_id"]
    assert second["status"] == STATUS_LINKED
    assert second["confidence"] == pytest.approx(0.85)
    assert second["created_ts"] == 100.0  # created_ts preserved on update

    # a later weak score does not downgrade
    third = store.upsert_identity_hypothesis(
        key_a="AA:01",
        key_b="BB:02",
        confidence=0.40,
        status=STATUS_CANDIDATE,
        reasons=["probe-SSID Jaccard 0.20 (1 shared)"],
        ts=300.0,
    )
    assert third["status"] == STATUS_LINKED
    assert third["confidence"] == pytest.approx(0.85)

    # a co-observation veto demotes and is sticky
    veto = store.upsert_identity_hypothesis(
        key_a="AA:01",
        key_b="BB:02",
        confidence=0.0,
        status=STATUS_REJECTED,
        reasons=["co-observed simultaneously"],
        ts=400.0,
    )
    assert veto["status"] == STATUS_REJECTED
    assert veto["confidence"] == 0.0
    again = store.upsert_identity_hypothesis(
        key_a="AA:01",
        key_b="BB:02",
        confidence=0.99,
        status=STATUS_LINKED,
        reasons=["probe-SSID Jaccard 1.00 (4 shared)"],
        ts=500.0,
    )
    assert again["status"] == STATUS_REJECTED


def test_hypothesis_store_validation(store):
    with pytest.raises(ValueError):
        store.upsert_identity_hypothesis(
            key_a="AA", key_b="AA", confidence=0.5, status=STATUS_CANDIDATE, reasons=[], ts=1.0
        )
    with pytest.raises(ValueError):
        store.upsert_identity_hypothesis(
            key_a="AA", key_b="BB", confidence=0.5, status="bogus", reasons=[], ts=1.0
        )


def test_hypothesis_listing_and_lookup(store):
    store.upsert_identity_hypothesis(
        key_a="AA",
        key_b="BB",
        confidence=0.85,
        status=STATUS_LINKED,
        reasons=["probe-SSID Jaccard 1.00 (3 shared)"],
        ts=1.0,
    )
    store.upsert_identity_hypothesis(
        key_a="CC",
        key_b="DD",
        confidence=0.40,
        status=STATUS_CANDIDATE,
        reasons=["probe-SSID Jaccard 0.50 (2 shared)"],
        ts=2.0,
    )
    assert len(store.list_identity_hypotheses()) == 2
    assert len(store.list_identity_hypotheses(status=STATUS_LINKED)) == 1
    by_key = store.list_identity_hypotheses(key="DD")
    assert len(by_key) == 1 and by_key[0]["key_a"] == "CC"
    got = store.get_identity_hypothesis(hypothesis_id("BB", "AA"))
    assert got is not None and got["status"] == STATUS_LINKED
    assert store.get_identity_hypothesis("nonexistent") is None


def test_identity_hypotheses_table_is_idempotent_v4(tmp_path: Path):
    """Table comes back after deletion, with schema version still at 4."""
    cfg = {"path": str(tmp_path / "cyt.db"), "mode": "durable"}
    store = CytStore.open(cfg)
    store.conn.execute("DROP TABLE identity_hypotheses")
    store.close()

    reopened = CytStore.open(cfg)
    try:
        cols = [
            r["name"]
            for r in reopened.conn.execute("PRAGMA table_info(identity_hypotheses)").fetchall()
        ]
        assert "hypothesis_id" in cols and "status" in cols
        version = reopened.conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'"
        ).fetchone()["value"]
        assert int(version) == 4  # v4 completion, not a new schema version
    finally:
        reopened.close()


def test_macs_for_fingerprint_returns_decrypted_keys(store):
    eid = store.upsert_entity("wifi_mac", "AA:BB:CC:DD:EE:01", 100.0)
    fid = store.upsert_fingerprint("ie_probe", "fp-hash-1", {"probe_ssids": ["x"]}, 100.0)
    store.link_entity_fingerprint(eid, fid, confidence=0.5)
    assert store.macs_for_fingerprint(fid) == ["AA:BB:CC:DD:EE:01"]
    assert store.macs_for_fingerprint(999999) == []


def test_score_link_identity_hypothesis_roundtrip(store):
    """score_link output persists through the store contract unchanged."""
    hyp = score_link(
        _view("AA", ssids=("home", "cafe", "gym"), tags=(1, 5, 11), first=100.0, last=100.0),
        _view("BB", ssids=("home", "cafe", "gym"), tags=(1, 5, 11), first=200.0, last=200.0),
        CTX,
    )
    assert hyp is not None
    stored = store.upsert_identity_hypothesis(
        key_a=hyp.key_a,
        key_b=hyp.key_b,
        confidence=hyp.confidence,
        status=hyp.status,
        reasons=list(hyp.reasons),
        ts=CTX.now,
    )
    assert stored["hypothesis_id"] == hyp.hypothesis_id
    assert stored["confidence"] == pytest.approx(hyp.confidence)
    assert stored["reasons"] == list(hyp.reasons)
    assert stored["status"] == hyp.status
