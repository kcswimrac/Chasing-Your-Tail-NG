"""D8 retention: class-driven purge on every table + real space reclamation."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyt_platform.detectors import DetectionResult, EvidenceLine, incident_fields
from cyt_platform.fused_evidence import attach as attach_fusion
from cyt_platform.incidents import IncidentEngine, IncidentStatus
from cyt_platform.store import CytStore, RETENTION_CLASSES

BASE = 1_700_000_000.0
DAYS = 86400
BULK_OBS = 600  # enough rows to grow the DB well past one page
MAC = "AA:BB:CC:00:00:42"


@pytest.fixture
def store(tmp_path: Path):
    s = CytStore.open(
        {
            "path": str(tmp_path / "retention.db"),
            "retention_days": 14,
            "heartbeat_keep_days": 7,
            "entity_retention_days": 30,
            "observation_retention_days": 7,
        }
    )
    yield s
    s.close()


def count(store: CytStore, table: str) -> int:
    return int(
        store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    )


def test_every_table_has_a_retention_class(store: CytStore):
    tables = {
        r[0]
        for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    # A new table without a class fails the build: retention must be a
    # decision, never a default.
    assert tables == set(RETENTION_CLASSES)


def test_auto_vacuum_incremental_enabled(store: CytStore):
    av = int(store.conn.execute("PRAGMA auto_vacuum").fetchone()[0])
    assert av == 2  # 0=NONE, 1=FULL, 2=INCREMENTAL


def seed_old_data(store: CytStore) -> None:
    """One OLD row in every purgeable table; bulk observations for pages."""
    session = store.begin_session()
    with store.transaction():
        for i in range(BULK_OBS):
            store.record_observation(
                ts=BASE + i,
                source="kismet.devices",
                kind="wifi_device",
                identity_key=f"AA:BB:CC:{i // 256:02X}:{i % 256:02X}:01",
                cycle_id=1,
                source_ref=f"kismet:devices:{i}",
                input_digest=f"digest-{i}",
                payload={"rssi": -50 - (i % 40), "pad": "x" * 2048},
            )
        # entities + incidents + events (observe_incident creates all three)
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:00:00:01",
            window_label="5-10",
            severity="watch",
            session_id=session,
            observed_at=BASE,
            summary="old closed incident",
        )
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:00:00:02",
            window_label="5-10",
            severity="watch",
            session_id=session,
            observed_at=BASE,
            summary="old open incident",
        )
        # An ignored entity is operator-confirmed: never purged.
        store.upsert_entity("wifi_mac", "AA:BB:CC:00:00:03", BASE)
        store.conn.execute(
            "UPDATE entities SET ignore=1 WHERE entity_type='wifi_mac' "
            "AND key='AA:BB:CC:00:00:03'"
        )
        store.record_location_sighting(
            "wifi_mac", "AA:BB:CC:00:00:04", "loc-old", 52.0, 13.0, BASE
        )
        store.upsert_cotravel(
            "wifi_mac",
            "AA:BB:CC:00:00:05",
            location_count=3,
            score=0.8,
            first_seen=BASE,
            last_seen=BASE,
        )
        fp_old = store.upsert_fingerprint("ie", "fp-old", {"tags": 1}, BASE)
        store.link_entity_fingerprint(1, fp_old, 0.5)
        store.bump_baseline_sighting("place", "wifi_mac", "AA:BB:CC:00:00:06", BASE)

        # Tables whose helpers stamp time.time() internally: backdate by SQL.
        for _ in range(20):
            store.write_heartbeat("analyzer", ok=True, cycle=1)
        store.append_status_history("clear", "seed", {})
        store.enqueue_push(severity="watch", title="t", body="b")
    store.close_stale_incidents(BASE + 10, close_after_seconds=5)
    with store.transaction():
        # close_stale closed both; reopen the second as a live incident
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:00:00:02",
            window_label="5-10",
            severity="watch",
            session_id=session,
            observed_at=BASE + 11,
            summary="old open incident",
        )
        store.conn.execute("UPDATE heartbeats SET ts = ?", (BASE,))
        store.conn.execute("UPDATE status_history SET ts = ?", (BASE,))
        store.conn.execute(
            "UPDATE push_queue SET sent_ts = ?, status='sent'", (BASE,)
        )
        store.conn.execute("UPDATE entity_fingerprints SET linked_ts = ?", (BASE,))


def test_purge_removes_only_expired_rows_per_class(store: CytStore):
    seed_old_data(store)
    fresh = BASE + 100 * DAYS
    with store.transaction():
        store.record_observation(
            ts=fresh - 60,
            source="kismet.devices",
            kind="wifi_device",
            identity_key="AA:BB:CC:FF:FF:FF",
            cycle_id=99,
            source_ref="kismet:devices:fresh",
            input_digest="digest-fresh",
        )
        store.enqueue_push(severity="watch", title="pending", body="b")  # unsent

    counts = store.purge_retention(now=fresh)

    # --- row counts after purge, per table ---
    assert count(store, "observations") == 1  # fresh kept, 600 old purged
    assert counts["observations"] == BULK_OBS
    assert count(store, "heartbeats") == 0
    assert counts["heartbeats"] == 20
    assert count(store, "status_history") == 0
    assert count(store, "events") == 0  # opened+closed+reopen, all expired
    assert count(store, "location_sightings") == 0
    assert count(store, "cotravel") == 0
    assert count(store, "fingerprints") == 0
    assert count(store, "entity_fingerprints") == 0
    assert count(store, "baseline_sightings") == 0
    # entities: expired non-ignored purged, EXCEPT the subject of the
    # still-open incident, which is pinned by its FK reference. The
    # ignored entity survives because operator dispositions are kept.
    assert count(store, "entities") == 2
    # incidents: closed expired purged; the re-opened one survives
    assert count(store, "incidents") == 1
    assert store.conn.execute(
        "SELECT COUNT(*) FROM push_queue WHERE status='pending'"
    ).fetchone()[0] == 1
    assert counts["push_sent"] == 1

    # --- keep-class tables are never purged ---
    assert count(store, "baselines") == 1
    assert count(store, "runtime_state") >= 1
    assert count(store, "schema_meta") == 1


def test_purge_reclaims_pages(store: CytStore):
    seed_old_data(store)
    pages_with_data = int(
        store.conn.execute("PRAGMA page_count").fetchone()[0]
    )
    assert pages_with_data > 10  # bulk data really grew the file

    store.purge_retention(now=BASE + 100 * DAYS)
    stats = store.vacuum_incremental(max_pages=1_000_000)

    assert stats["freelist_before"] > 0  # purge freed pages onto the freelist
    assert stats["page_count"] < pages_with_data  # file actually shrank
    assert stats["freelist_count"] < stats["freelist_before"]


def test_vacuum_incremental_refuses_inside_transaction(store: CytStore):
    with store.transaction():
        with pytest.raises(RuntimeError):
            store.vacuum_incremental()


def test_purge_noop_when_nothing_expired(store: CytStore):
    seed_old_data(store)
    # A "now" before every timestamp must purge nothing and touch nothing.
    counts = store.purge_retention(now=BASE - DAYS)
    assert sum(counts.values()) == 0
    assert count(store, "observations") == BULK_OBS
    assert count(store, "incidents") == 2


def test_hypothesis_retention_only_stale_candidates(store: CytStore):
    """candidate class: stale candidates go; linked/rejected are load-bearing."""
    fresh = BASE + 100 * DAYS
    ent_cut = fresh - 30 * DAYS  # matches purge's entity cutoff
    store.upsert_identity_hypothesis(
        key_a="AA:00:00:00:00:01",
        key_b="AA:00:00:00:00:02",
        confidence=0.4,
        status="candidate",
        reasons=["probe-SSID Jaccard 0.4"],
        ts=ent_cut - 1,  # stale candidate → purged
    )
    store.upsert_identity_hypothesis(
        key_a="AA:00:00:00:00:03",
        key_b="AA:00:00:00:00:04",
        confidence=0.5,
        status="candidate",
        reasons=[],
        ts=fresh - 60,  # fresh candidate → kept
    )
    store.upsert_identity_hypothesis(
        key_a="AA:00:00:00:00:05",
        key_b="AA:00:00:00:00:06",
        confidence=0.86,
        status="linked",
        reasons=["co-observed never"],
        ts=ent_cut - 1,  # stale linked → kept (detection joins depend on it)
    )
    store.upsert_identity_hypothesis(
        key_a="AA:00:00:00:00:07",
        key_b="AA:00:00:00:00:08",
        confidence=0.0,
        status="rejected",
        reasons=["co-observation veto"],
        ts=ent_cut - 1,  # stale rejected → kept (prevents relink churn)
    )

    counts = store.purge_retention(now=fresh)

    assert counts["identity_hypotheses"] == 1
    remaining = {
        (r["key_a"], r["key_b"], r["status"])
        for r in store.conn.execute(
            "SELECT key_a, key_b, status FROM identity_hypotheses"
        ).fetchall()
    }
    assert remaining == {
        ("AA:00:00:00:00:03", "AA:00:00:00:00:04", "candidate"),
        ("AA:00:00:00:00:05", "AA:00:00:00:00:06", "linked"),
        ("AA:00:00:00:00:07", "AA:00:00:00:00:08", "rejected"),
    }


# --- S14: purge over engine-managed incidents (timeline children) ----------

V2_CFG = {
    "fusion": {"weights": {"window_match": 0.5, "cotravel_visit": 0.5}},
    "incidents_v2": {
        "enabled": True,
        "watch_confidence": 0.30,
        "alert_confidence": 0.60,
        "alert_min_detectors": 2,
        "close_after_s": 600.0,
        "decay_grace_s": 120.0,
    },
}


def _close_engine_incident_through_disposition(store: CytStore) -> str:
    """Drive one real phenomenon incident to a closed disposition.

    Uses the exact emit path contract detectors use (incident_fields +
    fusion attach + observe_incident), so the incident goes through real
    lifecycle transitions and carries incident_timeline and
    incident_contributions children — the shape test fixtures never
    created before S14.
    """
    engine = IncidentEngine(store, V2_CFG)

    def emit(detector: str, kind: str) -> None:
        result = DetectionResult(
            detector=detector,
            kind=detector,
            subject=MAC,
            subject_type="wifi_mac",
            window_label="15-20",
            severity="watch",
            observed_at=BASE,
            summary=f"{detector} on {MAC}",
            evidence=(EvidenceLine(kind, f"{kind} detail"),),
        )
        fields = incident_fields(result, session_id="sess-purge")
        attach_fusion(fields, result)
        store.observe_incident(**fields)

    emit("mac_reappear", "window_match")
    emit("cotravel", "cotravel_visit")
    plans = engine.apply(now=BASE)
    assert plans, "fixture failed to drive lifecycle transitions"

    ph = store.conn.execute(
        "SELECT incident_key, lifecycle_state FROM incidents "
        "WHERE phenomenon_key IS NOT NULL"
    ).fetchone()
    assert ph is not None and ph["lifecycle_state"] == "alert"
    key = ph["incident_key"]
    engine.dispose(key, IncidentStatus.KNOWN_DEVICE, BASE + 2)
    return key


def test_purge_survives_engine_managed_incident_with_timeline(store: CytStore):
    """S14: a closed lifecycle incident purges cleanly under foreign_keys=ON.

    purge_retention used to delete the parent incidents row before its
    incident_timeline/incident_contributions children; with immediate
    foreign keys that raised IntegrityError on the first closed lifecycle
    incident — and in the service, rolled back the whole per-cycle
    transaction every tenth cycle.
    """
    fk = int(store.conn.execute("PRAGMA foreign_keys").fetchone()[0])
    assert fk == 1, "test is meaningless without the production pragma"

    key = _close_engine_incident_through_disposition(store)
    closed = store.conn.execute(
        "SELECT id, status, closed_at FROM incidents WHERE incident_key=?", (key,)
    ).fetchone()
    assert closed["status"] == "closed" and closed["closed_at"] is not None
    iid = int(closed["id"])
    timeline_before = int(
        store.conn.execute(
            "SELECT COUNT(*) FROM incident_timeline WHERE incident_id=?", (iid,)
        ).fetchone()[0]
    )
    contribs_before = int(
        store.conn.execute(
            "SELECT COUNT(*) FROM incident_contributions WHERE incident_id=?", (iid,)
        ).fetchone()[0]
    )
    assert timeline_before >= 2, "fixture produced no lifecycle transitions"
    assert contribs_before >= 1

    counts = store.purge_retention(now=BASE + 15 * DAYS)

    assert counts["incidents"] == 1  # the closed phenomenon row
    assert counts["incident_timeline"] == timeline_before
    assert counts["incident_contributions"] == contribs_before
    # The closed lifecycle incident and its audit children are gone.
    assert count(store, "incident_timeline") == 0
    assert count(store, "incident_contributions") == 0
    assert count(store, "incidents") == 2
    # Open detector-owned rows are not purge candidates — they survive,
    # and no phenomenon row is left behind.
    remaining = store.conn.execute(
        "SELECT COUNT(*) FROM incidents "
        "WHERE lifecycle_state IS NULL AND status='open'"
    ).fetchone()[0]
    assert int(remaining) == 2
    assert (
        store.conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE phenomenon_key IS NOT NULL"
        ).fetchone()[0]
        == 0
    )
