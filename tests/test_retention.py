"""D8 retention: class-driven purge on every table + real space reclamation."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyt_platform.store import CytStore, RETENTION_CLASSES

BASE = 1_700_000_000.0
DAYS = 86400
BULK_OBS = 600  # enough rows to grow the DB well past one page


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
