"""Schema v4 + canonical observation store tests (D1)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from cyt_platform import observations as obs
from cyt_platform.kismet_ro import connect_readonly
from cyt_platform.store import CytStore, SCHEMA_V1


@pytest.fixture
def store(tmp_path: Path):
    cfg = {
        "path": str(tmp_path / "cyt.db"),
        "synchronous": "NORMAL",
        "retention_days": 14,
        "heartbeat_keep_days": 7,
        "entity_retention_days": 30,
        "mode": "durable",
    }
    s = CytStore.open(cfg)
    yield s
    s.close()


def _legacy_fixture(tmp_path: Path, version: int) -> Path:
    """Build a populated database that stops at schema v2 or v3."""
    db_path = tmp_path / f"legacy_v{version}.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_V1)
    c = conn.cursor()
    # Reuse the store's own historical migration steps so the fixture matches
    # what a real v2/v3 deployment's file looks like.
    scratch = CytStore.open({"path": str(tmp_path / "scratch.db")})
    try:
        if version >= 2:
            scratch._migrate_v2(c)
        if version >= 3:
            scratch._migrate_v3(c)
    finally:
        scratch.conn.close()
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('version', ?)",
        (str(version),),
    )
    # Populate every table that exists at this schema version.
    conn.execute(
        "INSERT INTO entities(entity_type, key, first_seen, last_seen) "
        "VALUES ('wifi_mac', 'AA:BB:CC:DD:EE:01', 100.0, 200.0)"
    )
    conn.execute(
        "INSERT INTO incidents(incident_key, entity_id, event_type, window_label, "
        "severity, session_id, first_seen, last_seen, observation_count, status, "
        "summary) VALUES ('mac_reappear|AA|5-10|s1', 1, 'mac_reappear', '5-10', "
        "'watch', 's1', 100.0, 100.0, 3, 'open', 'legacy incident')"
    )
    conn.execute(
        "INSERT INTO events(ts, event_type, incident_id, entity_id, severity, summary) "
        "VALUES (100.0, 'incident_opened', 1, 1, 'watch', 'legacy incident')"
    )
    conn.execute(
        "INSERT INTO heartbeats(component, ts, ok) VALUES ('analyzer', 100.0, 1)"
    )
    conn.execute(
        "INSERT INTO runtime_state(key, value, ts) VALUES ('session_id', 's1', 100.0)"
    )
    conn.execute(
        "INSERT INTO status_history(ts, state, reason, snapshot_json) "
        "VALUES (100.0, 'clear', 'ok', '{}')"
    )
    if version >= 2:
        conn.execute(
            "INSERT INTO baselines(place_id, entity_type, entity_key, first_seen, "
            "last_seen, sighting_count, source) "
            "VALUES ('home', 'wifi_mac', 'AA:BB:CC:DD:EE:02', 50.0, 50.0, 2, 'learned')"
        )
        conn.execute(
            "INSERT INTO baseline_sightings(place_id, entity_type, entity_key, ts) "
            "VALUES ('home', 'wifi_mac', 'AA:BB:CC:DD:EE:02', 50.0)"
        )
        conn.execute(
            "UPDATE incidents SET suppressed=0, evidence_json='{\"k\":1}' "
            "WHERE id=1"
        )
    if version >= 3:
        conn.execute(
            "INSERT INTO push_queue(created_ts, severity, title, body, status) "
            "VALUES (100.0, 'watch', 'legacy title', 'body', 'pending')"
        )
        conn.execute(
            "INSERT INTO location_sightings(entity_type, entity_key, location_id, "
            "lat, lon, first_seen, last_seen) "
            "VALUES ('wifi_mac', 'AA:BB:CC:DD:EE:01', 'g_1.0_2.0', 1.0, 2.0, 100.0, 100.0)"
        )
        conn.execute(
            "INSERT INTO cotravel(entity_type, entity_key, location_count, score, "
            "first_seen, last_seen) "
            "VALUES ('wifi_mac', 'AA:BB:CC:DD:EE:01', 2, 0.5, 100.0, 100.0)"
        )
        conn.execute(
            "INSERT INTO fingerprints(fingerprint_type, fingerprint_hash, "
            "first_seen, last_seen) VALUES ('probe_ssid', 'fp_hash', 100.0, 100.0)"
        )
        conn.execute(
            "INSERT INTO entity_fingerprints(entity_id, fingerprint_id, confidence, "
            "linked_ts) VALUES (1, 1, 0.7, 100.0)"
        )
    conn.commit()
    conn.close()
    return db_path


def _legacy_cfg(db_path: Path) -> dict:
    return {
        "path": str(db_path),
        "synchronous": "NORMAL",
        "retention_days": 14,
        "heartbeat_keep_days": 7,
        "entity_retention_days": 30,
        "mode": "durable",
    }


# --- migration (acceptance 1 + 2) ---


def test_fresh_init_lands_on_v4(store: CytStore):
    row = store.conn.execute(
        "SELECT value FROM schema_meta WHERE key='version'"
    ).fetchone()
    assert row["value"] == "4"
    tables = {
        r["name"]
        for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "observations" in tables
    triggers = {
        r["name"]
        for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
    }
    assert "trg_observations_no_update" in triggers


@pytest.mark.parametrize("legacy_version", [2, 3])
def test_legacy_migration_preserves_rows(tmp_path: Path, legacy_version: int):
    db_path = _legacy_fixture(tmp_path, legacy_version)
    store = CytStore.open(_legacy_cfg(db_path))
    try:
        row = store.conn.execute(
            "SELECT value FROM schema_meta WHERE key='version'"
        ).fetchone()
        assert row["value"] == "4"

        # Every pre-existing row survived the v{legacy_version} -> v4 upgrade.
        entity = store.conn.execute(
            "SELECT entity_type, key, last_seen FROM entities WHERE id=1"
        ).fetchone()
        assert entity["key"] == "AA:BB:CC:DD:EE:01"
        assert entity["last_seen"] == 200.0
        incident = store.conn.execute(
            "SELECT summary, status FROM incidents WHERE id=1"
        ).fetchone()
        assert incident["summary"] == "legacy incident"
        assert incident["status"] == "open"
        assert (
            store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        )
        baseline = store.conn.execute(
            "SELECT sighting_count, source FROM baselines WHERE place_id='home'"
        ).fetchone()
        assert baseline["sighting_count"] == 2
        assert baseline["source"] == "learned"
        if legacy_version >= 3:
            push = store.conn.execute(
                "SELECT title, status FROM push_queue WHERE id=1"
            ).fetchone()
            assert push["title"] == "legacy title"
            assert push["status"] == "pending"
            cotravel = store.conn.execute(
                "SELECT score FROM cotravel WHERE entity_key='AA:BB:CC:DD:EE:01'"
            ).fetchone()
            assert cotravel["score"] == 0.5

        # The new table is live on the migrated database.
        obs_id = store.record_observation(
            ts=300.0,
            source=obs.SOURCE_KISMET_DEVICES,
            kind=obs.KIND_WIFI_DEVICE,
            identity_key="AA:BB:CC:DD:EE:01",
            cycle_id=1,
            source_ref="kismet:abc:devices:devid=1",
            input_digest="d" * 64,
        )
        assert obs_id == 1
    finally:
        store.close()


# --- record / read round trip (acceptance 3) ---


def test_record_and_read_back_identical(store: CytStore):
    payload = {"rssi": -58.0, "channel": "6", "ssid_count": 3}
    obs_id = store.record_observation(
        ts=1758732000.5,
        source=obs.SOURCE_KISMET_DEVICES,
        kind=obs.KIND_WIFI_DEVICE,
        identity_key="AA:BB:CC:DD:EE:FF",
        cycle_id=7,
        source_ref="kismet:0123abcd5678:devices:devid=1234",
        input_digest="ab" * 32,
        lat=33.5104,
        lon=-86.8744,
        accuracy_m=12.0,
        payload=payload,
        session_id="sess-1",
        recorded_ts=1758732001.0,
    )
    got = store.get_observation(obs_id)
    assert got is not None
    assert got["ts"] == 1758732000.5
    assert got["recorded_ts"] == 1758732001.0
    assert got["source"] == "kismet.devices"
    assert got["kind"] == "wifi_device"
    assert got["identity_key"] == "AA:BB:CC:DD:EE:FF"
    assert got["cycle_id"] == 7
    assert got["source_ref"] == "kismet:0123abcd5678:devices:devid=1234"
    assert got["input_digest"] == "ab" * 32
    assert got["lat"] == 33.5104
    assert got["lon"] == -86.8744
    assert got["accuracy_m"] == 12.0
    assert got["payload"] == payload
    assert got["session_id"] == "sess-1"


def test_record_minimal_observation(store: CytStore):
    obs_id = store.record_observation(
        ts=100.0,
        source=obs.SOURCE_GPS,
        kind=obs.KIND_GPS_FIX,
        identity_key=obs.OPERATOR_IDENTITY,
        cycle_id=1,
        source_ref="gps:fix:100.0",
        input_digest="cd" * 32,
    )
    got = store.get_observation(obs_id)
    assert got["lat"] is None
    assert got["lon"] is None
    assert got["detector"] is None
    assert got["payload"] is None
    assert got["session_id"] is None


# --- provenance enforcement (acceptance 5) ---


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ts": None},
        {"source": ""},
        {"source": None},
        {"kind": ""},
        {"kind": None},
        {"identity_key": ""},
        {"identity_key": None},
        {"cycle_id": None},
        {"source_ref": ""},
        {"source_ref": None},
        {"input_digest": ""},
        {"input_digest": None},
    ],
)
def test_missing_provenance_rejected(store: CytStore, kwargs: dict):
    base = dict(
        ts=100.0,
        source=obs.SOURCE_KISMET_DEVICES,
        kind=obs.KIND_WIFI_DEVICE,
        identity_key="AA:BB:CC:DD:EE:FF",
        cycle_id=1,
        source_ref="kismet:abc:devices:devid=1",
        input_digest="ab" * 32,
    )
    base.update(kwargs)
    with pytest.raises(ValueError) as excinfo:
        store.record_observation(**base)
    assert "provenance" in str(excinfo.value)


def test_detector_source_requires_detector_identity(store: CytStore):
    base = dict(
        ts=100.0,
        source=obs.SOURCE_DETECTOR,
        kind=obs.KIND_WIFI_DEVICE,
        identity_key="AA:BB:CC:DD:EE:FF",
        cycle_id=1,
        source_ref="detector:window:cycle=1",
        input_digest="ab" * 32,
    )
    with pytest.raises(ValueError, match="detector"):
        store.record_observation(**base)
    obs_id = store.record_observation(detector="window", **base)
    got = store.get_observation(obs_id)
    assert got["detector"] == "window"


def test_payload_must_be_object(store: CytStore):
    with pytest.raises(ValueError, match="payload"):
        store.record_observation(
            ts=100.0,
            source=obs.SOURCE_GPS,
            kind=obs.KIND_GPS_FIX,
            identity_key=obs.OPERATOR_IDENTITY,
            cycle_id=1,
            source_ref="gps:fix:100.0",
            input_digest="ab" * 32,
            payload=["not", "an", "object"],
        )


def test_non_finite_ts_rejected(store: CytStore):
    with pytest.raises(ValueError, match="ts"):
        store.record_observation(
            ts=float("nan"),
            source=obs.SOURCE_GPS,
            kind=obs.KIND_GPS_FIX,
            identity_key=obs.OPERATOR_IDENTITY,
            cycle_id=1,
            source_ref="gps:fix:nan",
            input_digest="ab" * 32,
        )


# --- immutability (acceptance 4) ---


def test_no_update_path_exists(store: CytStore):
    for method in (
        "update_observation",
        "edit_observation",
        "set_observation",
        "modify_observation",
        "replace_observation",
        "upsert_observation",
    ):
        assert not hasattr(store, method), f"unexpected update API: {method}"

    obs_id = store.record_observation(
        ts=100.0,
        source=obs.SOURCE_KISMET_DEVICES,
        kind=obs.KIND_WIFI_DEVICE,
        identity_key="AA:BB:CC:DD:EE:FF",
        cycle_id=1,
        source_ref="kismet:abc:devices:devid=1",
        input_digest="ab" * 32,
    )
    # Even bypassing the API, the database itself rejects UPDATE.
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store.conn.execute(
            "UPDATE observations SET ts = 999.0 WHERE id = ?", (obs_id,)
        )
    got = store.get_observation(obs_id)
    assert got["ts"] == 100.0


def test_correct_by_new_observation_not_mutation(store: CytStore):
    first = store.record_observation(
        ts=100.0,
        source=obs.SOURCE_KISMET_DEVICES,
        kind=obs.KIND_WIFI_DEVICE,
        identity_key="AA:BB:CC:DD:EE:FF",
        cycle_id=1,
        source_ref="kismet:abc:devices:devid=1",
        input_digest="ab" * 32,
        payload={"rssi": -80.0},
    )
    second = store.record_observation(
        ts=101.0,
        source=obs.SOURCE_KISMET_DEVICES,
        kind=obs.KIND_WIFI_DEVICE,
        identity_key="AA:BB:CC:DD:EE:FF",
        cycle_id=2,
        source_ref="kismet:abc:devices:devid=1",
        input_digest="ef" * 32,
        payload={"rssi": -55.0},
    )
    assert first != second
    assert store.get_observation(first)["payload"]["rssi"] == -80.0
    assert store.get_observation(second)["payload"]["rssi"] == -55.0


# --- query API ---


def test_query_observations_filters(store: CytStore):
    rows = [
        dict(ts=100.0, source=obs.SOURCE_KISMET_DEVICES, kind=obs.KIND_WIFI_DEVICE,
             identity_key="AA:00:00:00:00:01", cycle_id=1,
             source_ref="kismet:abc:devices:devid=1", input_digest="a" * 64),
        dict(ts=110.0, source=obs.SOURCE_KISMET_ALERTS, kind=obs.KIND_DEAUTH_ALERT,
             identity_key="AA:00:00:00:00:01", cycle_id=1,
             source_ref="kismet:abc:alerts:rowid=1", input_digest="b" * 64),
        dict(ts=120.0, source=obs.SOURCE_KISMET_DEVICES, kind=obs.KIND_WIFI_DEVICE,
             identity_key="AA:00:00:00:00:02", cycle_id=2,
             source_ref="kismet:abc:devices:devid=2", input_digest="c" * 64),
        dict(ts=130.0, source=obs.SOURCE_GPS, kind=obs.KIND_GPS_FIX,
             identity_key=obs.OPERATOR_IDENTITY, cycle_id=2,
             source_ref="gps:fix:130.0", input_digest="d" * 64),
    ]
    for r in rows:
        store.record_observation(**r)

    by_identity = store.query_observations(identity_key="AA:00:00:00:00:01")
    assert [o["ts"] for o in by_identity] == [100.0, 110.0]

    by_source = store.query_observations(source=obs.SOURCE_KISMET_DEVICES)
    assert [o["ts"] for o in by_source] == [100.0, 120.0]

    by_kind = store.query_observations(kind=obs.KIND_DEAUTH_ALERT)
    assert [o["ts"] for o in by_kind] == [110.0]

    by_cycle = store.query_observations(cycle_id=2)
    assert [o["ts"] for o in by_cycle] == [120.0, 130.0]

    in_window = store.query_observations(since=105.0, until=125.0)
    assert [o["ts"] for o in in_window] == [110.0, 120.0]

    combined = store.query_observations(
        identity_key="AA:00:00:00:00:01",
        source=obs.SOURCE_KISMET_DEVICES,
        since=100.0,
        until=105.0,
    )
    assert [o["ts"] for o in combined] == [100.0]

    limited = store.query_observations(limit=2)
    assert [o["ts"] for o in limited] == [100.0, 110.0]

    assert store.query_observations(identity_key="00:11:22:33:44:55") == []
    assert store.get_observation(9999) is None


# --- normalizers ---


def _device_json() -> str:
    return json.dumps(
        {
            "kismet.device.base.key": "1234/deadbeef",
            "kismet.device.base.macaddr": "aa:bb:cc:dd:ee:ff",
            "kismet.device.base.type": "Wi-Fi Device",
            "kismet.device.base.channel": "6",
            "kismet.device.base.frequency": 2.437,
            "kismet.device.base.signal": {
                "kismet.common.signal.last_signal": -58.0
            },
            "dot11.device": {
                "dot11.device.probed_ssid_map": {
                    "0": {"dot11.probedssid.ssid": "HomeNet"},
                    "1": {"dot11.probedssid.ssid": "CoffeeShop"},
                }
            },
        }
    )


def test_normalize_device_row_full():
    row = {
        "devmac": "aa:bb:cc:dd:ee:ff",
        "type": "Wi-Fi Device",
        "device": _device_json(),
        "last_time": 1758732000.0,
    }
    rec = obs.normalize_device_row(row, cycle_id=7, db_ref="0123abcd5678")
    assert rec is not None
    assert rec["identity_key"] == "AA:BB:CC:DD:EE:FF"
    assert rec["ts"] == 1758732000.0
    assert rec["source"] == obs.SOURCE_KISMET_DEVICES
    assert rec["kind"] == obs.KIND_WIFI_DEVICE
    assert rec["cycle_id"] == 7
    assert rec["source_ref"] == "kismet:0123abcd5678:devices:devid=1234/deadbeef"
    assert rec["input_digest"] == obs.input_digest(row)
    assert rec["payload"]["rssi"] == -58.0
    assert rec["payload"]["channel"] == "6"
    assert rec["payload"]["frequency"] == 2.437
    assert rec["payload"]["ssid_count"] == 2
    assert rec["payload"]["device_type"] == "Wi-Fi Device"
    # Raw SSID text never lands in the observation payload.
    assert "HomeNet" not in json.dumps(rec["payload"])


def test_normalize_device_row_strips_mac_mask():
    rec = obs.normalize_device_row(
        {
            "devmac": "aa:bb:cc:dd:ee:ff/01",
            "device": "{}",
            "last_time": 100.0,
        },
        cycle_id=1,
        db_ref="x",
    )
    assert rec is not None
    assert rec["identity_key"] == "AA:BB:CC:DD:EE:FF"
    assert rec["source_ref"] == "kismet:x:devices:devid=AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize(
    "row",
    [
        "not a mapping",
        None,
        {"last_time": 100.0},  # no devmac
        {"devmac": "aa:bb:cc:dd:ee:ff"},  # no last_time
        {"devmac": "", "last_time": 100.0},
        {"devmac": "aa:bb:cc:dd:ee:ff", "last_time": "not-a-number"},
        {"devmac": "aa:bb:cc:dd:ee:ff", "last_time": float("nan")},
        # No identity from either the column or the device JSON.
        {"device": json.dumps({"kismet.device.base.type": "Wi-Fi Device"}), "last_time": 100.0},
    ],
)
def test_normalize_device_row_malformed(row):
    assert obs.normalize_device_row(row, cycle_id=1, db_ref="x") is None


def test_normalize_device_row_garbage_device_json_tolerated():
    rec = obs.normalize_device_row(
        {"devmac": "aa:bb:cc:dd:ee:ff", "device": "{not json", "last_time": 100.0},
        cycle_id=1,
        db_ref="x",
    )
    assert rec is not None
    assert rec["payload"] == {}
    assert rec["identity_key"] == "AA:BB:CC:DD:EE:FF"


def test_normalize_device_row_identity_falls_back_to_device_json():
    rec = obs.normalize_device_row(
        {"devmac": None, "device": _device_json(), "last_time": 100.0},
        cycle_id=1,
        db_ref="x",
    )
    assert rec is not None
    assert rec["identity_key"] == "AA:BB:CC:DD:EE:FF"


def test_normalize_alert_row_deauth():
    alert_json = json.dumps(
        {
            "kismet.alert.header": "DEAUTH",
            "kismet.alert.text": "Disconnection announced by 11:22:33:44:55:66",
        }
    )
    row = {
        "ts_sec": 1758732100,
        "header": "DEAUTH",
        "json": alert_json,
        "src_mac": "11:22:33:44:55:66",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "bssid": "aa:bb:cc:dd:ee:ff",
        "rowid": 42,
    }
    rec = obs.normalize_alert_row(row, cycle_id=3, db_ref="0123abcd5678")
    assert rec is not None
    assert rec["kind"] == obs.KIND_DEAUTH_ALERT
    assert rec["identity_key"] == "11:22:33:44:55:66"
    assert rec["source"] == obs.SOURCE_KISMET_ALERTS
    assert rec["source_ref"] == "kismet:0123abcd5678:alerts:rowid=42"
    assert rec["input_digest"] == obs.input_digest(row)
    assert rec["ts"] == 1758732100.0


def test_normalize_alert_row_not_deauth_and_digest_locator():
    row = {
        "ts_sec": 100,
        "header": "SOMETHINGELSE",
        "json": json.dumps({"kismet.alert.src_mac": "11:22:33:44:55:66"}),
    }
    rec = obs.normalize_alert_row(row, cycle_id=1, db_ref="x")
    assert rec is not None
    assert rec["kind"] == obs.KIND_KISMET_ALERT
    assert rec["source_ref"].startswith("kismet:x:alerts:digest=")


def test_normalize_alert_row_mac_from_alert_json():
    row = {
        "ts_sec": 100,
        "header": "deauth",
        "json": {"kismet.alert.src_mac": "11:22:33:44:55:66"},
    }
    rec = obs.normalize_alert_row(row, cycle_id=1, db_ref="x")
    assert rec is not None
    assert rec["identity_key"] == "11:22:33:44:55:66"


@pytest.mark.parametrize(
    "row",
    [
        "nope",
        {"ts_sec": 100, "json": "{}"},  # no identity anywhere
        {"header": "x", "json": "{}"},  # no ts
        {"ts_sec": "bad", "json": "{}"},
    ],
)
def test_normalize_alert_row_malformed(row):
    assert obs.normalize_alert_row(row, cycle_id=1, db_ref="x") is None


def test_normalize_gps_fix():
    rec = obs.normalize_gps_fix(
        lat=33.5104, lon=-86.8744, ts=100.5, cycle_id=1, accuracy_m=8.0
    )
    assert rec is not None
    assert rec["identity_key"] == obs.OPERATOR_IDENTITY
    assert rec["source"] == obs.SOURCE_GPS
    assert rec["kind"] == obs.KIND_GPS_FIX
    assert rec["lat"] == 33.5104
    assert rec["lon"] == -86.8744
    assert rec["accuracy_m"] == 8.0
    assert rec["source_ref"] == "gps:fix:100.5"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"lat": 999.0, "lon": 0.0, "ts": 1.0},
        {"lat": 0.0, "lon": 999.0, "ts": 1.0},
        {"lat": None, "lon": 0.0, "ts": 1.0},
        {"lat": 1.0, "lon": 0.0, "ts": None},
    ],
)
def test_normalize_gps_fix_malformed(kwargs):
    assert obs.normalize_gps_fix(cycle_id=1, **kwargs) is None


def test_normalize_ble_advertisement():
    rec = obs.normalize_ble_advertisement(
        mac="aa:bb:cc:dd:ee:ff",
        ts=200.0,
        cycle_id=1,
        db_ref="0123abcd5678",
        name="Tile",
        rssi=-70.0,
        company_id="0x00E1",
    )
    assert rec is not None
    assert rec["source"] == obs.SOURCE_BLE
    assert rec["kind"] == obs.KIND_BLE_ADV
    assert rec["source_ref"] == "ble:0123abcd5678:adv:mac=AA:BB:CC:DD:EE:FF"
    assert rec["payload"] == {"name": "Tile", "rssi": -70.0, "company_id": "0x00E1"}
    assert rec["input_digest"] == obs.input_digest(
        {"mac": "AA:BB:CC:DD:EE:FF", "ts": 200.0, "name": "Tile", "rssi": -70.0}
    )


def test_normalize_ble_advertisement_without_db_ref():
    rec = obs.normalize_ble_advertisement(
        mac="aa:bb:cc:dd:ee:ff", ts=200.0, cycle_id=1
    )
    assert rec is not None
    assert rec["source_ref"] == "ble:adv:mac=AA:BB:CC:DD:EE:FF"
    assert rec["payload"] == {}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mac": None, "ts": 1.0},
        {"mac": "aa:bb:cc:dd:ee:ff", "ts": None},
        {"mac": "", "ts": 1.0},
    ],
)
def test_normalize_ble_advertisement_malformed(kwargs):
    assert obs.normalize_ble_advertisement(cycle_id=1, **kwargs) is None


def test_input_digest_stability():
    raw = {"b": 1, "a": "x", "c": [1.5, None]}
    assert obs.input_digest(raw) == obs.input_digest(dict(reversed(list(raw.items()))))
    assert obs.input_digest(raw) != obs.input_digest({"b": 1, "a": "x"})


# --- ingest: one cycle on a fixture Kismet DB (acceptance: fixture cycle) ---


def _kismet_fixture_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "kismet_fixture.kismet"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE devices (devmac TEXT, type TEXT, device TEXT, last_time REAL)"
    )
    conn.execute(
        "CREATE TABLE alerts (ts_sec INTEGER, header TEXT, json TEXT, "
        "src_mac TEXT, dst_mac TEXT, bssid TEXT)"
    )
    conn.execute(
        "INSERT INTO devices VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:01", "Wi-Fi Device", _device_json(), 1758732000.0),
    )
    # malformed device rows: NULL mac / NULL device / bad json tolerated later
    conn.execute(
        "INSERT INTO devices VALUES (?, ?, ?, ?)",
        (None, "Wi-Fi Device", _device_json(), 1758732001.0),
    )
    conn.execute(
        "INSERT INTO devices VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:02", "Wi-Fi Device", None, 1758732002.0),
    )
    conn.execute(
        "INSERT INTO devices VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:03", "Wi-Fi Device", "{not json", 1758732003.0),
    )
    conn.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
        (
            1758732100,
            "DEAUTH",
            json.dumps(
                {
                    "kismet.alert.header": "DEAUTH",
                    "kismet.alert.text": "Disconnection announced",
                }
            ),
            "11:22:33:44:55:66",
            "ff:ff:ff:ff:ff:ff",
            "aa:bb:cc:dd:ee:01",
        ),
    )
    # malformed alert row: no identity anywhere -> skipped
    conn.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
        (1758732101, "OTHER", json.dumps({"no": "mac"}), "", None, None),
    )
    # malformed alert row: unparseable json but identity in columns -> kept
    conn.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
        (1758732102, "deauth", "{not json", "11:22:33:44:55:67", None, None),
    )
    conn.commit()
    conn.close()
    return db_path


def test_ingest_kismet_cycle_persists_observations(store: CytStore, tmp_path: Path):
    db_path = _kismet_fixture_db(tmp_path)
    ro = connect_readonly(str(db_path))
    try:
        ids = obs.ingest_kismet_cycle(
            store,
            ro,
            cycle_id=11,
            db_path=str(db_path),
            session_id="sess-11",
            since_ts=0.0,
        )
    finally:
        ro.close()

    # Device JSON macaddr rescues the NULL-devmac row; only the
    # identity-less alert row is skipped.
    assert len(ids) == 6
    rows = store.query_observations(cycle_id=11)
    assert len(rows) == 6

    ref = obs.db_ref(str(db_path))
    device_rows = store.query_observations(
        source=obs.SOURCE_KISMET_DEVICES, cycle_id=11
    )
    assert len(device_rows) == 4
    for row in device_rows:
        assert row["identity_key"].startswith("AA:BB:CC:DD:EE:")
        assert row["source_ref"].startswith(
            f"kismet:{ref}:devices:devid="
        )
        assert row["kind"] == obs.KIND_WIFI_DEVICE
        assert row["session_id"] == "sess-11"
    assert device_rows[0]["payload"]["rssi"] == -58.0
    # NULL devmac column: identity + devid recovered from device JSON.
    assert device_rows[1]["identity_key"] == "AA:BB:CC:DD:EE:FF"
    assert device_rows[1]["source_ref"] == (
        f"kismet:{ref}:devices:devid=1234/deadbeef"
    )
    # NULL and garbage device JSON tolerated; the row's type column
    # still whitelists through.
    assert device_rows[2]["payload"] == {"device_type": "Wi-Fi Device"}
    assert device_rows[3]["payload"] == {"device_type": "Wi-Fi Device"}

    alert_rows = store.query_observations(source=obs.SOURCE_KISMET_ALERTS, cycle_id=11)
    assert len(alert_rows) == 2
    assert alert_rows[0]["kind"] == obs.KIND_DEAUTH_ALERT
    assert alert_rows[0]["identity_key"] == "11:22:33:44:55:66"
    assert alert_rows[0]["source_ref"].startswith(f"kismet:{ref}:alerts:rowid=")
    assert alert_rows[1]["kind"] == obs.KIND_DEAUTH_ALERT
    assert alert_rows[1]["identity_key"] == "11:22:33:44:55:67"


def test_ingest_kismet_cycle_respects_since_ts(store: CytStore, tmp_path: Path):
    db_path = _kismet_fixture_db(tmp_path)
    ro = connect_readonly(str(db_path))
    try:
        ids = obs.ingest_kismet_cycle(
            store, ro, cycle_id=12, db_path=str(db_path), since_ts=1758732002.0
        )
    finally:
        ro.close()
    rows = store.query_observations(cycle_id=12)
    assert len(ids) == len(rows)
    # Devices at/after the cutoff plus alerts (alert cutoff is separate).
    assert all(row["ts"] >= 1758732002.0 for row in rows)


def test_ingest_kismet_cycle_with_gps_fix(store: CytStore, tmp_path: Path):
    db_path = _kismet_fixture_db(tmp_path)
    ro = connect_readonly(str(db_path))
    try:
        ids = obs.ingest_kismet_cycle(
            store,
            ro,
            cycle_id=13,
            db_path=str(db_path),
            gps_fix={"lat": 33.5, "lon": -86.87, "ts": 1758732200.0, "accuracy_m": 9.0},
        )
    finally:
        ro.close()
    gps_rows = store.query_observations(source=obs.SOURCE_GPS, cycle_id=13)
    assert len(gps_rows) == 1
    assert gps_rows[0]["identity_key"] == obs.OPERATOR_IDENTITY
    assert gps_rows[0]["lat"] == 33.5
    assert gps_rows[0]["accuracy_m"] == 9.0
    assert len(ids) == 7


def test_ingest_missing_alerts_table_tolerated(store: CytStore, tmp_path: Path):
    db_path = tmp_path / "devices_only.kismet"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE devices (devmac TEXT, type TEXT, device TEXT, last_time REAL)"
    )
    conn.execute(
        "INSERT INTO devices VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:09", "Wi-Fi Device", _device_json(), 1758732000.0),
    )
    conn.commit()
    conn.close()

    ro = connect_readonly(str(db_path))
    try:
        ids = obs.ingest_kismet_cycle(
            store, ro, cycle_id=14, db_path=str(db_path)
        )
    finally:
        ro.close()
    assert len(ids) == 1
