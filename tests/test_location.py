"""D5 location geometry: haversine clustering, visits, co-travel, density.

Tests are written on synthetic lat/lons and assert the audit's exact
failure cases:
- two clusters 10 m apart across a 0.001° grid boundary (grid cells split
  them; haversine clustering must merge them),
- any device with two cells anywhere scoring as co-travel (replaced by
  operator-path co-travel),
- re-entry of the same place counting as a distinct visit,
- physically infeasible transitions (250 mi in 10 min) dropped.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import List

from cyt_platform.gps_live import LiveGpsFusion
from cyt_platform.location import (
    DEFAULT_MERGE_RADIUS_M,
    Sighting,
    Visit,
    attendance,
    cluster_sightings,
    cotravel_matches,
    haversine_m,
    independent_visits,
    path_visits,
    stable_cluster_id,
)
from cyt_platform.observations import (
    KIND_WIFI_DEVICE,
    SOURCE_KISMET_DEVICES,
    input_digest,
    normalize_gps_fix,
)
from cyt_platform.store import CytStore

# Test fixture places: Phoenix downtown area (realistic mid-latitude geometry).
PHOENIX_LAT = 33.4
PHOENIX_LON = -112.0


def _grid_cell(lat: float, lon: float) -> str:
    """The audited 0.001° grid id (gps_live.cluster_id before D5)."""
    return f"g_{lat:.3f}_{lon:.3f}"


def test_haversine_known_distances():
    # One degree of latitude is ~111.19 km everywhere.
    one_deg = haversine_m(0.0, 0.0, 1.0, 0.0)
    assert abs(one_deg - 111194.9) < 50.0
    # Zero distance for identical points.
    assert haversine_m(PHOENIX_LAT, PHOENIX_LON, PHOENIX_LAT, PHOENIX_LON) == 0.0


def test_ten_meter_boundary_pair_merges():
    """The exact audit case: 10 m apart, split by a 0.001° grid boundary.

    Grid cells count these as two locations; haversine clustering must
    merge them into one place at the default merge radius (30 m).
    """
    lat_a, lon_a = PHOENIX_LAT, -112.0006  # cell g_-112.001
    lon_b = lon_a + 10.0 / (111194.9 * 0.8345)  # ~10 m east: cell g_-112.000

    # The audit precondition: the OLD grid counted these as two cells.
    assert _grid_cell(lat_a, lon_a) != _grid_cell(lat_a, lon_b)
    # And they are genuinely ~10 m apart (well inside one merge radius).
    assert haversine_m(lat_a, lon_a, lat_a, lon_b) <= 10.5

    clusters = cluster_sightings(
        [
            Sighting(ts=1000.0, lat=lat_a, lon=lon_a),
            Sighting(ts=1010.0, lat=lat_a, lon=lon_b),
        ],
        merge_radius_m=DEFAULT_MERGE_RADIUS_M,
    )
    assert len(clusters) == 1
    assert clusters[0].member_count == 2


def test_ten_km_pair_stays_separate():
    """10 km apart is genuinely two places, at default and legacy radii."""
    # ~0.09 deg of latitude is ~10 km.
    far_lat = PHOENIX_LAT + 0.09
    assert 9_900.0 <= haversine_m(PHOENIX_LAT, PHOENIX_LON, far_lat, PHOENIX_LON) <= 10_100.0
    for radius in (DEFAULT_MERGE_RADIUS_M, 100.0):
        clusters = cluster_sightings(
            [
                Sighting(ts=1000.0, lat=PHOENIX_LAT, lon=PHOENIX_LON),
                Sighting(ts=2000.0, lat=far_lat, lon=PHOENIX_LON),
            ],
            merge_radius_m=radius,
        )
        assert len(clusters) == 2


def test_clustering_is_order_independent():
    """Same sightings in any arrival order produce the same clusters."""
    sightings = [
        Sighting(ts=100.0, lat=PHOENIX_LAT, lon=PHOENIX_LON),
        Sighting(ts=200.0, lat=PHOENIX_LAT + 0.09, lon=PHOENIX_LON),
        Sighting(ts=300.0, lat=PHOENIX_LAT, lon=PHOENIX_LON + 0.0001),  # ~9 m
        Sighting(ts=400.0, lat=PHOENIX_LAT + 0.09, lon=PHOENIX_LON + 0.0001),
    ]
    baseline = [(c.cluster_id, c.member_count) for c in cluster_sightings(sightings)]
    shuffled = list(sightings)
    random.Random(1234).shuffle(shuffled)
    reshuffled = [(c.cluster_id, c.member_count) for c in cluster_sightings(shuffled)]
    assert sorted(baseline) == sorted(reshuffled)
    # And the close pairs merged: 4 sightings, 2 clusters.
    assert {mc for _, mc in baseline} == {2}


def test_stable_cluster_id_deterministic():
    """Ids are content-addressed (no seed-randomized hash()), replay-safe."""
    assert stable_cluster_id(PHOENIX_LAT, PHOENIX_LON) == stable_cluster_id(
        PHOENIX_LAT, PHOENIX_LON
    )
    assert stable_cluster_id(PHOENIX_LAT, PHOENIX_LON) != stable_cluster_id(
        PHOENIX_LAT, PHOENIX_LON + 0.01
    )
    assert stable_cluster_id(PHOENIX_LAT, PHOENIX_LON).startswith("loc_")


def test_place_registry_merges_boundary_pair():
    """The live place registry: 10 m apart across a grid boundary = one place."""
    fusion = LiveGpsFusion(
        object(), {"gps_fusion": {"enabled": False}}
    )  # geometry only; store unused here
    a = fusion._place_id(PHOENIX_LAT, -112.0006, now=1000.0)
    b = fusion._place_id(PHOENIX_LAT, -112.0006 + 10.0 / (111194.9 * 0.8345), now=1010.0)
    assert a.cluster_id == b.cluster_id
    assert len(fusion.anchors) == 1


# --- distinct visits (D5) -------------------------------------------------

FAR_LAT = PHOENIX_LAT + 0.09  # ~10 km north


def _sightings(points, identity="operator"):
    return [
        Sighting(ts=ts, lat=lat, lon=lon, identity_key=identity)
        for lat, lon, ts in points
    ]


def test_distinct_visit_reentry_counts_twice():
    """Operator at A, then B, then A again = 3 visits; A counts twice."""
    path = _sightings(
        [
            (PHOENIX_LAT, PHOENIX_LON, 0.0),
            (PHOENIX_LAT, PHOENIX_LON, 600.0),
            (FAR_LAT, PHOENIX_LON, 1200.0),
            (FAR_LAT, PHOENIX_LON, 1800.0),
            (PHOENIX_LAT, PHOENIX_LON, 2400.0),
            (PHOENIX_LAT, PHOENIX_LON, 3000.0),
        ]
    )
    visits = independent_visits(path)
    assert len(visits) == 3
    # Re-entry of the first place: same cluster id, a distinct visit.
    assert visits[0].cluster_id == visits[2].cluster_id
    assert visits[0].enter_ts < visits[2].enter_ts
    # Exits close on departure; the final visit stays open.
    assert visits[0].exit_ts == 600.0
    assert visits[2].exit_ts is None


def test_gap_split_counts_as_reentry():
    """Same cluster, but the observer vanished longer than revisit_gap_s."""
    path = _sightings(
        [
            (PHOENIX_LAT, PHOENIX_LON, 0.0),
            (PHOENIX_LAT, PHOENIX_LON, 100.0),
            (PHOENIX_LAT, PHOENIX_LON, 100.0 + 601.0),
        ]
    )
    visits = path_visits(path, revisit_gap_s=600.0)
    assert len(visits) == 2


def test_continuous_stay_is_one_visit():
    """Sightings jittering within a few metres of one anchor = one visit."""
    path = _sightings(
        [
            (
                PHOENIX_LAT + 0.00004 * ((i % 3) - 1),  # ±~4 m jitter
                PHOENIX_LON + 0.00004 * ((i % 2) - 0.5),
                100.0 * i,
            )
            for i in range(10)
        ]
    )
    assert len(independent_visits(path)) == 1


def test_infeasible_pair_dropped():
    """250 mi in 10 minutes is a GPS artifact, not a visited place."""
    jump_lat = PHOENIX_LAT + 402336.0 / 111194.9  # 250 mi north in degrees
    path = _sightings(
        [
            (PHOENIX_LAT, PHOENIX_LON, 0.0),
            (PHOENIX_LAT, PHOENIX_LON, 300.0),
            (jump_lat, PHOENIX_LON, 600.0),
            (jump_lat, PHOENIX_LON, 900.0),
        ]
    )
    pre = path_visits(path)
    assert len(pre) == 2  # geometry sees two clusters
    visits = independent_visits(path, max_speed_mps=35.0)
    assert len(visits) == 1  # the 250-mi-in-10-min arrival is dropped
    assert visits[0].lat == PHOENIX_LAT


def test_feasible_travel_between_visits_kept():
    """14 km in 25 minutes (9.4 m/s) is feasible and kept."""
    path = _sightings(
        [
            (PHOENIX_LAT, PHOENIX_LON, 0.0),
            (PHOENIX_LAT + 0.09, PHOENIX_LON + 0.08, 1500.0),
        ]
    )
    assert len(independent_visits(path)) == 2


# --- co-travel matching (D5) ----------------------------------------------


def _visit(lat, lon, enter, exit_, accuracy=0.0):
    return Visit(
        cluster_id=stable_cluster_id(lat, lon),
        enter_ts=enter,
        exit_ts=exit_,
        lat=lat,
        lon=lon,
        accuracy_m=accuracy,
    )


def test_cotravel_requires_time_overlap():
    """Same place at disjoint times is not co-travel."""
    place = (PHOENIX_LAT, PHOENIX_LON)
    entity = [_visit(place[0], place[1], 0.0, 100.0)]
    operator = [_visit(place[0], place[1], 500.0, 600.0)]
    assert (
        cotravel_matches(
            entity, operator, merge_radius_m=DEFAULT_MERGE_RADIUS_M, revisit_gap_s=600.0
        )
        == []
    )


def test_offpath_device_never_matches():
    """A device at places the operator never visited matches nothing."""
    entity = [
        _visit(33.8, -112.5, 0.0, 100.0),
        _visit(33.9, -112.6, 500.0, 600.0),
    ]
    operator = [
        _visit(PHOENIX_LAT, PHOENIX_LON, 0.0, 100.0),
        _visit(FAR_LAT, PHOENIX_LON, 500.0, 600.0),
    ]
    assert (
        cotravel_matches(
            entity, operator, merge_radius_m=DEFAULT_MERGE_RADIUS_M, revisit_gap_s=600.0
        )
        == []
    )


def test_on_path_device_matches_operator_visits():
    """Co-located, time-overlapping visits match — the operator-path join."""
    entity = [
        _visit(PHOENIX_LAT + 0.0001, PHOENIX_LON, 100.0, 1700.0),
        _visit(FAR_LAT + 0.0001, PHOENIX_LON, 1900.0, 2100.0),
    ]
    operator = [
        _visit(PHOENIX_LAT, PHOENIX_LON, 0.0, 1800.0),
        _visit(FAR_LAT, PHOENIX_LON, 1800.0, 2400.0),
    ]
    matches = cotravel_matches(
        entity, operator, merge_radius_m=DEFAULT_MERGE_RADIUS_M, revisit_gap_s=600.0
    )
    assert len(matches) == 2


# --- density context (D5) ---------------------------------------------------


def test_attendance_counts_distinct_bystanders():
    """Density = distinct identities near a place in the time window.

    Same-device repeats count once, far and out-of-window sightings don't
    count, and the subject/operator are excluded (they are the signal).
    """
    bystanders = [
        Sighting(ts=100.0, lat=PHOENIX_LAT, lon=PHOENIX_LON, identity_key="aa:03"),
        Sighting(ts=150.0, lat=PHOENIX_LAT, lon=PHOENIX_LON, identity_key="aa:03"),
        Sighting(ts=120.0, lat=PHOENIX_LAT + 0.0001, lon=PHOENIX_LON, identity_key="aa:04"),
        Sighting(ts=120.0, lat=FAR_LAT, lon=PHOENIX_LON, identity_key="aa:05"),
        Sighting(ts=1000.0, lat=PHOENIX_LAT, lon=PHOENIX_LON, identity_key="aa:06"),
        Sighting(ts=110.0, lat=PHOENIX_LAT, lon=PHOENIX_LON, identity_key="aa:07"),
    ]
    assert (
        attendance(
            bystanders,
            lat=PHOENIX_LAT,
            lon=PHOENIX_LON,
            from_ts=50.0,
            to_ts=200.0,
            exclude=("aa:07", "operator"),
        )
        == 2
    )


# --- replay scenarios (D5 acceptance: scenario asserts visit counts) ------

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios" / "location"


def _load_scenario(name: str) -> dict:
    with open(SCENARIO_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def _record_scenario(store: CytStore, scenario: dict) -> None:
    """Persist scenario sightings as canonical observations (CytStore API)."""
    with store.transaction():
        for i, s in enumerate(scenario["sightings"]):
            if s["identity"] == "operator":
                rec = normalize_gps_fix(
                    lat=s["lat"],
                    lon=s["lon"],
                    ts=s["ts"],
                    cycle_id=i // 10,
                    accuracy_m=s.get("accuracy_m"),
                )
            else:
                rec = {
                    "ts": float(s["ts"]),
                    "source": SOURCE_KISMET_DEVICES,
                    "kind": KIND_WIFI_DEVICE,
                    "identity_key": s["identity"],
                    "cycle_id": i // 10,
                    "source_ref": f"scenario:{scenario['scenario']}:{i}",
                    "input_digest": input_digest(s),
                    "payload": {},
                    "lat": float(s["lat"]),
                    "lon": float(s["lon"]),
                }
            assert rec is not None
            store.record_observation(**rec)


def _operator_sightings(store: CytStore) -> List[Sighting]:
    rows = store.query_observations(
        identity_key="operator", source="gps", kind="gps_fix", limit=5000
    )
    return [
        Sighting(
            ts=float(r["ts"]),
            lat=float(r["lat"]),
            lon=float(r["lon"]),
            accuracy_m=float(r.get("accuracy_m") or 0.0),
            identity_key="operator",
        )
        for r in rows
    ]


def test_replay_scenario_commuter_visit_counts(tmp_path: Path):
    """Scenario replay: 4 operator visits (re-entry counts twice), the
    follower co-travels across all of them, the mall device never does."""
    scenario = _load_scenario("commuter_visits.json")
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    store.begin_session()
    _record_scenario(store, scenario)

    visits = independent_visits(_operator_sightings(store))
    assert len(visits) == scenario["expect"]["operator_visit_count"]
    # Re-entry: first and last visit share a place.
    assert visits[0].cluster_id == visits[-1].cluster_id

    fusion = LiveGpsFusion(
        store,
        {
            "gps_fusion": {
                "enabled": True,
                "min_locations_for_cotravel": 2,
                "min_span_seconds": 1,
                "incident_score_threshold": 0.5,
            }
        },
    )
    now = max(s["ts"] for s in scenario["sightings"]) + 60.0
    results = fusion.score_cotravel(now)
    by_key = {r["entity_key"]: r for r in results}
    follower = by_key.get("AA:00:00:00:00:01")
    assert follower is not None
    assert follower["location_count"] == scenario["expect"]["follower_locations"]
    assert "AA:00:00:00:00:02" not in by_key  # off-path device never co-travels

    # Density context: the cafe had two bystander devices; quiet places 0.
    op_visits = follower["detail"]["operator_visits"]
    cafe = [v for v in op_visits if abs(v["lat"] - 33.4180) < 0.001]
    quiet = [v for v in op_visits if abs(v["lat"] - 33.4180) >= 0.001]
    assert len(cafe) == 1
    assert cafe[0]["density"] == scenario["expect"]["follower_cafe_density"]
    assert all(v["density"] == 0 for v in quiet)

    # Synthetic clock is in the past relative to the wall clock, so the
    # incident hold window must span the difference.
    evidence = store.list_open_incident_evidence(hold_seconds=10 * 365 * 86400)
    assert any(
        (e.get("evidence") or {}).get("kind") == "cotravel" for e in evidence
    )
    store.close()


def test_replay_scenario_infeasible_jump(tmp_path: Path):
    """Scenario replay: the 250-mi-in-10-min arrival is dropped."""
    scenario = _load_scenario("infeasible_jump.json")
    store = CytStore.open({"path": str(tmp_path / "cyt.db"), "mode": "durable"})
    store.begin_session()
    _record_scenario(store, scenario)
    path = path_visits(_operator_sightings(store))
    assert len(path) == scenario["expect"]["pre_filter_visit_count"]
    visits = independent_visits(_operator_sightings(store), max_speed_mps=35.0)
    assert len(visits) == scenario["expect"]["independent_visit_count"]
    store.close()
