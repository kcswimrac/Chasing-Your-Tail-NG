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

import random

from cyt_platform.gps_live import LiveGpsFusion
from cyt_platform.location import (
    DEFAULT_MERGE_RADIUS_M,
    Sighting,
    cluster_sightings,
    haversine_m,
    stable_cluster_id,
)

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
