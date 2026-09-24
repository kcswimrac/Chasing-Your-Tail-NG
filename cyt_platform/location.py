"""D5: location geometry — haversine clustering, distinct visits, co-travel.

Pure geometry for location independence. No store access, no clock reads,
no I/O: every function takes sightings in and returns values out, so the
exact same code runs live and in replay (locked decision #4: deterministic
core — same inputs produce identical outputs).

The audit this module replaces: location "independence" counted distinct
0.001° grid cells, so two clusters 10 m apart across a grid boundary
scored the same as clusters 10 km apart, and co-travel scoring never
joined the operator's own path — any device seen at two cells anywhere
scored. Here a location is a haversine-radius cluster, a location is
counted once per distinct visit (re-entry counts twice), and co-travel is
matched against the operator's own visited places.

Clustering is leader-based and deterministic: sightings are processed in
(ts, lat, lon) order and each joins the first cluster whose leader
(first-seen sighting) is within ``merge_radius_m``. Leaders do not drift,
so cluster identity is stable for a given input set.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import List, Optional, Sequence

# Spec D5 defaults. The live fusion allows config overrides (gps_fusion.*).
# merge radius: spec default max(2 x gps_accuracy, 30) — bounded, not a grid.
DEFAULT_MERGE_RADIUS_M = 30.0
# Same-place sightings separated by more than this are distinct visits
# (the observer is assumed to have left; continuous tracking is not required).
DEFAULT_REVISIT_GAP_S = 600.0
# Transitions faster than highway speed are GPS artifacts, not travel.
DEFAULT_MAX_SPEED_MPS = 35.0

EARTH_RADIUS_M = 6371000.0


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points, in meters."""
    r = EARTH_RADIUS_M
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def stable_cluster_id(lat: float, lon: float) -> str:
    """Deterministic content address for a cluster anchor.

    Derived from the anchor coordinates, not a mutable counter, so the same
    place mints the same id across restarts and replays (no hash() — the
    built-in is seed-randomized and would break replay determinism).
    """
    return "loc_" + hashlib.sha1(f"{lat:.6f},{lon:.6f}".encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True)
class Sighting:
    """One located observation of one identity (operator or device)."""

    ts: float
    lat: float
    lon: float
    accuracy_m: float = 0.0
    identity_key: str = ""


@dataclass(frozen=True)
class Visit:
    """One distinct stay at one cluster.

    ``exit_ts`` is None when the sighting window ends without a departure
    signal (the observer was still there, or stopped being heard).
    """

    cluster_id: str
    enter_ts: float
    exit_ts: Optional[float]
    lat: float
    lon: float
    accuracy_m: float = 0.0


@dataclass(frozen=True)
class Cluster:
    """A haversine-radius cluster of sightings anchored on its leader."""

    cluster_id: str
    lat: float
    lon: float
    first_ts: float
    last_ts: float
    member_count: int


def _sorted_sightings(sightings: Sequence[Sighting]) -> List[Sighting]:
    return sorted(sightings, key=lambda s: (s.ts, s.lat, s.lon))


def assign_clusters(
    sightings: Sequence[Sighting], *, merge_radius_m: float = DEFAULT_MERGE_RADIUS_M
) -> List[int]:
    """Cluster index per sighting, in (ts, lat, lon) sorted order.

    Leader clustering: a sighting joins the first cluster (in creation
    order) whose leader is within ``merge_radius_m`` of it; otherwise it
    founds a new cluster. Leader-based rather than single-link so clusters
    cannot chain unboundedly along a walk.
    """
    ordered = _sorted_sightings(sightings)
    leaders: List[Sighting] = []
    out: List[int] = []
    for s in ordered:
        idx: Optional[int] = None
        for i, leader in enumerate(leaders):
            if haversine_m(leader.lat, leader.lon, s.lat, s.lon) <= merge_radius_m:
                idx = i
                break
        if idx is None:
            leaders.append(s)
            idx = len(leaders) - 1
        out.append(idx)
    return out


def cluster_sightings(
    sightings: Sequence[Sighting], *, merge_radius_m: float = DEFAULT_MERGE_RADIUS_M
) -> List[Cluster]:
    """Group sightings into haversine-radius clusters.

    Replaces grid-cell counting: two sightings 10 m apart across a 0.001°
    boundary land in one cluster (the exact audit failure case), while
    clusters 10 km apart stay separate.
    """
    ordered = _sorted_sightings(sightings)
    assign = assign_clusters(ordered, merge_radius_m=merge_radius_m)
    members: List[List[Sighting]] = []
    for s, idx in zip(ordered, assign):
        while len(members) <= idx:
            members.append([])
        members[idx].append(s)
    clusters: List[Cluster] = []
    for group in members:
        leader = group[0]
        clusters.append(
            Cluster(
                cluster_id=stable_cluster_id(leader.lat, leader.lon),
                lat=leader.lat,
                lon=leader.lon,
                first_ts=group[0].ts,
                last_ts=group[-1].ts,
                member_count=len(group),
            )
        )
    return sorted(clusters, key=lambda c: (c.first_ts, c.cluster_id))
