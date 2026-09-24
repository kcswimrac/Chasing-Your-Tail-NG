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
from typing import List, Optional, Sequence, Tuple

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
    leaders, assign = _cluster_leaders(ordered, merge_radius_m)
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


def _cluster_leaders(
    ordered: Sequence[Sighting], merge_radius_m: float
) -> Tuple[List[Sighting], List[int]]:
    """Leader per cluster and the cluster index of each (sorted) sighting."""
    leaders: List[Sighting] = []
    assign: List[int] = []
    for s in ordered:
        idx: Optional[int] = None
        for i, leader in enumerate(leaders):
            if haversine_m(leader.lat, leader.lon, s.lat, s.lon) <= merge_radius_m:
                idx = i
                break
        if idx is None:
            leaders.append(s)
            idx = len(leaders) - 1
        assign.append(idx)
    return leaders, assign


def path_visits(
    sightings: Sequence[Sighting],
    *,
    merge_radius_m: float = DEFAULT_MERGE_RADIUS_M,
    revisit_gap_s: float = DEFAULT_REVISIT_GAP_S,
) -> List[Visit]:
    """Split a time-ordered sighting sequence into distinct place visits.

    A visit ends when the sequence moves to a different cluster (the
    observer left) or when the gap since the previous same-cluster
    sighting exceeds ``revisit_gap_s`` (departure assumed). Re-entering a
    cluster therefore starts a NEW visit — re-entry counts twice, which
    pure cell counting could never express.
    """
    ordered = _sorted_sightings(sightings)
    if not ordered:
        return []
    leaders, assign = _cluster_leaders(ordered, merge_radius_m)

    def _close(idx: int, enter: float, exit: Optional[float], acc: float) -> Visit:
        leader = leaders[idx]
        return Visit(
            cluster_id=stable_cluster_id(leader.lat, leader.lon),
            enter_ts=enter,
            exit_ts=exit,
            lat=leader.lat,
            lon=leader.lon,
            accuracy_m=acc,
        )

    visits: List[Visit] = []
    cur_idx: Optional[int] = None
    enter_ts = 0.0
    last_ts = 0.0
    cur_acc = 0.0
    for s, idx in zip(ordered, assign):
        if idx != cur_idx:
            if cur_idx is not None:
                visits.append(_close(cur_idx, enter_ts, last_ts, cur_acc))
            cur_idx, enter_ts, last_ts, cur_acc = idx, s.ts, s.ts, s.accuracy_m
        elif s.ts - last_ts > revisit_gap_s:
            visits.append(_close(idx, enter_ts, last_ts, cur_acc))
            enter_ts, last_ts, cur_acc = s.ts, s.ts, s.accuracy_m
        else:
            last_ts = s.ts
            cur_acc = max(cur_acc, s.accuracy_m)
    assert cur_idx is not None  # ordered is non-empty
    # The final visit stays open (exit None) — the observer was still there
    # when the window ended; overlap logic extends it by revisit_gap_s.
    visits.append(_close(cur_idx, enter_ts, None, cur_acc))
    return visits


def _transition_feasible(prev: Visit, nxt: Visit, *, max_speed_mps: float) -> bool:
    """Whether travel from ``prev`` to ``nxt`` is physically possible.

    distance <= max_speed * dt + 2 x accuracy. Infeasible transitions are
    GPS artifacts (or spoofing), not movement.
    """
    anchor_ts = prev.exit_ts if prev.exit_ts is not None else prev.enter_ts
    dt = max(nxt.enter_ts - anchor_ts, 0.0)
    dist = haversine_m(prev.lat, prev.lon, nxt.lat, nxt.lon)
    allowance = max_speed_mps * dt + 2.0 * max(prev.accuracy_m, nxt.accuracy_m)
    return dist <= allowance


def independent_visits(
    sightings: Sequence[Sighting],
    *,
    merge_radius_m: float = DEFAULT_MERGE_RADIUS_M,
    revisit_gap_s: float = DEFAULT_REVISIT_GAP_S,
    max_speed_mps: float = DEFAULT_MAX_SPEED_MPS,
) -> List[Visit]:
    """Distinct visits a sighting sequence makes, in time order.

    1. Cluster sightings by haversine radius (not grid cells).
    2. Split re-entries of the same cluster into distinct visits when the
       observer left the cluster in between.
    3. Drop visits whose arrival is physically infeasible from the last
       credible visit: distance > max_speed * dt + 2 x accuracy (e.g. a
       250 mi jump in 10 minutes is a GPS artifact, not a visited place).
    """
    visits = path_visits(
        sightings, merge_radius_m=merge_radius_m, revisit_gap_s=revisit_gap_s
    )
    kept: List[Visit] = []
    for v in visits:  # path_visits yields time-ordered visits
        if not kept or _transition_feasible(kept[-1], v, max_speed_mps=max_speed_mps):
            kept.append(v)
        # else: arrival faster than max_speed from the last credible
        # visit — dropped as a location artifact, not counted as travel.
    return kept


def visits_overlap(
    a: Visit, b: Visit, *, revisit_gap_s: float = DEFAULT_REVISIT_GAP_S
) -> bool:
    """Whether two visits' time windows overlap.

    An open visit (exit_ts None) is treated as still occupied for
    revisit_gap_s after its last sighting.
    """
    a_end = a.exit_ts if a.exit_ts is not None else a.enter_ts + revisit_gap_s
    b_end = b.exit_ts if b.exit_ts is not None else b.enter_ts + revisit_gap_s
    return a.enter_ts <= b_end and b.enter_ts <= a_end


# Two visits are co-located when their anchors sit within one merge radius
# each of the shared place (leaders may differ between observers).
COTRAVEL_ANCHOR_RADIUS_FACTOR = 2.0


def cotravel_matches(
    entity_visits: Sequence[Visit],
    operator_visits: Sequence[Visit],
    *,
    merge_radius_m: float = DEFAULT_MERGE_RADIUS_M,
    revisit_gap_s: float = DEFAULT_REVISIT_GAP_S,
) -> List[Tuple[Visit, Visit]]:
    """Pair (entity_visit, operator_visit) co-located in space and time.

    This is the operator-path join the audit found missing: a match means
    the entity was where the operator was, while the operator was there.
    A device seen at two places the operator never visited matches nothing.
    """
    threshold_m = COTRAVEL_ANCHOR_RADIUS_FACTOR * merge_radius_m
    matches: List[Tuple[Visit, Visit]] = []
    for ev in entity_visits:
        for ov in operator_visits:
            if (
                haversine_m(ev.lat, ev.lon, ov.lat, ov.lon) <= threshold_m
                and visits_overlap(ev, ov, revisit_gap_s=revisit_gap_s)
            ):
                matches.append((ev, ov))
    return matches
