"""D5: Live GPS extraction from Kismet + co-travel scoring on operator path.

Location geometry lives in cyt_platform/location.py (pure, replayable);
this module is the live adapter: it extracts GPS fixes from Kismet device
JSON, clusters them into haversine-radius places (replacing 0.001° grid
cells, whose boundary pairs 10 m apart over-counted locations), records
observations through the CytStore API, and scores co-travel against the
operator's own visited places — the audit's docstring-lie fix.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from cyt_platform.location import (
    DEFAULT_MERGE_RADIUS_M,
    DEFAULT_REVISIT_GAP_S,
    haversine_m,
    stable_cluster_id,
)

logger = logging.getLogger(__name__)


@dataclass
class GpsFix:
    lat: float
    lon: float
    ts: float
    alt: Optional[float] = None
    source: str = "kismet"


@dataclass
class _ClusterAnchor:
    """Registered place: sightings within merge radius reuse its stable id."""

    lat: float
    lon: float
    cluster_id: str
    last_seen: float


# Anchor registry is bounded session state; the geometric truth of a place
# is always recomputable from the persisted lat/lon observations.
ANCHOR_REGISTRY_CAP = 512


def extract_gps_from_device_json(device_data: dict) -> Optional[Tuple[float, float, float]]:
    """Return (lat, lon, ts) if device JSON has location."""
    if not device_data:
        return None
    # Common Kismet paths
    candidates = [
        device_data.get("kismet.device.base.location"),
        device_data.get("kismet.device.base.last_location"),
    ]
    loc = None
    for c in candidates:
        if isinstance(c, dict):
            loc = c
            break
    if not loc:
        # nested geopoint
        for k, v in device_data.items():
            if isinstance(v, dict) and (
                "kismet.common.location.geopoint" in v
                or "geopoint" in str(v.keys())
            ):
                loc = v
                break
    if not isinstance(loc, dict):
        return None

    lat = lon = None
    # geopoint is often [lon, lat]
    gp = loc.get("kismet.common.location.geopoint") or loc.get("geopoint")
    if isinstance(gp, (list, tuple)) and len(gp) >= 2:
        lon, lat = float(gp[0]), float(gp[1])
    else:
        lat = loc.get("kismet.common.location.lat") or loc.get("lat")
        lon = loc.get("kismet.common.location.lon") or loc.get("lon")
    if lat is None or lon is None:
        return None
    try:
        lat_f, lon_f = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    if abs(lat_f) < 0.0001 and abs(lon_f) < 0.0001:
        return None
    ts = loc.get("kismet.common.location.time_sec") or loc.get("time") or time.time()
    try:
        ts_f = float(ts)
    except (TypeError, ValueError):
        ts_f = time.time()
    return lat_f, lon_f, ts_f


class LiveGpsFusion:
    """Track operator path from Kismet GPS + score co-traveling devices.

    Operator fixes are recorded as canonical ``gps``/``gps_fix``
    observations (D1) with cycle provenance; device sightings reuse the
    existing ``record_location_sighting`` API keyed by haversine place ids
    instead of grid cells.
    """

    def __init__(self, store: Any, config: dict):
        self.store = store
        self.cfg = config.get("gps_fusion") or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        # merge_radius_m wins; cluster_meters (legacy grid-size knob) is the
        # fallback so existing tuned configs keep their radius.
        self.merge_radius_m = float(
            self.cfg.get("merge_radius_m")
            or self.cfg.get("cluster_meters")
            or DEFAULT_MERGE_RADIUS_M
        )
        self.min_locations = int(self.cfg.get("min_locations_for_cotravel") or 2)
        self.min_span_s = float(self.cfg.get("min_span_seconds") or 900)
        self.revisit_gap_s = float(
            self.cfg.get("revisit_gap_s") or DEFAULT_REVISIT_GAP_S
        )
        self.last_fix: Optional[GpsFix] = None
        self.operator_path: List[_ClusterAnchor] = []
        self.anchors: List[_ClusterAnchor] = []
        self._cycle_counter = 0

    def _place_id(self, lat: float, lon: float, now: float) -> _ClusterAnchor:
        """Return the anchor for this point, creating one when it is a new place.

        Haversine radius, not grid cells: two fixes 10 m apart share a place
        even across a 0.001° boundary, while places km apart stay distinct.
        """
        for anchor in self.anchors:
            if haversine_m(anchor.lat, anchor.lon, lat, lon) <= self.merge_radius_m:
                anchor.last_seen = now
                return anchor
        anchor = _ClusterAnchor(
            lat=lat,
            lon=lon,
            cluster_id=stable_cluster_id(lat, lon),
            last_seen=now,
        )
        self.anchors.append(anchor)
        if len(self.anchors) > ANCHOR_REGISTRY_CAP:
            # Drop the stalest anchor — bounded registry, geometrically recoverable.
            self.anchors.sort(key=lambda a: a.last_seen)
            self.anchors.pop(0)
        return anchor

    def _record_observation(
        self,
        *,
        source: str,
        kind: str,
        identity_key: str,
        ts: float,
        lat: float,
        lon: float,
        payload: dict,
    ) -> None:
        """Persist one located observation through the CytStore API (D1)."""
        from cyt_platform import observations as obs  # lazy: obs imports this module

        session_id = self.store.get_runtime("session_id")
        if source == obs.SOURCE_GPS:
            rec = obs.normalize_gps_fix(
                lat=lat,
                lon=lon,
                ts=ts,
                cycle_id=self._cycle_counter,
                session_id=session_id,
            )
        else:
            rec = {
                "ts": float(ts),
                "source": source,
                "kind": kind,
                "identity_key": identity_key,
                "cycle_id": self._cycle_counter,
                "source_ref": f"kismet:live:devices:mac={identity_key}:ts={ts}",
                "input_digest": obs.input_digest(
                    {"k": identity_key, "ts": ts, "lat": lat, "lon": lon}
                ),
                "payload": payload,
                "session_id": session_id,
                "lat": lat,
                "lon": lon,
            }
        if rec is None:
            return
        # Errors propagate: rf_plugins records them as a gps component
        # failure — a silent drop here would be an invisible blind spot.
        self.store.record_observation(**rec)

    def ingest_kismet(self, kdb: Any, recent_window_s: float = 120.0) -> Optional[GpsFix]:
        """Pull located devices + the operator fix for this cycle.

        Records one ``gps_fix`` observation for the operator fix and one
        ``wifi_device`` observation per located device. Device location
        sightings are keyed by haversine place id. Returns the operator
        fix, or None when no located fix exists this cycle.
        """
        if not self.enabled:
            return None
        now = time.time()
        self._cycle_counter += 1
        try:
            devices = kdb.get_devices_by_time_range(now - recent_window_s)
        except Exception as e:
            logger.debug("gps ingest devices failed: %s", e)
            return None

        best: Optional[GpsFix] = None
        located: List[Tuple[str, float, float, float]] = []
        for d in devices:
            dd = d.get("device_data") or {}
            extracted = extract_gps_from_device_json(dd)
            if not extracted:
                continue
            lat, lon, ts = extracted
            fix = GpsFix(lat=lat, lon=lon, ts=ts, source="kismet_device")
            if best is None or ts > best.ts:
                best = fix
            # record device at its haversine place
            mac = (d.get("mac") or "").upper()
            if mac:
                located.append((mac, lat, lon, ts))
                self._record_observation(
                    source="kismet.devices",
                    kind="wifi_device",
                    identity_key=mac,
                    ts=ts,
                    lat=lat,
                    lon=lon,
                    payload={},
                )

        if best is None:
            return None

        self.last_fix = best
        operator_anchor = self._place_id(best.lat, best.lon, best.ts)
        if (
            not self.operator_path
            or self.operator_path[-1].cluster_id != operator_anchor.cluster_id
        ):
            self.operator_path.append(operator_anchor)
        self._record_observation(
            source="gps",
            kind="gps_fix",
            identity_key="operator",
            ts=best.ts,
            lat=best.lat,
            lon=best.lon,
            payload={"device_source": best.source},
        )
        for mac, lat, lon, ts in located:
            place = self._place_id(lat, lon, ts)
            self.store.record_location_sighting(
                "wifi_mac", mac, place.cluster_id, lat, lon, ts
            )
        self.store.set_runtime(
            "last_gps",
            json.dumps({"lat": best.lat, "lon": best.lon, "ts": best.ts}),
        )
        self.store.set_runtime("last_gps_cluster", operator_anchor.cluster_id)
        return best

    def score_cotravel(self, now: Optional[float] = None) -> List[dict]:
        """
        Entities seen in >= min_locations clusters along operator path.
        Writes/updates cotravel table; returns top results.
        """
        if not self.enabled:
            return []
        now = now or time.time()
        rows = self.store.conn.execute(
            """
            SELECT entity_type, entity_key,
                   COUNT(DISTINCT location_id) AS location_count,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen,
                   SUM(see_count) AS sees
            FROM location_sightings
            GROUP BY entity_type, entity_key
            HAVING location_count >= ?
            """,
            (self.min_locations,),
        ).fetchall()
        results = []
        for r in rows:
            span = float(r["last_seen"]) - float(r["first_seen"])
            if span < self.min_span_s:
                continue
            # score: locations * log(span hours) * log(sees)
            locs = int(r["location_count"])
            sees = int(r["sees"] or 1)
            score = min(1.0, (locs / 5.0) * 0.5 + min(span / 3600.0, 6) / 12.0 + min(sees, 20) / 40.0)
            detail = {
                "locations": locs,
                "span_hours": round(span / 3600.0, 2),
                "sees": sees,
            }
            self.store.upsert_cotravel(
                r["entity_type"],
                r["entity_key"],
                location_count=locs,
                score=score,
                first_seen=float(r["first_seen"]),
                last_seen=float(r["last_seen"]),
                detail=detail,
            )
            results.append(
                {
                    "entity_type": r["entity_type"],
                    "entity_key": r["entity_key"],
                    "location_count": locs,
                    "score": score,
                    "detail": detail,
                }
            )
            # Raise durable incident for high co-travel
            if score >= float(self.cfg.get("incident_score_threshold") or 0.55):
                self.store.observe_incident(
                    event_type="cotravel",
                    subject=r["entity_key"],
                    window_label="multi-loc",
                    severity="alert" if score >= 0.75 else "watch",
                    session_id=self.store.get_runtime("session_id") or "gps",
                    observed_at=now,
                    summary=f"cotravel score={score:.2f} locs={locs}",
                    detail=detail,
                    entity_type=r["entity_type"],
                    evidence={
                        "reasons": [
                            f"Co-traveled across {locs} location clusters",
                            f"span {detail['span_hours']}h",
                            f"score={score:.2f}",
                        ],
                        "kind": "cotravel",
                        "subject_fp": abs(hash(r["entity_key"])) % 0xFFFFFFFF,
                    },
                )
        results.sort(key=lambda x: x["score"], reverse=True)
        return results
