"""P2: Live GPS extraction from Kismet + co-travel scoring."""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class GpsFix:
    lat: float
    lon: float
    ts: float
    alt: Optional[float] = None
    source: str = "kismet"


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def cluster_id(lat: float, lon: float, precision: int = 3) -> str:
    """~100m-ish grid cell id at precision=3."""
    return f"g_{lat:.{precision}f}_{lon:.{precision}f}"


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
    """Track operator path from Kismet GPS + score co-traveling devices."""

    def __init__(self, store: Any, config: dict):
        self.store = store
        self.cfg = config.get("gps_fusion") or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.cluster_m = float(self.cfg.get("cluster_meters") or 100)
        self.min_locations = int(self.cfg.get("min_locations_for_cotravel") or 2)
        self.min_span_s = float(self.cfg.get("min_span_seconds") or 900)
        self.last_fix: Optional[GpsFix] = None
        self.operator_clusters: List[str] = []

    def ingest_kismet(self, kdb: Any, recent_window_s: float = 120.0) -> Optional[GpsFix]:
        if not self.enabled:
            return None
        now = time.time()
        try:
            devices = kdb.get_devices_by_time_range(now - recent_window_s)
        except Exception as e:
            logger.debug("gps ingest devices failed: %s", e)
            return None

        best: Optional[GpsFix] = None
        for d in devices:
            dd = d.get("device_data") or {}
            extracted = extract_gps_from_device_json(dd)
            if not extracted:
                continue
            lat, lon, ts = extracted
            fix = GpsFix(lat=lat, lon=lon, ts=ts, source="kismet_device")
            if best is None or ts > best.ts:
                best = fix
            # record device at cluster
            mac = (d.get("mac") or "").upper()
            if mac:
                loc_id = cluster_id(lat, lon)
                self.store.record_location_sighting(
                    "wifi_mac", mac, loc_id, lat, lon, ts or now
                )

        if best:
            self.last_fix = best
            loc_id = cluster_id(best.lat, best.lon)
            if not self.operator_clusters or self.operator_clusters[-1] != loc_id:
                self.operator_clusters.append(loc_id)
            self.store.set_runtime("last_gps", json.dumps({"lat": best.lat, "lon": best.lon, "ts": best.ts}))
            self.store.set_runtime("last_gps_cluster", loc_id)
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
