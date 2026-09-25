"""D5: Live GPS extraction from Kismet + co-travel scoring on operator path.

Location geometry lives in cyt_platform/location.py (pure, replayable);
this module is the live adapter: it extracts GPS fixes from Kismet device
JSON, clusters them into haversine-radius places (replacing 0.001° grid
cells, whose boundary pairs 10 m apart over-counted locations), records
observations through the CytStore API, and scores co-travel against the
operator's own visited places — the audit's docstring-lie fix.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cyt_platform.detectors import (
    DetectionResult,
    EvidenceLine,
    incident_fields,
)
from cyt_platform.fused_evidence import attach as attach_fusion
from cyt_platform.location import (
    DEFAULT_DENSITY_WINDOW_S,
    DEFAULT_MERGE_RADIUS_M,
    DEFAULT_MAX_SPEED_MPS,
    DEFAULT_REVISIT_GAP_S,
    Sighting,
    attendance,
    cotravel_matches,
    haversine_m,
    independent_visits,
    stable_cluster_id,
)

logger = logging.getLogger(__name__)

# How far back co-travel scoring looks for observations. Co-travel is a
# multi-place relationship, not a single-cycle event.
COTRAVEL_LOOKBACK_S = 6 * 3600.0


def _cotravel_result(
    key: str,
    locs: int,
    score: float,
    detail: dict,
    now: float,
) -> DetectionResult:
    """Build the contract result for one high-confidence co-travel score.

    Pure: no store access. Severity mapping, reason strings, and the
    subject fingerprint are unchanged from the pre-contract engine
    (including its deterministic sha1-based fingerprint). ``confidence``
    carries the co-travel score — co-travel has a real computed score,
    unlike the capture-scan detectors.

    S2/D4: each matched operator visit with ambient bystanders also emits
    a ``density`` CONTRA line (a count — never an identifier), so the
    against block is populated on the live path and crowded places
    discount tracking confidence through the D4 model.
    """
    visits = detail.get("operator_visits") or []
    contra = tuple(
        EvidenceLine(
            "density",
            f"Ambient density {int(visit.get('density') or 0)} other device(s) "
            f"near operator visit #{position}",
        )
        for position, visit in enumerate(
            sorted(
                visits, key=lambda item: float(item.get("enter_ts") or 0.0)
            ),
            start=1,
        )
        if int(visit.get("density") or 0) > 0
    )
    return DetectionResult(
        detector="cotravel",
        kind="cotravel",
        subject=key,
        subject_type="wifi_mac",
        window_label="multi-loc",
        severity="alert" if score >= 0.75 else "watch",
        observed_at=now,
        summary=f"cotravel score={score:.2f} locs={locs}",
        detail=detail,
        evidence=(
            EvidenceLine(
                "copresence",
                f"Co-located with the operator at {locs} distinct places",
            ),
            EvidenceLine(
                "travel_span", f"co-travel span {detail['span_hours']}h"
            ),
            EvidenceLine("score", f"score={score:.2f}"),
        ),
        contra=contra,
        confidence=score,
        subject_fp=int(hashlib.sha1(key.encode("utf-8")).hexdigest()[:8], 16),
    )


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


def extract_gps_from_device_json(
    device_data: dict,
    now: Optional[float] = None,
    row_ts: Optional[float] = None,
) -> Optional[Tuple[float, float, float]]:
    """Return (lat, lon, ts) if device JSON has location.

    Timestamp provenance (S6): the location block's own stamp when present
    (``kismet.common.location.time_sec`` / ``time``), else the device
    record's ``kismet.device.base.last_time``, else ``row_ts`` (the pull
    row's last_time), else the caller's injected cycle clock ``now``. The
    wall clock is read only when the caller injects nothing — under replay
    a wall-clock stamp lands far outside the scenario clock and silently
    zeroes detection.
    """
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
    ts = loc.get("kismet.common.location.time_sec") or loc.get("time")
    if ts is None:
        # S6: no location stamp — fall back to the device record's own
        # last_time, never the wall clock.
        ts = device_data.get("kismet.device.base.last_time")
    if ts is None and row_ts is not None:
        ts = row_ts
    if ts is None and now is not None:
        ts = now
    try:
        ts_f = float(ts)
    except (TypeError, ValueError):
        ts_f = float(now) if now is not None else time.time()
    if not ts_f > 0:
        ts_f = float(now) if now is not None else time.time()
    return lat_f, lon_f, ts_f


def _sighting_from_row(row: dict, identity: str) -> Sighting:
    """One located observation row -> geometry Sighting (CytStore API dicts)."""
    return Sighting(
        ts=float(row["ts"]),
        lat=float(row["lat"]),
        lon=float(row["lon"]),
        accuracy_m=float(row.get("accuracy_m") or 0.0),
        identity_key=identity,
    )


def _sightings_from_rows(rows: List[dict], identity: str) -> List[Sighting]:
    """Located observation rows -> Sighting list (drops unlocated rows)."""
    out: List[Sighting] = []
    for row in rows:
        if row.get("lat") is None or row.get("lon") is None:
            continue
        out.append(_sighting_from_row(row, identity))
    return out


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
        self.max_speed_mps = float(
            self.cfg.get("max_speed_mps") or DEFAULT_MAX_SPEED_MPS
        )
        self.density_window_s = float(
            self.cfg.get("density_window_s") or DEFAULT_DENSITY_WINDOW_S
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
        recorded_ts: Optional[float] = None,
    ) -> None:
        """Persist one located observation through the CytStore API (D1).

        ``recorded_ts`` carries the caller's cycle clock so the store's
        recorded_at column never drifts to wall time under replay (S6).
        """
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
            if rec is not None and recorded_ts is not None:
                rec["recorded_ts"] = float(recorded_ts)
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
                "recorded_ts": float(recorded_ts) if recorded_ts is not None else None,
            }
        if rec is None:
            return
        # Errors propagate: rf_plugins records them as a gps component
        # failure — a silent drop here would be an invisible blind spot.
        self.store.record_observation(**rec)

    def ingest_kismet(
        self, kdb: Any, recent_window_s: float = 120.0, now: Optional[float] = None
    ) -> Optional[GpsFix]:
        """Pull located devices + the operator fix for this cycle.

        Records one ``gps_fix`` observation for the operator fix and one
        ``wifi_device`` observation per located device. Device location
        sightings are keyed by haversine place id. Returns the operator
        fix, or None when no located fix exists this cycle. ``now`` is the
        caller's cycle clock — injected by replay so the pull window is
        scenario time; wall clock when omitted (live path unchanged).
        """
        if not self.enabled:
            return None
        if now is None:
            now = time.time()
        else:
            now = float(now)
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
            extracted = extract_gps_from_device_json(
                dd, now=now, row_ts=d.get("last_time")
            )
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
                    recorded_ts=now,
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
            recorded_ts=now,
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

    def score_cotravel(
        self,
        now: Optional[float] = None,
        obs_index: Optional[Any] = None,
    ) -> List[dict]:
        """Score entities co-present with the operator at distinct places.

        Co-travel requires the operator's own path: an entity is scored
        only when it was co-located (within the merge radius, with
        overlapping time) with at least ``min_locations`` DISTINCT
        operator visits. A device seen at two places the operator never
        visited does not co-travel — this is the audit's docstring-lie
        fix, where the SQL counted cells with no operator join at all.

        ``obs_index`` (B6) is the cycle's provenance index; when given, the
        emitted result's evidence lines cite the subject's located device
        observations recorded this cycle.

        Sightings are read from canonical observations via the CytStore
        API only. Writes/updates the cotravel table and returns scored
        results sorted by score.
        """
        if not self.enabled:
            return []
        now = now or time.time()
        lookback_s = float(self.cfg.get("cotravel_lookback_s") or COTRAVEL_LOOKBACK_S)
        since = now - lookback_s

        from cyt_platform import observations as obs  # lazy: obs imports this module

        op_rows = self.store.query_observations(
            identity_key=obs.OPERATOR_IDENTITY,
            source=obs.SOURCE_GPS,
            kind=obs.KIND_GPS_FIX,
            since=since,
            limit=5000,
        )
        op_sightings = _sightings_from_rows(op_rows, identity=obs.OPERATOR_IDENTITY)
        if len(op_sightings) < 2:
            return []  # no operator path yet — nothing can co-travel with it
        op_visits = independent_visits(
            op_sightings,
            merge_radius_m=self.merge_radius_m,
            revisit_gap_s=self.revisit_gap_s,
            max_speed_mps=self.max_speed_mps,
        )
        if not op_visits:
            return []

        device_rows = self.store.query_observations(
            source=obs.SOURCE_KISMET_DEVICES,
            kind=obs.KIND_WIFI_DEVICE,
            since=since,
            limit=5000,
        )
        by_identity: Dict[str, List[Sighting]] = {}
        for row in device_rows:
            if row.get("lat") is None or row.get("lon") is None:
                continue
            key = row.get("identity_key") or ""
            if not key or key == obs.OPERATOR_IDENTITY:
                continue
            if self.store.entity_is_ignored("wifi_mac", key):
                continue
            by_identity.setdefault(key, []).append(_sighting_from_row(row, key))

        results: List[dict] = []
        # Density context: all located device sightings, so bystander
        # counts around each operator visit can be recorded per visit.
        all_device_sightings = [
            s for group in by_identity.values() for s in group
        ]
        for key in sorted(by_identity):
            sightings = by_identity[key]
            entity_visits = independent_visits(
                sightings,
                merge_radius_m=self.merge_radius_m,
                revisit_gap_s=self.revisit_gap_s,
                max_speed_mps=self.max_speed_mps,
            )
            matches = cotravel_matches(
                entity_visits,
                op_visits,
                merge_radius_m=self.merge_radius_m,
                revisit_gap_s=self.revisit_gap_s,
            )
            # Distinct operator visits co-presenced (an entity may match the
            # same operator visit with several of its own visits).
            matched_ops = {(ov.enter_ts, ov.cluster_id) for _, ov in matches}
            locs = len(matched_ops)
            if locs < self.min_locations:
                continue
            first_ts = min(ev.enter_ts for ev, _ in matches)
            last_ts = max(
                (ev.exit_ts if ev.exit_ts is not None else ev.enter_ts)
                for ev, _ in matches
            )
            span = last_ts - first_ts
            if span < self.min_span_s:
                continue
            sees = len(sightings)
            score = min(
                1.0,
                (locs / 5.0) * 0.5
                + min(span / 3600.0, 6) / 12.0
                + min(sees, 20) / 40.0,
            )
            detail = {
                "locations": locs,
                "span_hours": round(span / 3600.0, 2),
                "sees": sees,
                "operator_visits": [
                    {
                        "enter_ts": ov.enter_ts,
                        "lat": round(ov.lat, 6),
                        "lon": round(ov.lon, 6),
                        "cluster_id": ov.cluster_id,
                        # Density context: distinct other devices near this
                        # operator visit (subject + operator excluded), so
                        # the confidence model can discount crowded sites.
                        "density": attendance(
                            all_device_sightings,
                            lat=ov.lat,
                            lon=ov.lon,
                            from_ts=ov.enter_ts - self.density_window_s,
                            to_ts=(
                                ov.exit_ts
                                if ov.exit_ts is not None
                                else ov.enter_ts
                            )
                            + self.density_window_s,
                            radius_m=self.merge_radius_m,
                            exclude=(key, obs.OPERATOR_IDENTITY),
                        ),
                    }
                    for _, ov in sorted(matches, key=lambda m: m[1].enter_ts)
                ],
            }
            self.store.upsert_cotravel(
                "wifi_mac",
                key,
                location_count=locs,
                score=score,
                first_seen=first_ts,
                last_seen=last_ts,
                detail=detail,
            )
            results.append(
                {
                    "entity_type": "wifi_mac",
                    "entity_key": key,
                    "location_count": locs,
                    "score": score,
                    "detail": detail,
                }
            )
            # Raise durable incident for high co-travel
            if score >= float(self.cfg.get("incident_score_threshold") or 0.55):
                result = _cotravel_result(key, locs, score, detail, now)
                # B6: cite this cycle's located device observations for the
                # co-traveling subject (obs is lazily imported above).
                if obs_index is not None:
                    result = obs.attach_obs_ids(
                        result, obs_index.ids_for_identity(key)
                    )
                fields = incident_fields(
                    result,
                    session_id=self.store.get_runtime("session_id") or "gps",
                )
                # D4: evidence additionally carries the fused why/against block.
                attach_fusion(fields, result)
                self.store.observe_incident(**fields)
        results.sort(key=lambda x: x["score"], reverse=True)
        return results
