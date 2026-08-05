"""
Baseline learning — home/work/commute filtering (P1).

Suppresses threat contribution for entities that are normal for a place.
Learning: sightings while current_place is set; after min_sightings → baseline.
Manual: mark_false / mark_baseline via CLI.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Place:
    place_id: str
    name: str
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius_m: float = 150.0
    hours: Optional[List[List[int]]] = None  # [[start_hour, end_hour], ...] local


def places_from_config(config: dict) -> Dict[str, Place]:
    bl = config.get("baseline") or {}
    out: Dict[str, Place] = {}
    for pid, raw in (bl.get("places") or {}).items():
        if not isinstance(raw, dict):
            continue
        out[pid] = Place(
            place_id=pid,
            name=raw.get("name") or pid,
            lat=raw.get("lat"),
            lon=raw.get("lon"),
            radius_m=float(raw.get("radius_m") or 150),
            hours=raw.get("hours"),
        )
    return out


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    from math import radians, sin, cos, sqrt, atan2

    r = 6371000.0
    p1, p2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dl = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(p1) * cos(p2) * sin(dl / 2) ** 2
    return 2 * r * atan2(sqrt(a), sqrt(1 - a))


def resolve_place(
    config: dict,
    *,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    now: Optional[float] = None,
) -> Optional[str]:
    """
    Resolve current place id:
      1. baseline.current_place override
      2. runtime GPS lat/lon vs geofences
      3. None
    """
    bl = config.get("baseline") or {}
    if bl.get("current_place"):
        return str(bl["current_place"])
    if lat is None or lon is None:
        return None
    places = places_from_config(config)
    best: Optional[Tuple[float, str]] = None
    for p in places.values():
        if p.lat is None or p.lon is None:
            continue
        d = haversine_m(lat, lon, p.lat, p.lon)
        if d <= p.radius_m:
            if best is None or d < best[0]:
                best = (d, p.place_id)
    if best is None:
        return None
    place = places[best[1]]
    if place.hours:
        hour = datetime.fromtimestamp(now or time.time()).hour
        ok = False
        for window in place.hours:
            if len(window) >= 2 and window[0] <= hour < window[1]:
                ok = True
                break
        if not ok:
            return None
    return best[1]


class BaselineEngine:
    def __init__(self, store: Any, config: dict):
        self.store = store
        self.config = config
        self.cfg = config.get("baseline") or {}
        self.enabled = bool(self.cfg.get("enabled", False))
        self.min_sightings = int(self.cfg.get("min_sightings") or 5)
        self.places = places_from_config(config)
        self._cache: Set[Tuple[str, str, str]] = set()  # place, type, key
        if self.enabled:
            self._reload_cache()

    def _reload_cache(self) -> None:
        self._cache.clear()
        for row in self.store.list_baselines():
            # list_baselines returns decrypted keys
            self._cache.add((row["place_id"], row["entity_type"], row["entity_key"]))

    def is_baselined(
        self, place_id: Optional[str], entity_type: str, entity_key: str
    ) -> bool:
        if not self.enabled:
            return False
        # global ignore always suppresses
        if self.store.entity_is_ignored(entity_type, entity_key):
            return True
        if not place_id:
            return False
        key = entity_key.upper() if entity_type == "wifi_mac" else entity_key
        if (place_id, entity_type, key) in self._cache:
            return True
        # also try original casing
        return (place_id, entity_type, entity_key) in self._cache

    def should_suppress_threat(
        self,
        entity_type: str,
        entity_key: str,
        place_id: Optional[str],
    ) -> bool:
        return self.is_baselined(place_id, entity_type, entity_key)

    def record_sighting(
        self,
        place_id: Optional[str],
        entity_type: str,
        entity_key: str,
        ts: Optional[float] = None,
    ) -> Optional[str]:
        """
        Record sighting for learning. Returns 'learned' if newly baselined.
        """
        if not self.enabled or not place_id:
            return None
        ts = ts or time.time()
        key = entity_key.upper() if entity_type == "wifi_mac" else entity_key
        count = self.store.bump_baseline_sighting(
            place_id, entity_type, key, ts
        )
        if count >= self.min_sightings:
            created = self.store.ensure_baseline(
                place_id,
                entity_type,
                key,
                ts,
                source="learned",
                sighting_count=count,
            )
            self._cache.add((place_id, entity_type, key))
            return "learned" if created else "already"
        return None

    def mark_manual(
        self,
        place_id: str,
        entity_type: str,
        entity_key: str,
        *,
        source: str = "manual",
    ) -> None:
        key = entity_key.upper() if entity_type == "wifi_mac" else entity_key
        self.store.ensure_baseline(
            place_id,
            entity_type,
            key,
            time.time(),
            source=source,
            sighting_count=self.min_sightings,
        )
        if source == "mark_false":
            self.store.set_entity_ignore(entity_type, key, True)
        self._cache.add((place_id, entity_type, key))

    def forget(
        self, place_id: str, entity_type: str, entity_key: str
    ) -> int:
        key = entity_key.upper() if entity_type == "wifi_mac" else entity_key
        n = self.store.delete_baseline(place_id, entity_type, key)
        self._cache.discard((place_id, entity_type, key))
        self._cache.discard((place_id, entity_type, entity_key))
        return n

    def explain_suppression(
        self, place_id: Optional[str], entity_type: str, entity_key: str
    ) -> List[str]:
        reasons = []
        if self.store.entity_is_ignored(entity_type, entity_key):
            reasons.append("entity marked ignore / mark_false")
        if place_id and (place_id, entity_type, entity_key) in self._cache:
            reasons.append(f"baseline for place={place_id}")
        return reasons
