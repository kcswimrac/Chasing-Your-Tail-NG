"""
P3: BLE / BTLE tracker-style detection from Kismet devices.

Flags devices that look like AirTag/Tile/SmartTag style trackers and
persists them via the same incident/entity path.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, List, Optional, Set

logger = logging.getLogger(__name__)

# Heuristic name / type tokens (passive detection only)
TRACKER_NAME_RE = re.compile(
    r"(airtag|tile|smarttag|smart.?tag|galaxy.?smarttag|chipolo|eufy|trackr|pebblebee)",
    re.I,
)
TRACKER_TYPE_HINTS = (
    "btle",
    "bluetooth",
    "bt device",
    "ble device",
)


def _device_type_str(device: dict, device_data: dict) -> str:
    t = device.get("type") or ""
    if device_data:
        t = t or device_data.get("kismet.device.base.type") or ""
        t = t or device_data.get("kismet.device.base.phyname") or ""
    return str(t).lower()


def _device_name(device_data: dict) -> str:
    if not device_data:
        return ""
    for k in (
        "kismet.device.base.commonname",
        "kismet.device.base.name",
        "kismet.device.base.manuf",
    ):
        v = device_data.get(k)
        if v:
            return str(v)
    return ""


def is_ble_device(device: dict, device_data: dict) -> bool:
    t = _device_type_str(device, device_data)
    if any(h in t for h in TRACKER_TYPE_HINTS):
        return True
    if device_data and any(
        "btle" in str(k).lower() or "bluetooth" in str(k).lower()
        for k in device_data.keys()
    ):
        return True
    return False


def tracker_score(device: dict, device_data: dict) -> tuple[float, List[str]]:
    """Return (score 0-1, reasons)."""
    reasons: List[str] = []
    score = 0.0
    if not is_ble_device(device, device_data):
        return 0.0, reasons
    score += 0.25
    reasons.append("BLE/BTLE PHY")
    name = _device_name(device_data)
    if TRACKER_NAME_RE.search(name):
        score += 0.55
        reasons.append(f"name/manuf matches tracker pattern ({name[:40]})")
    # Apple Continuity / Find My often use specific company IDs — if present in JSON
    blob = json_dumps_safe(device_data).lower()
    if "find my" in blob or "findmy" in blob or "continuity" in blob:
        score += 0.35
        reasons.append("Find My / Continuity hints in advertisement metadata")
    if "airtag" in blob:
        score += 0.4
        reasons.append("AirTag token in device metadata")
    return min(score, 1.0), reasons


def json_dumps_safe(obj) -> str:
    try:
        import json

        return json.dumps(obj)
    except Exception:
        return str(obj)


class BLETrackerEngine:
    def __init__(self, store: Any, config: dict):
        self.store = store
        self.cfg = config.get("ble_tracker") or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.min_score = float(self.cfg.get("min_score") or 0.5)
        self._seen: Set[str] = set()

    def process_devices(self, devices: List[dict], now: Optional[float] = None) -> int:
        if not self.enabled:
            return 0
        now = now or time.time()
        hits = 0
        for d in devices:
            mac = (d.get("mac") or "").upper()
            dd = d.get("device_data") or {}
            if not mac:
                continue
            score, reasons = tracker_score(d, dd)
            if score < self.min_score:
                # still track generic BLE as entity without incident
                if is_ble_device(d, dd):
                    self.store.upsert_entity(
                        "ble", mac, now, meta={"name": _device_name(dd)}
                    )
                continue
            self.store.upsert_entity(
                "ble_tracker", mac, now, meta={"score": score, "name": _device_name(dd)}
            )
            sev = "alert" if score >= 0.8 else "watch"
            self.store.observe_incident(
                event_type="ble_tracker",
                subject=mac,
                window_label="ble",
                severity=sev,
                session_id=self.store.get_runtime("session_id") or "ble",
                observed_at=now,
                summary=f"ble_tracker score={score:.2f}",
                detail={"score": score, "name": _device_name(dd)},
                entity_type="ble_tracker",
                evidence={
                    "reasons": reasons + [f"score={score:.2f}"],
                    "kind": "ble_tracker",
                    "subject_fp": abs(hash(mac)) % 0xFFFFFFFF,
                },
            )
            hits += 1
        return hits
