"""
P3: IE / probe-set fingerprinting to re-link randomized MACs.

Builds a stable-ish fingerprint from Kismet device JSON fields:
  - ordered probe SSID set
  - advertised IE tag IDs / HT/VHT caps when present
  - manufacturer OUI class (when not randomized)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


def _walk_ie_tags(obj: Any, found: Optional[Set[int]] = None) -> Set[int]:
    found = found if found is not None else set()
    if isinstance(obj, dict):
        # common patterns
        for k, v in obj.items():
            kl = k.lower()
            if "ie" in kl and "tag" in kl and isinstance(v, (int, float)):
                found.add(int(v))
            if kl.endswith(".tag") or kl.endswith("tag_number"):
                try:
                    found.add(int(v))
                except (TypeError, ValueError):
                    pass
            if isinstance(v, (dict, list)):
                _walk_ie_tags(v, found)
    elif isinstance(obj, list):
        for x in obj:
            _walk_ie_tags(x, found)
    return found


def extract_probe_ssids(device_data: dict) -> List[str]:
    ssids: List[str] = []
    if not device_data:
        return ssids
    try:
        dot11 = device_data.get("dot11.device") or {}
        # last probed
        last = dot11.get("dot11.device.last_probed_ssid_record") or {}
        s = last.get("dot11.probedssid.ssid")
        if s:
            ssids.append(str(s))
        # map of probed
        probed = dot11.get("dot11.device.probed_ssid_map") or {}
        if isinstance(probed, dict):
            for _k, rec in probed.items():
                if isinstance(rec, dict):
                    s2 = rec.get("dot11.probedssid.ssid")
                    if s2:
                        ssids.append(str(s2))
    except Exception:
        pass
    # unique stable order
    return sorted(set(ssids))


def extract_ie_fingerprint(device_data: dict) -> Optional[Dict[str, Any]]:
    """Return fingerprint dict or None if insufficient signal."""
    if not device_data:
        return None
    ssids = extract_probe_ssids(device_data)
    tags = sorted(_walk_ie_tags(device_data.get("dot11.device") or device_data))

    # HT/VHT/HE capability fragments if present
    caps = []
    for key in (
        "dot11.device.ht_capability",
        "dot11.device.vht_capability",
        "dot11.device.he_capability",
        "dot11ht.capability",
    ):
        # search nested
        pass

    def find_caps(obj, acc):
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower()
                if any(x in kl for x in ("ht_cap", "vht_cap", "he_cap", "extended_capabilities")):
                    acc.append(f"{k}={v}" if not isinstance(v, (dict, list)) else k)
                find_caps(v, acc)
        elif isinstance(obj, list):
            for x in obj:
                find_caps(x, acc)

    find_caps(device_data, caps)
    caps = sorted(set(caps))[:40]

    # Need enough distinctiveness
    if len(ssids) < 1 and len(tags) < 3 and len(caps) < 1:
        return None

    features = {
        "probe_ssids": ssids,
        "ie_tags": tags[:64],
        "caps": caps,
    }
    raw = json.dumps(features, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return {"hash": h, "features": features, "raw": raw}


class IEFingerprintEngine:
    def __init__(self, store: Any, config: dict):
        self.store = store
        self.cfg = config.get("ie_fingerprint") or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.min_ssids = int(self.cfg.get("min_probe_ssids") or 1)

    def process_devices(self, devices: List[dict], now: Optional[float] = None) -> int:
        """Link devices to fingerprints. Returns number of new links."""
        if not self.enabled:
            return 0
        now = now or time.time()
        links = 0
        for d in devices:
            mac = (d.get("mac") or "").upper()
            dd = d.get("device_data") or {}
            if not mac:
                continue
            fp = extract_ie_fingerprint(dd)
            if not fp:
                continue
            if len(fp["features"].get("probe_ssids") or []) < self.min_ssids and len(
                fp["features"].get("ie_tags") or []
            ) < 3:
                continue
            fid = self.store.upsert_fingerprint(
                "ie_probe", fp["hash"], fp["features"], now
            )
            eid = self.store.upsert_entity("wifi_mac", mac, now)
            if self.store.link_entity_fingerprint(eid, fid, confidence=0.7):
                links += 1
            # If this fingerprint already linked to other MACs, note multi-mac identity
            others = self.store.entities_for_fingerprint(fid)
            if len(others) >= 2:
                self.store.observe_incident(
                    event_type="ie_relink",
                    subject=fp["hash"],
                    window_label="identity",
                    severity="watch",
                    session_id=self.store.get_runtime("session_id") or "ie",
                    observed_at=now,
                    summary=f"IE fingerprint linked to {len(others)} MACs",
                    detail={"mac_count": len(others), "fp": fp["hash"]},
                    entity_type="fingerprint",
                    evidence={
                        "reasons": [
                            f"Same IE/probe fingerprint seen on {len(others)} MACs",
                            "Possible randomized-MAC re-link",
                            f"fp={fp['hash'][:12]}…",
                        ],
                        "kind": "ie_relink",
                        "subject_fp": fp["hash"][:16],
                    },
                )
        return links
