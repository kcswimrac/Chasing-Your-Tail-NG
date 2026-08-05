"""P3: Orchestrate deauth, rogue AP, IE fingerprint, BLE plugins each cycle."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class RFPluginRunner:
    def __init__(self, store: Any, config: dict):
        self.store = store
        self.config = config
        self.deauth = None
        self.rogue = None
        self.ie = None
        self.ble = None
        self.gps = None
        self._init_plugins()

    def _init_plugins(self) -> None:
        rf = self.config.get("rf") or {}
        if rf.get("deauth_enabled", True):
            try:
                from deauth_detector import DeauthDetector

                self.deauth = DeauthDetector(self.config)
            except Exception as e:
                logger.warning("DeauthDetector unavailable: %s", e)
        if rf.get("rogue_enabled", True):
            try:
                from rogue_ap_detector import RogueAPDetector

                self.rogue = RogueAPDetector(self.config)
            except Exception as e:
                logger.warning("RogueAPDetector unavailable: %s", e)
        if (self.config.get("ie_fingerprint") or {}).get("enabled", True):
            from cyt_platform.ie_fingerprint import IEFingerprintEngine

            self.ie = IEFingerprintEngine(self.store, self.config)
        if (self.config.get("ble_tracker") or {}).get("enabled", True):
            from cyt_platform.ble_tracker import BLETrackerEngine

            self.ble = BLETrackerEngine(self.store, self.config)
        if (self.config.get("gps_fusion") or {}).get("enabled", True):
            from cyt_platform.gps_live import LiveGpsFusion

            self.gps = LiveGpsFusion(self.store, self.config)

    def run_cycle(
        self, kdb: Any, db_path: str, recent_window_s: float = 120.0
    ) -> Dict[str, Any]:
        now = time.time()
        stats: Dict[str, Any] = {
            "deauth_events": 0,
            "rogue_alerts": 0,
            "ie_links": 0,
            "ble_hits": 0,
            "cotravel": 0,
            "gps": None,
        }
        try:
            devices = kdb.get_devices_by_time_range(now - recent_window_s)
        except Exception as e:
            logger.debug("rf plugins device pull failed: %s", e)
            devices = []

        # GPS + co-travel
        if self.gps:
            try:
                fix = self.gps.ingest_kismet(kdb, recent_window_s)
                if fix:
                    stats["gps"] = {"lat": fix.lat, "lon": fix.lon}
                co = self.gps.score_cotravel(now)
                stats["cotravel"] = len(co)
            except Exception as e:
                logger.warning("gps fusion error: %s", e)

        # IE + BLE on same device set
        if self.ie:
            try:
                stats["ie_links"] = self.ie.process_devices(devices, now)
            except Exception as e:
                logger.warning("ie fingerprint error: %s", e)
        if self.ble:
            try:
                stats["ble_hits"] = self.ble.process_devices(devices, now)
            except Exception as e:
                logger.warning("ble tracker error: %s", e)

        # Deauth / rogue — use file path APIs from CM5 modules
        if self.deauth:
            try:
                events = self.deauth.scan_kismet_db(db_path)
                stats["deauth_events"] = len(events or [])
                attacks = []
                if hasattr(self.deauth, "analyze_attacks"):
                    attacks = self.deauth.analyze_attacks() or []
                elif hasattr(self.deauth, "attacks"):
                    attacks = self.deauth.attacks or []
                for atk in attacks[-20:]:
                    self._incident_from_deauth(atk, now)
            except Exception as e:
                logger.warning("deauth scan error: %s", e)

        if self.rogue:
            try:
                if hasattr(self.rogue, "scan_kismet_db"):
                    alerts = self.rogue.scan_kismet_db(db_path)
                else:
                    alerts = []
                stats["rogue_alerts"] = len(alerts or [])
                for al in (alerts or [])[-20:]:
                    self._incident_from_rogue(al, now)
            except Exception as e:
                logger.warning("rogue scan error: %s", e)

        return stats

    def _incident_from_deauth(self, atk: Any, now: float) -> None:
        sev_map = {
            "LOW": "watch",
            "MEDIUM": "watch",
            "HIGH": "alert",
            "CRITICAL": "alert",
        }
        severity = sev_map.get(getattr(atk, "severity", "MEDIUM"), "watch")
        target = getattr(atk, "target_mac", "?")
        attacker = getattr(atk, "attacker_mac", "?")
        self.store.observe_incident(
            event_type="deauth_attack",
            subject=str(target).upper(),
            window_label="deauth",
            severity=severity,
            session_id=self.store.get_runtime("session_id") or "rf",
            observed_at=getattr(atk, "last_seen", None) or now,
            summary=f"deauth {getattr(atk, 'attack_type', 'attack')}",
            detail={
                "attacker": str(attacker).upper(),
                "frames": getattr(atk, "total_frames", 0),
                "severity_raw": getattr(atk, "severity", ""),
            },
            entity_type="wifi_mac",
            evidence={
                "reasons": [
                    f"Deauth/disassoc pattern toward {str(target)[:17]}",
                    f"type={getattr(atk, 'attack_type', '?')} frames={getattr(atk, 'total_frames', 0)}",
                    f"source severity={getattr(atk, 'severity', '?')}",
                ],
                "kind": "deauth_attack",
            },
        )

    def _incident_from_rogue(self, al: Any, now: float) -> None:
        sev_map = {
            "LOW": "watch",
            "MEDIUM": "watch",
            "HIGH": "alert",
            "CRITICAL": "alert",
        }
        severity = sev_map.get(getattr(al, "severity", "HIGH"), "alert")
        ssid = getattr(al, "ssid", "?")
        bssid = getattr(al, "rogue_bssid", "?")
        reasons = list(getattr(al, "reasons", None) or ["Rogue/evil-twin AP detected"])
        self.store.observe_incident(
            event_type="rogue_ap",
            subject=str(bssid).upper(),
            window_label="ap",
            severity=severity,
            session_id=self.store.get_runtime("session_id") or "rf",
            observed_at=getattr(al, "timestamp", None) or now,
            summary=f"rogue_ap ssid_present",
            detail={"ssid_len": len(str(ssid)), "reasons": reasons[:5]},
            entity_type="wifi_ap",
            evidence={
                "reasons": reasons[:5],
                "kind": "rogue_ap",
            },
        )
