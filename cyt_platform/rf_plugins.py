"""P3: Orchestrate deauth, rogue AP, IE fingerprint, BLE plugins each cycle.

Detector failures are recorded, never swallowed: RFPluginRunner tracks the
last error per plugin so status composition can degrade the published state
while any plugin is failing (see ``failures()`` and StatusEngine).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from cyt_platform.detectors import (
    DetectionResult,
    EvidenceLine,
    incident_fields,
)
from cyt_platform.fused_evidence import attach as attach_fusion
from cyt_platform.privacy import sanitize_error
from cyt_platform.health import (
    GPS_DROPOUT_DEFAULT_SECONDS,
    ComponentFailureRegistry,
    clock_skew_reason,
    gps_dropout_reason,
)

logger = logging.getLogger(__name__)

# Severity classification shared by the capture-scan detectors. Scan alerts
# arrive already classified by the Kismet layer; the mapping only translates
# the source's LOW..CRITICAL bands onto the platform's watch/alert vocabulary.
SCAN_SEVERITY_MAP = {
    "LOW": "watch",
    "MEDIUM": "watch",
    "HIGH": "alert",
    "CRITICAL": "alert",
}

# Kismet capture DB watermark keys in runtime_state. Format: "<key>_ts" holds
# the epoch second just past the newest alert durably handled (max processed
# alert ts + 1); a scan reads strictly after it, so a restart never re-emits
# historical alerts as fresh. Both keys are written inside the same store
# transaction that commits the derived incidents.
DEAUTH_WATERMARK_KEY = "deauth_alert_watermark_ts"
ROGUE_WATERMARK_KEY = "rogue_ap_alert_watermark_ts"

# Per-cycle cap on deauth attack filings. analyze_attacks() sorts
# severity-critical first, so the head is kept — the old tail slice
# (attacks[-20:]) dropped the most severe attack exactly when the list
# overflowed.
MAX_DEAUTH_FILINGS_PER_CYCLE = 20


def _runtime_watermark_loader(
    store: Any, key: str
) -> Callable[[], Optional[float]]:
    def load() -> Optional[float]:
        raw = store.get_runtime(key)
        if raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    return load


def _runtime_watermark_saver(
    store: Any, key: str
) -> Callable[[float], None]:
    def save(ts: float) -> None:
        store.set_runtime(key, str(ts))

    return save


def _deauth_result(atk: Any, now: float) -> DetectionResult:
    """Build the contract result for one deauth attack observation.

    Pure: no store access. Evidence lines carry exactly the reason strings
    the pre-contract adapter wrote (same order), classified into kinds.
    Confidence stays None — the capture scan has no computed score; the D4
    fusion model assigns one.
    """
    target = getattr(atk, "target_mac", "?")
    return DetectionResult(
        detector="deauth",
        kind="deauth_attack",
        subject=str(target).upper(),
        subject_type="wifi_mac",
        window_label="deauth",
        severity=SCAN_SEVERITY_MAP.get(
            getattr(atk, "severity", "MEDIUM"), "watch"
        ),
        observed_at=getattr(atk, "last_seen", None) or now,
        summary=f"deauth {getattr(atk, 'attack_type', 'attack')}",
        detail={
            "attacker": str(getattr(atk, "attacker_mac", "?")).upper(),
            "frames": getattr(atk, "total_frames", 0),
            "severity_raw": getattr(atk, "severity", ""),
        },
        evidence=(
            EvidenceLine(
                "deauth_pattern",
                f"Deauth/disassoc pattern toward {str(target)[:17]}",
            ),
            EvidenceLine(
                "attack_signature",
                f"type={getattr(atk, 'attack_type', '?')} "
                f"frames={getattr(atk, 'total_frames', 0)}",
            ),
            EvidenceLine(
                "source_severity",
                f"source severity={getattr(atk, 'severity', '?')}",
            ),
        ),
        confidence=None,
    )


def _rogue_result(al: Any, now: float) -> DetectionResult:
    """Build the contract result for one rogue-AP alert observation.

    Pure: no store access. The alert's own reason list (up to five) is
    carried as evidence lines; when the source supplies none, the
    pre-contract default reason applies. Raw SSID text never enters the
    result — only its length (the privacy policy for status surfaces).
    """
    reasons = list(
        getattr(al, "reasons", None) or ["Rogue/evil-twin AP detected"]
    )[:5]
    return DetectionResult(
        detector="rogue",
        kind="rogue_ap",
        subject=str(getattr(al, "rogue_bssid", "?")).upper(),
        subject_type="wifi_ap",
        window_label="ap",
        severity=SCAN_SEVERITY_MAP.get(getattr(al, "severity", "HIGH"), "alert"),
        observed_at=getattr(al, "timestamp", None) or now,
        summary="rogue_ap ssid_present",
        detail={"ssid_len": len(str(getattr(al, "ssid", "?"))), "reasons": reasons},
        evidence=tuple(
            EvidenceLine("rogue_reason", reason) for reason in reasons
        ),
        confidence=None,
    )


class RFPluginRunner:
    def __init__(
        self,
        store: Any,
        config: dict,
        registry: Optional[ComponentFailureRegistry] = None,
    ):
        self.store = store
        self.config = config
        # D6: failures report into one per-component registry (shared with
        # status composition when the host supplies one).
        self.registry = (
            registry if registry is not None else ComponentFailureRegistry()
        )
        gps_cfg = config.get("gps_fusion") or {}
        self.gps_dropout_seconds = float(
            gps_cfg.get("dropout_seconds") or GPS_DROPOUT_DEFAULT_SECONDS
        )
        self.gps_dropout_min_cycles = int(gps_cfg.get("dropout_min_cycles") or 0)
        self._gps_cycles_seen = 0
        # B4: last filed last_seen per (target, attacker) — deauth filing is
        # idempotent per advance of the attack's newest frame, so quiet
        # cycles never re-file (or re-open) an unchanged attack.
        self._deauth_filed: Dict[Tuple[str, str], float] = {}
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
                from cyt_platform.deauth_detector import DeauthDetector

                self.deauth = DeauthDetector(
                    self.config,
                    watermark_loader=_runtime_watermark_loader(
                        self.store, DEAUTH_WATERMARK_KEY
                    ),
                    watermark_saver=_runtime_watermark_saver(
                        self.store, DEAUTH_WATERMARK_KEY
                    ),
                )
            except Exception as e:
                logger.warning("DeauthDetector unavailable: %s", e)
                self.registry.record_failure(
                    "detector:deauth", f"init: {sanitize_error(e)}"
                )
        if rf.get("rogue_enabled", True):
            try:
                from cyt_platform.rogue_ap_detector import RogueAPDetector

                self.rogue = RogueAPDetector(
                    self.config,
                    watermark_loader=_runtime_watermark_loader(
                        self.store, ROGUE_WATERMARK_KEY
                    ),
                    watermark_saver=_runtime_watermark_saver(
                        self.store, ROGUE_WATERMARK_KEY
                    ),
                )
            except Exception as e:
                logger.warning("RogueAPDetector unavailable: %s", e)
                self.registry.record_failure(
                    "detector:rogue", f"init: {sanitize_error(e)}"
                )
        if (self.config.get("ie_fingerprint") or {}).get("enabled", True):
            from cyt_platform.ie_fingerprint import IEFingerprintEngine

            self.ie = IEFingerprintEngine(self.store, self.config)
        if (self.config.get("ble_tracker") or {}).get("enabled", True):
            from cyt_platform.ble_tracker import BLETrackerEngine

            self.ble = BLETrackerEngine(self.store, self.config)
        if (self.config.get("gps_fusion") or {}).get("enabled", True):
            from cyt_platform.gps_live import LiveGpsFusion

            self.gps = LiveGpsFusion(self.store, self.config)

    def _record_failure(
        self, component: str, exc: Exception, ts: Optional[float] = None
    ) -> str:
        detail = sanitize_error(exc)
        self.registry.record_failure(component, detail, ts)
        return detail

    def _clear_failure(self, component: str, ts: Optional[float] = None) -> None:
        self.registry.record_success(component, ts)

    def failures(self) -> Dict[str, str]:
        """Component name -> sanitized failure detail; empty when all healthy."""
        return self.registry.failures()

    def _gps_health(
        self, fix: Any, now: float
    ) -> Optional[str]:
        """D6: classify the GPS feed after this cycle's ingest.

        Dropout is NOT an exception: a dead or unfixed GPS feed returns None
        fixes silently, which must still be visible ("cannot detect" vs "no
        threat"). The newest known fix is this cycle's fix, the fusion's
        in-memory last fix, or the persisted runtime last fix (survives
        restarts), in that order.
        """
        fix_ts: Optional[float] = None
        if fix is not None:
            fix_ts = float(fix.ts)
        elif getattr(self.gps, "last_fix", None) is not None:
            fix_ts = float(self.gps.last_fix.ts)
        else:
            raw = self.store.get_runtime("last_gps")
            if raw:
                try:
                    fix_ts = float(json.loads(raw).get("ts"))
                except (TypeError, ValueError):
                    fix_ts = None
        self._gps_cycles_seen += 1
        return gps_dropout_reason(
            last_fix_ts=fix_ts,
            now=now,
            dropout_seconds=self.gps_dropout_seconds,
            min_cycles_before_dropout=self.gps_dropout_min_cycles,
            cycles_seen=self._gps_cycles_seen,
        )

    def run_cycle(
        self,
        kdb: Any,
        db_path: str,
        recent_window_s: float = 120.0,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        # Injected clock (replay, locked decision 4): the wall clock is read
        # only when the host does not supply a scenario time.
        now = time.time() if now is None else float(now)
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
                fix = self.gps.ingest_kismet(kdb, recent_window_s, now=now)
                if fix:
                    stats["gps"] = {"lat": fix.lat, "lon": fix.lon}
                co = self.gps.score_cotravel(now)
                stats["cotravel"] = len(co)
                # D6: exception-free dropout (no located fix) is its own
                # degraded component — a dead GPS feed must be visible.
                drop = self._gps_health(fix, now)
                if drop:
                    self.registry.record_failure("gps", drop, now)
                else:
                    self._clear_failure("gps", now)
            except Exception as e:
                detail = self._record_failure("gps", e, ts=now)
                logger.warning("gps fusion error: %s", detail)

        # IE + BLE on same device set
        if self.ie:
            try:
                stats["ie_links"] = self.ie.process_devices(devices, now)
                self._clear_failure("detector:ie", now)
            except Exception as e:
                detail = self._record_failure("detector:ie", e, ts=now)
                logger.warning("ie fingerprint error: %s", detail)
        if self.ble:
            try:
                stats["ble_hits"] = self.ble.process_devices(devices, now)
                self._clear_failure("detector:ble", now)
            except Exception as e:
                detail = self._record_failure("detector:ble", e, ts=now)
                logger.warning("ble tracker error: %s", detail)

        # Deauth / rogue — use file path APIs from CM5 modules
        if self.deauth:
            try:
                events = self.deauth.scan_kismet_db(db_path, now=now)
                stats["deauth_events"] = len(events or [])
                attacks = []
                if hasattr(self.deauth, "analyze_attacks"):
                    attacks = self.deauth.analyze_attacks() or []
                elif hasattr(self.deauth, "attacks"):
                    attacks = self.deauth.attacks or []
                self._file_deauth_attacks(attacks, now)
                # scan_kismet_db records its own last_scan_error (e.g. a
                # read/parse failure while the file itself opened); count
                # that as a plugin failure too so status cannot read clear.
                scan_err = getattr(self.deauth, "last_scan_error", None)
                if scan_err:
                    self.registry.record_failure("detector:deauth", scan_err, now)
                else:
                    self._clear_failure("detector:deauth", now)
                # S10: a watermark or captured event stamped ahead of the
                # analyzer's clock (a forward jump, later corrected) is a
                # clock anomaly — visible as its own failing component,
                # never silently applied. The read side already treats such
                # a watermark as untrusted
                # (kismet_ro.scan_start_from_watermark), and the detector
                # repairs the stored value after a clean scan; the anomaly
                # flag it raised is reported here.
                skew = getattr(self.deauth, "last_clock_anomaly", None) or clock_skew_reason(
                    watermark=getattr(self.deauth, "last_scan_time", None),
                    newest_event_ts=max(
                        (e.timestamp for e in (events or [])), default=None
                    ),
                    now=now,
                )
                if skew:
                    self.registry.record_failure("clock", skew, now)
                else:
                    self._clear_failure("clock", now)
            except Exception as e:
                detail = self._record_failure("detector:deauth", e, ts=now)
                logger.warning("deauth scan error: %s", detail)

        if self.rogue:
            try:
                if hasattr(self.rogue, "scan_kismet_db"):
                    alerts = self.rogue.scan_kismet_db(db_path, now=now)
                else:
                    alerts = []
                stats["rogue_alerts"] = len(alerts or [])
                for al in (alerts or [])[-20:]:
                    self._incident_from_rogue(al, now)
                scan_err = getattr(self.rogue, "last_scan_error", None)
                if scan_err:
                    self.registry.record_failure("detector:rogue", scan_err, now)
                else:
                    self._clear_failure("detector:rogue", now)
            except Exception as e:
                detail = self._record_failure("detector:rogue", e, ts=now)
                logger.warning("rogue scan error: %s", detail)

        # Live failure map rides with the cycle stats so the service can hand
        # it straight to status composition (never clear while failing).
        stats["detector_failures"] = self.registry.failures()
        return stats

    def _file_deauth_attacks(self, attacks: List[Any], now: float) -> List[Any]:
        """File deauth attacks through the contract, once per last_seen advance.

        analyze_attacks() rebuilds the attack list from the windowed
        in-memory event list every cycle, so the same attack reappears until
        its events age out. Filing is keyed on (target, attacker) and
        idempotent on the attack's last_seen: an attack whose newest frame
        was already filed is skipped, so quiet cycles never re-file — and
        never re-open a stale-closed — incident, and observation_count only
        grows with genuinely new frames. The head slice keeps the
        severity-sorted most severe attacks; the old tail slice dropped the
        worst attack exactly when the list overflowed. Returns the attacks
        actually filed this cycle.
        """
        filed = []
        for atk in attacks[:MAX_DEAUTH_FILINGS_PER_CYCLE]:
            key = (
                str(getattr(atk, "target_mac", "?")).upper(),
                str(getattr(atk, "attacker_mac", "?")).upper(),
            )
            last_seen = getattr(atk, "last_seen", 0.0) or 0.0
            if last_seen <= self._deauth_filed.get(key, float("-inf")):
                continue
            self._incident_from_deauth(atk, now)
            self._deauth_filed[key] = last_seen
            filed.append(atk)
        return filed

    def _incident_from_deauth(self, atk: Any, now: float) -> None:
        """Emit one deauth detection through the contract (D6).

        Severity/reasons/detail are unchanged from the pre-contract adapter —
        this is a shape migration, not a behavior change. D4: the incident's
        evidence additionally carries the fused why/against block.
        """
        result = _deauth_result(atk, now)
        fields = incident_fields(
            result,
            session_id=self.store.get_runtime("session_id") or "rf",
        )
        attach_fusion(fields, result)
        self.store.observe_incident(**fields)

    def _incident_from_rogue(self, al: Any, now: float) -> None:
        """Emit one rogue-AP detection through the contract (D6).

        Severity/reasons/detail are unchanged from the pre-contract adapter —
        this is a shape migration, not a behavior change. D4: the incident's
        evidence additionally carries the fused why/against block.
        """
        result = _rogue_result(al, now)
        fields = incident_fields(
            result,
            session_id=self.store.get_runtime("session_id") or "rf",
        )
        attach_fusion(fields, result)
        self.store.observe_incident(**fields)
