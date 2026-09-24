"""Deterministic status engine: clear | degraded | watch | alert | fail with hold_seconds.

``degraded`` means the detection surface is reduced — one or more RF plugins
are failing — so a ``clear`` reading would be unreliable. Priority:
fail > alert > watch > degraded > clear.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from cyt_platform.privacy import chmod_private_file, ensure_dir
from cyt_platform.store import CytStore, StatusInputs

logger = logging.getLogger(__name__)


@dataclass
class ComponentHealth:
    ok: bool
    detail: Optional[str] = None
    extra: Optional[dict] = None


class StatusEngine:
    def __init__(self, store: CytStore, config: dict):
        self.store = store
        self.config = config
        self.status_cfg = config.get("status") or {}
        self.path = Path(self.status_cfg.get("file") or "data/run/status.json")
        # D8 ENOSPC parking: a failed status write (disk full, read-only fs)
        # parks publishing instead of crashing the cycle; the next
        # successful write unparks. detectable via status.parked_publish().
        self._publish_parked = False
        self._park_reason: Optional[str] = None
        self._last_attempted: Optional[dict] = None

    def publish(
        self,
        *,
        cycle: int,
        db_label: str,
        freshness: Optional[dict],
        consecutive_fails: int,
        analyzer_ok: bool = True,
        analyzer_detail: str = "ok",
        kismet_db_ok: bool = True,
        kismet_proc_ok: Optional[bool] = None,
        force_fail: bool = False,
        fail_reason: Optional[str] = None,
        detector_failures: Optional[Dict[str, str]] = None,
    ) -> dict:
        hold = float(self.status_cfg.get("hold_seconds") or 300)
        stale_s = float(self.status_cfg.get("stale_seconds") or 150)
        deaf_s = float(self.status_cfg.get("deaf_seconds") or 180)
        deaf_is_fail = bool(self.status_cfg.get("deaf_is_fail", True))
        quiet_is_watch = bool(self.status_cfg.get("quiet_is_watch", False))

        detector_failures = detector_failures or {}

        inputs: StatusInputs = self.store.get_status_inputs(hold)
        now = inputs.now

        # Capture / deaf
        capture: Dict[str, Any] = {
            "ok": True,
            "max_last_time": None,
            "age_s": None,
            "recent_device_count": 0,
            "reason": None,
        }
        deaf_fail = False
        quiet_watch = False
        if freshness is not None:
            age = freshness.get("age_s")
            capture["max_last_time"] = freshness.get("max_last_time")
            capture["age_s"] = age
            capture["recent_device_count"] = int(freshness.get("recent_device_count") or 0)
            if age is None or (isinstance(age, (int, float)) and age > deaf_s):
                capture["ok"] = False
                capture["reason"] = "deaf"
                deaf_fail = True
            elif capture["recent_device_count"] == 0 and quiet_is_watch:
                capture["ok"] = True
                capture["reason"] = "quiet"
                quiet_watch = True

        heartbeat_age = None
        if inputs.last_heartbeat_ts is not None:
            heartbeat_age = now - inputs.last_heartbeat_ts

        component_fail = (
            force_fail
            or not analyzer_ok
            or not kismet_db_ok
            or consecutive_fails > 0
            or (deaf_fail and deaf_is_fail)
            or (
                inputs.last_heartbeat_ts is not None
                and (now - inputs.last_heartbeat_ts) > stale_s
                and not analyzer_ok
            )
        )

        # threat from hold-filtered opens (all sessions)
        if inputs.alert_open >= 1:
            threat_level = 2
        elif inputs.watch_open >= 1:
            threat_level = 1
        else:
            threat_level = 0

        if component_fail or (deaf_fail and deaf_is_fail):
            state = "fail"
            reason = fail_reason or (
                "deaf" if deaf_fail and deaf_is_fail else
                "analyzer_error" if consecutive_fails or not analyzer_ok else
                "kismet_db" if not kismet_db_ok else
                "component_fail"
            )
        elif threat_level >= 2:
            state = "alert"
            reason = "open_alert_incidents"
        elif threat_level >= 1 or quiet_watch:
            state = "watch"
            reason = "quiet_rf" if quiet_watch and threat_level == 0 else "open_watch_incidents"
        elif detector_failures:
            # A failing detector means we cannot see; "clear" would be a lie.
            state = "degraded"
            reason = "detector_failures: " + ", ".join(sorted(detector_failures))
        else:
            state = "clear"
            reason = "healthy"

        # Invariants when not fail:
        # clear <=> both open counts 0; alert if alert_open>=1; watch if watch only
        session_id = self.store.get_runtime("session_id") or ""

        last_ok = now if analyzer_ok and consecutive_fails == 0 else None
        if last_ok is not None:
            self.store.set_runtime("last_ok_ts", str(last_ok))
        last_ok_stored = self.store.get_runtime("last_ok_ts")
        last_ok_f = float(last_ok_stored) if last_ok_stored else None

        snapshot = {
            "schema_version": 1,
            "state": state,
            "reason": reason,
            "last_ok": last_ok_f,
            "last_ok_iso": (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_ok_f))
                if last_ok_f
                else None
            ),
            "heartbeat_age_s": heartbeat_age,
            "session_id": session_id,
            "components": {
                "analyzer": {
                    "ok": analyzer_ok and consecutive_fails == 0,
                    "detail": f"cycle {cycle}" if analyzer_ok else analyzer_detail,
                },
                "kismet_db": {
                    "ok": kismet_db_ok,
                    "path_basename": db_label,
                },
                "kismet_proc": {
                    "ok": True if kismet_proc_ok is None else bool(kismet_proc_ok),
                },
                "detectors": {
                    "ok": not detector_failures,
                    "failed": dict(detector_failures),
                    "detail": (
                        "; ".join(
                            f"{name}: {det_failures_detail}"
                            for name, det_failures_detail in sorted(detector_failures.items())
                        )
                        if detector_failures
                        else "ok"
                    ),
                },
                "capture": capture,
            },
            "counts": {
                "events_last_hour": inputs.events_last_hour,
                "watch_open": inputs.watch_open,
                "alert_open": inputs.alert_open,
                "suppressed_open": getattr(inputs, "suppressed_open", 0),
            },
            "evidence": [],  # filled below — no raw MAC/SSID
            "battery": None,
            "thermal": None,
            "updated_at": now,
        }
        if self.status_cfg.get("expose_total_opens"):
            snapshot["counts"]["watch_open_total"] = inputs.watch_open_total
            snapshot["counts"]["alert_open_total"] = inputs.alert_open_total

        # Explainable top hits (fingerprints + reasons only)
        try:
            hold = float(self.status_cfg.get("hold_seconds") or 300)
            snapshot["evidence"] = self.store.list_open_incident_evidence(hold, limit=5)
        except Exception:
            snapshot["evidence"] = []

        # D8: a status write failure (ENOSPC, read-only fs) must not kill the
        # analysis cycle — the publish parks and the next successful write
        # unparks. Storage stays the component to blame in the reason.
        self._last_attempted = json.loads(json.dumps(snapshot))
        try:
            self._write_atomic(snapshot)
            self._publish_parked = False
            self._park_reason = None
        except OSError as e:
            if not self._publish_parked:
                logger.error("status publish parked (write failed): %s", e)
            self._publish_parked = True
            self._park_reason = f"status_write_failed: {e}"
            snapshot["state"] = state
            snapshot["parked"] = True
            snapshot["park_reason"] = self._park_reason
        try:
            self.store.append_status_history(state, reason, snapshot)
        except Exception:
            pass
        return snapshot

    def parked_publish(self) -> bool:
        """True while status writes are failing (e.g. ENOSPC)."""
        return self._publish_parked

    def park_reason(self) -> Optional[str]:
        return self._park_reason

    def recover_publish(self) -> bool:
        """Attempt one status write to clear a parked publish.

        Returns True when publishing is healthy again. Recovery is
        verify-by-write: only a successful disk write unparks. The last
        attempted snapshot (true computed state) is re-written — never a
        fabricated "clear", which would silence a safety device.
        """
        if not self._publish_parked:
            return True
        if self._last_attempted is not None:
            probe = json.loads(json.dumps(self._last_attempted))  # deep copy
            probe["parked"] = False
            probe["recovered_at"] = time.time()
        else:
            probe = {
                "schema_version": 1,
                "state": "fail",
                "reason": "publish_recovery_probe",
                "parked": False,
                "updated_at": time.time(),
            }
        try:
            self._write_atomic(probe)
        except OSError as e:
            logger.debug("publish still parked: %s", e)
            return False
        self._publish_parked = False
        reason = self._park_reason
        self._park_reason = None
        logger.info("status publish recovered: %s", reason)
        return True

    def publish_fail(
        self,
        *,
        reason: str,
        consecutive_fails: int,
        cycle: int = 0,
        db_label: str = "",
    ) -> dict:
        return self.publish(
            cycle=cycle,
            db_label=db_label,
            freshness=None,
            consecutive_fails=consecutive_fails,
            analyzer_ok=False,
            analyzer_detail=reason,
            kismet_db_ok=False,
            force_fail=True,
            fail_reason=reason,
        )

    def _write_atomic(self, snapshot: dict) -> None:
        ensure_dir(self.path.parent, 0o750)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        data = json.dumps(snapshot, indent=2)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        # 0640 preferred; may not set group without root
        try:
            os.chmod(self.path, 0o640)
        except OSError:
            chmod_private_file(self.path, 0o600)
