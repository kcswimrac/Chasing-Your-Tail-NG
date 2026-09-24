"""P2: Offline-capable push queue (ntfy by default)."""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class PushQueue:
    """Persist alerts; deliver when network available."""

    def __init__(self, store: Any, config: dict):
        self.store = store
        self.cfg = config.get("push") or {}
        self.enabled = bool(self.cfg.get("enabled", False))
        self.backend = (self.cfg.get("backend") or "ntfy").lower()
        self.min_severity = (self.cfg.get("min_severity") or "alert").lower()
        self.ntfy_url = self.cfg.get("ntfy_url") or "https://ntfy.sh"
        self.ntfy_topic = self.cfg.get("ntfy_topic") or ""
        self.ntfy_token = self.cfg.get("ntfy_token") or ""
        self.max_attempts = int(self.cfg.get("max_attempts") or 8)
        self.cooldown_s = float(self.cfg.get("cooldown_seconds") or 300)
        self._last_sent_fingerprint: Dict[str, float] = {}

    def _sev_rank(self, s: str) -> int:
        return {"watch": 1, "alert": 2, "fail": 3, "critical": 4}.get(s.lower(), 0)

    def should_enqueue(self, severity: str) -> bool:
        if not self.enabled:
            return False
        return self._sev_rank(severity) >= self._sev_rank(self.min_severity)

    def enqueue(
        self,
        *,
        severity: str,
        title: str,
        body: str,
        payload: Optional[dict] = None,
        dedupe_key: Optional[str] = None,
    ) -> Optional[int]:
        if not self.should_enqueue(severity):
            return None
        if dedupe_key:
            last = self._last_sent_fingerprint.get(dedupe_key, 0)
            if time.time() - last < self.cooldown_s:
                return None
            # also check pending with same title
            row = self.store.conn.execute(
                """
                SELECT id FROM push_queue
                WHERE status='pending' AND title=? AND created_ts > ?
                LIMIT 1
                """,
                (title, time.time() - self.cooldown_s),
            ).fetchone()
            if row:
                return None
        return self.store.enqueue_push(
            severity=severity,
            title=title[:120],
            body=body[:2000],
            payload=payload or {},
        )

    def enqueue_from_status(self, snapshot: dict) -> int:
        """Enqueue on transition to alert/fail (caller should track prev state)."""
        state = snapshot.get("state")
        if state not in ("alert", "fail"):
            return 0
        if not self.should_enqueue(state if state != "fail" else "fail"):
            return 0
        counts = snapshot.get("counts") or {}
        evidence = snapshot.get("evidence") or []
        lines = [
            f"state={state} reason={snapshot.get('reason')}",
            f"alert_open={counts.get('alert_open')} watch_open={counts.get('watch_open')}",
        ]
        for e in evidence[:3]:
            ev = e.get("evidence") or {}
            reasons = ev.get("reasons") or [e.get("summary")]
            lines.append(" · ".join(str(x) for x in reasons[:2]))
        title = f"CYT {state.upper()}"
        body = "\n".join(lines)
        pid = self.enqueue(
            severity=state if state != "fail" else "alert",
            title=title,
            body=body,
            payload={"state": state, "reason": snapshot.get("reason")},
            dedupe_key=f"{state}:{snapshot.get('reason')}",
        )
        return 1 if pid else 0

    def flush(self) -> Dict[str, int]:
        """Try to send pending messages. Returns counts."""
        if not self.enabled:
            return {"sent": 0, "failed": 0, "skipped": 0}
        pending = self.store.list_push_pending(limit=20)
        sent = failed = skipped = 0
        for row in pending:
            if int(row["attempts"]) >= self.max_attempts:
                self.store.mark_push(row["id"], status="failed")
                failed += 1
                continue
            ok, err = self._deliver(row)
            if ok:
                self.store.mark_push(row["id"], status="sent")
                sent += 1
                self._last_sent_fingerprint[row["title"]] = time.time()
            else:
                self.store.mark_push(row["id"], status="pending", error=err)
                failed += 1
                logger.warning("Push delivery failed id=%s: %s", row["id"], err)
        return {"sent": sent, "failed": failed, "skipped": skipped}

    def _deliver(self, row: dict) -> tuple[bool, str]:
        if self.backend == "ntfy":
            return self._deliver_ntfy(row)
        if self.backend == "log":
            logger.info("PUSH [%s] %s — %s", row["severity"], row["title"], row["body"])
            return True, ""
        return False, f"unknown backend {self.backend}"

    def _deliver_ntfy(self, row: dict) -> tuple[bool, str]:
        if not self.ntfy_topic:
            return False, "ntfy_topic not configured"
        url = self.ntfy_url.rstrip("/") + "/" + self.ntfy_topic
        data = row["body"].encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Title", row["title"])
        prio = "5" if row["severity"] in ("alert", "fail", "critical") else "3"
        req.add_header("Priority", prio)
        req.add_header("Tags", "warning,eye")
        if self.ntfy_token:
            req.add_header("Authorization", f"Bearer {self.ntfy_token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if 200 <= resp.status < 300:
                    return True, ""
                return False, f"http {resp.status}"
        except urllib.error.URLError as e:
            return False, str(e.reason if hasattr(e, "reason") else e)
        except Exception as e:
            return False, str(e)
