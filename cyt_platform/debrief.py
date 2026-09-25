"""P2: End-of-day debrief narrative from durable store."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyt_platform.privacy import redact_evidence_text, redact_subject


def _day_bounds(day: Optional[str] = None) -> tuple[float, float, str]:
    """Return (start_ts, end_ts, day_label). day = YYYY-MM-DD local or None=today."""
    if day:
        dt = datetime.strptime(day, "%Y-%m-%d")
    else:
        dt = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start = dt.timestamp()
    end = start + 86400
    return start, end, dt.strftime("%Y-%m-%d")


def generate_debrief(
    store: Any,
    config: dict,
    *,
    day: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build narrative debrief for a calendar day.
    Returns dict with text markdown + structured stats; writes file if output_dir set.
    """
    start, end, label = _day_bounds(day)
    c = store.conn

    opened = c.execute(
        """
        SELECT COUNT(*) AS n FROM events
        WHERE event_type='incident_opened' AND ts >= ? AND ts < ?
        """,
        (start, end),
    ).fetchone()["n"]
    reopened = c.execute(
        """
        SELECT COUNT(*) AS n FROM events
        WHERE event_type='incident_reopened' AND ts >= ? AND ts < ?
        """,
        (start, end),
    ).fetchone()["n"]
    closed = c.execute(
        """
        SELECT COUNT(*) AS n FROM events
        WHERE event_type='incident_closed' AND ts >= ? AND ts < ?
        """,
        (start, end),
    ).fetchone()["n"]

    top = c.execute(
        """
        SELECT severity, summary, observation_count, evidence_json, suppressed,
               first_seen, last_seen, window_label
        FROM incidents
        WHERE first_seen < ? AND last_seen >= ? AND COALESCE(suppressed,0)=0
        ORDER BY
          CASE severity WHEN 'alert' THEN 0 ELSE 1 END,
          observation_count DESC
        LIMIT 20
        """,
        (end, start),
    ).fetchall()

    cotravel = []
    try:
        rows = c.execute(
            """
            SELECT entity_type, entity_key, location_count, score, detail_json
            FROM cotravel
            WHERE last_seen >= ? AND last_seen < ?
            ORDER BY score DESC LIMIT 10
            """,
            (start, end),
        ).fetchall()
        for r in rows:
            cotravel.append(dict(r))
    except Exception:
        pass

    fp_links = 0
    try:
        fp_links = c.execute(
            "SELECT COUNT(*) AS n FROM entity_fingerprints"
        ).fetchone()["n"]
    except Exception:
        pass

    ble_hits = c.execute(
        """
        SELECT COUNT(*) AS n FROM incidents
        WHERE event_type LIKE 'ble_%' AND last_seen >= ? AND last_seen < ?
        """,
        (start, end),
    ).fetchone()["n"]

    deauth_hits = c.execute(
        """
        SELECT COUNT(*) AS n FROM incidents
        WHERE event_type LIKE 'deauth%' AND last_seen >= ? AND last_seen < ?
        """,
        (start, end),
    ).fetchone()["n"]

    rogue_hits = c.execute(
        """
        SELECT COUNT(*) AS n FROM incidents
        WHERE event_type LIKE 'rogue%' AND last_seen >= ? AND last_seen < ?
        """,
        (start, end),
    ).fetchone()["n"]

    multi_loc = []
    try:
        rows = c.execute(
            """
            SELECT entity_type, entity_key, COUNT(DISTINCT location_id) AS locs,
                   SUM(see_count) AS sees
            FROM location_sightings
            WHERE last_seen >= ? AND last_seen < ?
            GROUP BY entity_type, entity_key
            HAVING locs >= 2
            ORDER BY locs DESC, sees DESC
            LIMIT 15
            """,
            (start, end),
        ).fetchall()
        multi_loc = [dict(r) for r in rows]
    except Exception:
        pass

    alert_n = sum(1 for r in top if r["severity"] == "alert")
    watch_n = sum(1 for r in top if r["severity"] == "watch")

    lines: List[str] = []
    lines.append(f"# CYT End-of-Day Debrief — {label}")
    lines.append("")
    lines.append(f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"**{len(top)}** active threat incidents (non-suppressed) touched this day · "
        f"**{alert_n}** alert · **{watch_n}** watch"
    )
    lines.append(
        f"Transitions: **{opened}** opened · **{reopened}** reopened · **{closed}** closed"
    )
    if multi_loc:
        lines.append(
            f"**{len(multi_loc)}** entities seen across ≥2 location clusters "
            f"(co-travel candidates)"
        )
    if cotravel:
        lines.append(f"**{len(cotravel)}** scored co-travel entities")
    if ble_hits:
        lines.append(f"BLE tracker-style hits: **{ble_hits}**")
    if deauth_hits:
        lines.append(f"Deauth attack incidents: **{deauth_hits}**")
    if rogue_hits:
        lines.append(f"Rogue/evil-twin incidents: **{rogue_hits}**")
    if fp_links:
        lines.append(f"Fingerprint↔entity links in store: **{fp_links}**")
    lines.append("")

    if not top and not multi_loc:
        lines.append("No escalations met the threat threshold today. Stay boring.")
        lines.append("")
    else:
        lines.append("## What mattered")
        lines.append("")
        for i, r in enumerate(top[:10], 1):
            ev = {}
            if r["evidence_json"]:
                try:
                    ev = json.loads(r["evidence_json"])
                except json.JSONDecodeError:
                    pass
            reasons = "; ".join(
                # D9: debrief markdown renders stored evidence — redact
                # identity/markup, same as the status.json evidence path.
                redact_evidence_text(str(item))
                for item in (ev.get("reasons") or [r["summary"]])
            )
            span_h = max(0.0, (r["last_seen"] - r["first_seen"]) / 3600.0)
            lines.append(
                f"{i}. **{r['severity'].upper()}** · window `{r['window_label']}` · "
                f"obs={r['observation_count']} · span={span_h:.1f}h"
            )
            lines.append(f"   - {reasons}")
            if ev.get("subject_fp"):
                lines.append(f"   - fingerprint ref `{ev['subject_fp']}`")
            lines.append("")

    if multi_loc:
        lines.append("## Co-travel / multi-location")
        lines.append("")
        lines.append(
            "Entities that appeared in multiple GPS clusters with you "
            "(MAC/SSID keys may be field-encrypted at rest):"
        )
        lines.append("")
        for r in multi_loc[:10]:
            key = r.get("entity_key", "?")
            if isinstance(key, str) and key.startswith("enc:v1:"):
                key = f"enc…{key[-8:]}"
            else:
                # S8: the debrief is a written, wipe-scoped artifact — a
                # plaintext entity key (raw MAC, SSID key, fingerprint
                # hash) renders as its stable redacted token.
                key = redact_subject(str(key))
            lines.append(
                f"- `{r['entity_type']}` locs={r['locs']} sees={r['sees']} key={key}"
            )
        lines.append("")

    lines.append("## Operator notes")
    lines.append("")
    lines.append(
        "- Baseline false positives: "
        "`python -m cyt_platform baseline mark --place HOME --key … --false`"
    )
    lines.append("- Threat state is also in `status.json` / LED consumer.")
    lines.append("- Passive-only counter-surveillance; no active RF tooling.")
    lines.append("")

    md = "\n".join(lines)
    out_path = None
    odir = output_dir or (config.get("paths") or {}).get("log_dir") or "logs"
    odir_p = Path(odir)
    odir_p.mkdir(parents=True, exist_ok=True)
    out_path = odir_p / f"debrief_{label}.md"
    out_path.write_text(md, encoding="utf-8")

    return {
        "day": label,
        "markdown": md,
        "path": str(out_path),
        "stats": {
            "opened": opened,
            "reopened": reopened,
            "closed": closed,
            "top_incidents": len(top),
            "alert": alert_n,
            "watch": watch_n,
            "multi_location_entities": len(multi_loc),
            "ble_hits": ble_hits,
            "deauth_hits": deauth_hits,
            "rogue_hits": rogue_hits,
        },
    }
