"""Read-only connections to live Kismet capture databases.

Detectors must never be able to mutate capture data. Every connection a
detector opens to a Kismet database goes through here so that:

- the file is opened with URI ``mode=ro`` (no journal creation, no
  temp-file writes, file is not created when missing);
- ``PRAGMA query_only=ON`` doubles the lock so even a stray write
  statement fails loudly instead of silently succeeding.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional, Union


def connect_readonly(db_path: str, timeout: float = 30.0) -> sqlite3.Connection:
    """Open an existing Kismet database strictly read-only.

    Raises sqlite3.OperationalError if the file is missing (mode=ro never
    creates it) or if a write is attempted (readonly database).
    """
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


# A watermark this far ahead of the analyzer's clock is a clock anomaly (a
# forward clock jump that was later corrected): reads treat it as untrusted.
WATERMARK_SKEW_ALLOWANCE_S = 300.0


def scan_start_from_watermark(
    watermark: float,
    now: float,
    catchup_window_s: float,
    skew_allowance_s: float = WATERMARK_SKEW_ALLOWANCE_S,
) -> float:
    """Compute the earliest timestamp a detector scan should read.

    The watermark is the epoch second just past the newest alert already
    durably handled (max processed ts + 1). Reads start strictly after it,
    so processed alerts are never re-read — and when the watermark is old
    (service down a long time) or missing, the look-back is capped at
    ``catchup_window_s`` from ``now`` so a start against a stale capture DB
    cannot replay days of history as fresh.

    A watermark far ahead of ``now`` means the capture host's clock ran
    fast and was later corrected: rows below the watermark were stamped by
    the wrong clock, not actually processed, so the watermark is untrusted.
    Clamping it to ``now + allowance`` would leave the scan start ahead of
    the wall clock and detection blind until the clock caught up; instead
    the read falls back to the bounded catch-up window so real-time rows
    are seen again immediately. Re-read alerts re-file idempotently (the
    runner keys filings on the attack's last_seen), and the anomaly is
    reported as a ``clock`` component failure (health.clock_skew_reason).
    """
    if watermark > now + skew_allowance_s:
        watermark = 0.0
    floor = max(0.0, now - catchup_window_s)
    return max(watermark, floor)


def coerce_watermark(raw: Optional[Union[float, str]]) -> Optional[float]:
    """Parse a persisted watermark; None when absent or invalid."""
    if not raw:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None
