"""Kismet capture-DB fixture materialization for replay (D7a).

The production detectors (``deauth_detector``/``rogue_ap_detector``) read a
Kismet capture database by path through read-only connections. Replay
materializes the scenario's raw source rows into a Kismet-shaped SQLite file
exactly once, up front — mirroring reality, where Kismet writes rows as
frames arrive and CYT scans them periodically. Scans are bounded by the
per-detector watermarks, so cycle placement is what makes detection progress.

Only the tables/columns the detectors and the D1 normalizer actually read are
created: ``alerts(ts_sec, header, json, src_mac, dst_mac, bssid, rowid)`` and
``devices(devmac, type, device, last_time, first_time)``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from cyt_platform.replay.scenario import (
    SOURCE_KISMET_ALERTS,
    SOURCE_KISMET_DEVICES,
    ScenarioRow,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  ts_sec  REAL NOT NULL,
  header  TEXT,
  json    TEXT,
  src_mac TEXT,
  dst_mac TEXT,
  bssid   TEXT,
  rowid   INTEGER PRIMARY KEY AUTOINCREMENT
);
CREATE TABLE IF NOT EXISTS devices (
  devmac     TEXT NOT NULL,
  type       TEXT,
  device     TEXT,
  last_time  REAL NOT NULL,
  first_time REAL
);
"""


def _as_json_text(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class KismetFixture:
    """A Kismet-shaped SQLite database built from scenario source rows."""

    def __init__(self, path: Path):
        self.path = Path(path)
        if self.path.exists():
            self.path.unlink()
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def write_rows(self, rows: Iterable[ScenarioRow]) -> None:
        """Insert all kismet-sourced scenario rows.

        gps/ble rows are skipped: they do not live in a capture DB; the
        engine normalizes them directly into observations.
        """
        try:
            for row in rows:
                if row.source == SOURCE_KISMET_DEVICES:
                    self._insert_device(row.row)
                elif row.source == SOURCE_KISMET_ALERTS:
                    self._insert_alert(row.row)
        finally:
            self._conn.commit()

    def _insert_device(self, row: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO devices(devmac, type, device, last_time, first_time)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                row["devmac"],
                row.get("type"),
                _as_json_text(row["device"])
                if row.get("device") is not None
                else None,
                float(row["last_time"]),
                float(row["first_time"])
                if row.get("first_time") is not None
                else None,
            ),
        )

    def _insert_alert(self, row: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO alerts(ts_sec, header, json, src_mac, dst_mac, bssid)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                float(row["ts_sec"]),
                row.get("header"),
                _as_json_text(row["json"])
                if row.get("json") is not None
                else None,
                row.get("src_mac"),
                row.get("dst_mac"),
                row.get("bssid"),
            ),
        )

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:  # pragma: no cover - close is best effort
            pass