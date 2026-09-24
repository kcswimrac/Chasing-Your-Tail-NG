"""CytStore — SQLite WAL durable store with optional sealed encryption (P0+P1)."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Generator, List, Optional

from cyt_platform.crypto import (
    CryptoError,
    StoreKey,
    resolve_store_key,
    runtime_db_path,
    seal_file,
    sealed_path_for,
    secure_delete,
    unseal_file,
)
from cyt_platform.privacy import chmod_private_file, ensure_dir

logger = logging.getLogger(__name__)

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS heartbeats (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  component   TEXT NOT NULL,
  ts          REAL NOT NULL,
  ok          INTEGER NOT NULL,
  detail      TEXT,
  pid         INTEGER,
  cycle       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_hb_component_ts ON heartbeats(component, ts DESC);

CREATE TABLE IF NOT EXISTS entities (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type   TEXT NOT NULL,
  key           TEXT NOT NULL,
  first_seen    REAL NOT NULL,
  last_seen     REAL NOT NULL,
  see_count     INTEGER NOT NULL DEFAULT 1,
  ignore        INTEGER NOT NULL DEFAULT 0,
  meta_json     TEXT,
  UNIQUE(entity_type, key)
);

CREATE TABLE IF NOT EXISTS incidents (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_key    TEXT NOT NULL UNIQUE,
  entity_id       INTEGER NOT NULL REFERENCES entities(id),
  event_type      TEXT NOT NULL,
  window_label    TEXT NOT NULL,
  severity        TEXT NOT NULL,
  session_id      TEXT NOT NULL,
  first_seen      REAL NOT NULL,
  last_seen       REAL NOT NULL,
  observation_count INTEGER NOT NULL DEFAULT 1,
  status          TEXT NOT NULL,
  closed_at       REAL,
  summary         TEXT NOT NULL,
  detail_json     TEXT,
  kismet_db       TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_open ON incidents(status, severity, last_seen DESC);

CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            REAL NOT NULL,
  event_type    TEXT NOT NULL,
  incident_id   INTEGER REFERENCES incidents(id),
  entity_id     INTEGER REFERENCES entities(id),
  severity      TEXT NOT NULL,
  summary       TEXT NOT NULL,
  detail_json   TEXT,
  session_id    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

CREATE TABLE IF NOT EXISTS runtime_state (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  ts    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS status_history (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      REAL NOT NULL,
  state   TEXT NOT NULL,
  reason  TEXT,
  snapshot_json TEXT
);
"""

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS baselines (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  place_id        TEXT NOT NULL,
  entity_type     TEXT NOT NULL,
  entity_key      TEXT NOT NULL,
  first_seen      REAL NOT NULL,
  last_seen       REAL NOT NULL,
  sighting_count  INTEGER NOT NULL DEFAULT 1,
  source          TEXT NOT NULL,
  UNIQUE(place_id, entity_type, entity_key)
);
CREATE INDEX IF NOT EXISTS idx_baselines_place ON baselines(place_id);

CREATE TABLE IF NOT EXISTS baseline_sightings (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  place_id        TEXT NOT NULL,
  entity_type     TEXT NOT NULL,
  entity_key      TEXT NOT NULL,
  ts              REAL NOT NULL,
  UNIQUE(place_id, entity_type, entity_key)
);

-- suppressed=1 means open but excluded from threat counts
ALTER TABLE incidents ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN evidence_json TEXT;
"""


@dataclass
class StatusInputs:
    now: float
    hold_cutoff: float
    watch_open: int
    alert_open: int
    watch_open_total: int
    alert_open_total: int
    events_last_hour: int
    last_heartbeat_ts: Optional[float]
    last_heartbeat_ok: Optional[bool]
    suppressed_open: int = 0


@dataclass
class IncidentResult:
    id: int
    is_new: bool
    observation_count: int
    reopened: bool = False
    suppressed: bool = False


class CytStore:
    def __init__(
        self,
        conn: sqlite3.Connection,
        path: Path,
        cfg: dict,
        *,
        key: Optional[StoreKey] = None,
        logical_path: Optional[Path] = None,
        sealed_path: Optional[Path] = None,
    ):
        self.conn = conn
        self.path = path  # actual open path (may be tmpfs)
        self.logical_path = logical_path or path
        self.sealed_path = sealed_path
        self.cfg = cfg
        self.key = key
        self._in_txn = False
        self._field_crypto = bool(
            key and (cfg.get("encryption") or {}).get("field_encrypt", True)
        )

    # --- identity crypto helpers ---
    def _enc_key(self, plaintext: str) -> str:
        if self._field_crypto and self.key:
            return self.key.field_encrypt(plaintext)
        return plaintext

    def _dec_key(self, value: str) -> str:
        if self.key and value and value.startswith("enc:v1:"):
            return self.key.field_decrypt(value)
        return value

    @classmethod
    def open(cls, store_cfg: dict, repair: bool = False) -> "CytStore":
        logical = Path(store_cfg.get("path") or "data/cyt.db")
        ensure_dir(logical.parent, 0o700)
        enc = store_cfg.get("encryption") or {}
        key: Optional[StoreKey] = None
        if enc.get("enabled"):
            key = resolve_store_key(enc)

        sealed = sealed_path_for(logical)
        use_seal = bool(key and enc.get("sealed", True))
        open_path = runtime_db_path(store_cfg, logical) if use_seal else logical

        if use_seal and key:
            # Prefer sealed on disk; unseal to runtime path
            if sealed.is_file():
                unseal_file(sealed, open_path, key)
            elif logical.is_file() and logical != open_path:
                # migrate: seal existing plaintext then move
                seal_file(logical, sealed, key)
                # copy plaintext to runtime
                open_path.write_bytes(logical.read_bytes())
                chmod_private_file(open_path, 0o600)
                secure_delete(logical)
                for s in ("-wal", "-shm"):
                    p = Path(str(logical) + s)
                    if p.exists():
                        secure_delete(p)
            elif not open_path.is_file() and not sealed.is_file():
                # fresh DB at runtime path
                ensure_dir(open_path.parent, 0o700)

        allow = bool(store_cfg.get("allow_recreate_on_corrupt")) or repair
        try:
            conn = sqlite3.connect(str(open_path), timeout=30.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            store = cls(
                conn,
                open_path,
                store_cfg,
                key=key,
                logical_path=logical,
                sealed_path=sealed if use_seal else None,
            )
            store._apply_pragmas()
            store.migrate()
            chmod_private_file(open_path, 0o600)
            for suffix in ("-wal", "-shm"):
                p = Path(str(open_path) + suffix)
                if p.exists():
                    chmod_private_file(p, 0o600)
            return store
        except (sqlite3.Error, CryptoError):
            if not allow:
                raise
            if open_path.exists():
                bak = open_path.with_name(f"{open_path.name}.corrupt.{int(time.time())}")
                open_path.rename(bak)
            conn = sqlite3.connect(str(open_path), timeout=30.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            store = cls(
                conn,
                open_path,
                store_cfg,
                key=key,
                logical_path=logical,
                sealed_path=sealed if use_seal else None,
            )
            store._apply_pragmas()
            store.migrate()
            chmod_private_file(open_path, 0o600)
            return store

    def _apply_pragmas(self) -> None:
        sync = (self.cfg.get("synchronous") or "NORMAL").upper()
        if sync not in ("OFF", "NORMAL", "FULL", "EXTRA"):
            sync = "NORMAL"
        c = self.conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute(f"PRAGMA synchronous={sync}")
        c.execute("PRAGMA temp_store=MEMORY")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=5000")
        c.execute("PRAGMA wal_autocheckpoint=1000")

    def migrate(self) -> None:
        c = self.conn.cursor()
        c.executescript(SCHEMA_V1)
        row = c.execute(
            "SELECT value FROM schema_meta WHERE key = ?", ("version",)
        ).fetchone()
        version = int(row["value"]) if row else 0
        if version < 1:
            c.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES (?, ?)",
                ("version", "1"),
            )
            version = 1
        if version < 2:
            self._migrate_v2(c)
            c.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES (?, ?)",
                ("version", "2"),
            )
            version = 2
        if version < 3:
            self._migrate_v3(c)
            c.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES (?, ?)",
                ("version", "3"),
            )

    def _migrate_v2(self, c: sqlite3.Cursor) -> None:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS baselines (
              id              INTEGER PRIMARY KEY AUTOINCREMENT,
              place_id        TEXT NOT NULL,
              entity_type     TEXT NOT NULL,
              entity_key      TEXT NOT NULL,
              first_seen      REAL NOT NULL,
              last_seen       REAL NOT NULL,
              sighting_count  INTEGER NOT NULL DEFAULT 1,
              source          TEXT NOT NULL,
              UNIQUE(place_id, entity_type, entity_key)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_baselines_place ON baselines(place_id)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS baseline_sightings (
              id              INTEGER PRIMARY KEY AUTOINCREMENT,
              place_id        TEXT NOT NULL,
              entity_type     TEXT NOT NULL,
              entity_key      TEXT NOT NULL,
              ts              REAL NOT NULL,
              UNIQUE(place_id, entity_type, entity_key)
            )
            """
        )
        # additive columns on incidents
        cols = {
            r["name"]
            for r in c.execute("PRAGMA table_info(incidents)").fetchall()
        }
        if "suppressed" not in cols:
            c.execute(
                "ALTER TABLE incidents ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0"
            )
        if "evidence_json" not in cols:
            c.execute("ALTER TABLE incidents ADD COLUMN evidence_json TEXT")

    def _migrate_v3(self, c: sqlite3.Cursor) -> None:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS push_queue (
              id            INTEGER PRIMARY KEY AUTOINCREMENT,
              created_ts    REAL NOT NULL,
              severity      TEXT NOT NULL,
              title         TEXT NOT NULL,
              body          TEXT NOT NULL,
              payload_json  TEXT,
              status        TEXT NOT NULL,
              attempts      INTEGER NOT NULL DEFAULT 0,
              last_attempt  REAL,
              last_error    TEXT,
              sent_ts       REAL
            );
            CREATE INDEX IF NOT EXISTS idx_push_pending
              ON push_queue(status, created_ts);

            CREATE TABLE IF NOT EXISTS location_sightings (
              id            INTEGER PRIMARY KEY AUTOINCREMENT,
              entity_type   TEXT NOT NULL,
              entity_key    TEXT NOT NULL,
              location_id   TEXT NOT NULL,
              lat           REAL,
              lon           REAL,
              first_seen    REAL NOT NULL,
              last_seen     REAL NOT NULL,
              see_count     INTEGER NOT NULL DEFAULT 1,
              UNIQUE(entity_type, entity_key, location_id)
            );
            CREATE INDEX IF NOT EXISTS idx_loc_entity
              ON location_sightings(entity_type, entity_key);

            CREATE TABLE IF NOT EXISTS cotravel (
              id              INTEGER PRIMARY KEY AUTOINCREMENT,
              entity_type     TEXT NOT NULL,
              entity_key      TEXT NOT NULL,
              location_count  INTEGER NOT NULL,
              score           REAL NOT NULL,
              first_seen      REAL NOT NULL,
              last_seen       REAL NOT NULL,
              detail_json     TEXT,
              UNIQUE(entity_type, entity_key)
            );

            CREATE TABLE IF NOT EXISTS fingerprints (
              id                INTEGER PRIMARY KEY AUTOINCREMENT,
              fingerprint_type  TEXT NOT NULL,
              fingerprint_hash  TEXT NOT NULL,
              features_json     TEXT,
              first_seen        REAL NOT NULL,
              last_seen         REAL NOT NULL,
              UNIQUE(fingerprint_type, fingerprint_hash)
            );

            CREATE TABLE IF NOT EXISTS entity_fingerprints (
              entity_id       INTEGER NOT NULL,
              fingerprint_id  INTEGER NOT NULL,
              confidence      REAL NOT NULL DEFAULT 0.5,
              linked_ts       REAL NOT NULL,
              PRIMARY KEY (entity_id, fingerprint_id)
            );
            """
        )

    def checkpoint(self) -> None:
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass

    def seal_now(self) -> None:
        """Checkpoint and write sealed ciphertext; keep plaintext open."""
        if not self.key or not self.sealed_path:
            return
        self.checkpoint()
        seal_file(self.path, self.sealed_path, self.key)

    def close(self) -> None:
        try:
            self.checkpoint()
            if self.key and self.sealed_path:
                seal_file(self.path, self.sealed_path, self.key)
        except Exception as e:
            logger.error("seal on close failed: %s", e)
        try:
            self.conn.close()
        finally:
            # shred runtime plaintext when sealed mode used tmpfs/open dir
            if self.key and self.sealed_path and self.path != self.logical_path:
                for p in (
                    self.path,
                    Path(str(self.path) + "-wal"),
                    Path(str(self.path) + "-shm"),
                ):
                    secure_delete(p)

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        if self._in_txn:
            yield
            return
        self.conn.execute("BEGIN IMMEDIATE")
        self._in_txn = True
        try:
            yield
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        finally:
            self._in_txn = False

    def begin_session(self) -> str:
        session_id = uuid.uuid4().hex
        self.set_runtime("session_id", session_id)
        return session_id

    def set_runtime(self, key: str, value: str) -> None:
        now = time.time()
        self.conn.execute(
            """
            INSERT INTO runtime_state(key, value, ts) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, ts=excluded.ts
            """,
            (key, value, now),
        )

    def get_runtime(self, key: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT value FROM runtime_state WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def upsert_entity(
        self,
        entity_type: str,
        key: str,
        ts: float,
        meta: Optional[dict] = None,
    ) -> int:
        store_key = self._enc_key(key)
        meta_json = json.dumps(meta) if meta else None
        # match either plaintext (legacy) or encrypted
        row = self.conn.execute(
            "SELECT id, see_count, key FROM entities WHERE entity_type=? AND key=?",
            (entity_type, store_key),
        ).fetchone()
        if row is None and store_key != key:
            row = self.conn.execute(
                "SELECT id, see_count, key FROM entities WHERE entity_type=? AND key=?",
                (entity_type, key),
            ).fetchone()
        if row:
            self.conn.execute(
                """
                UPDATE entities
                SET last_seen=?, see_count=see_count+1, meta_json=COALESCE(?, meta_json),
                    key=?
                WHERE id=?
                """,
                (ts, meta_json, store_key, row["id"]),
            )
            return int(row["id"])
        cur = self.conn.execute(
            """
            INSERT INTO entities(entity_type, key, first_seen, last_seen, see_count, ignore, meta_json)
            VALUES (?, ?, ?, ?, 1, 0, ?)
            """,
            (entity_type, store_key, ts, ts, meta_json),
        )
        return int(cur.lastrowid)

    def entity_is_ignored(self, entity_type: str, key: str) -> bool:
        store_key = self._enc_key(key)
        row = self.conn.execute(
            "SELECT ignore FROM entities WHERE entity_type=? AND (key=? OR key=?)",
            (entity_type, store_key, key),
        ).fetchone()
        return bool(row and row["ignore"])

    def set_entity_ignore(self, entity_type: str, key: str, ignore: bool) -> None:
        store_key = self._enc_key(key)
        self.upsert_entity(entity_type, key, time.time())
        self.conn.execute(
            "UPDATE entities SET ignore=? WHERE entity_type=? AND (key=? OR key=?)",
            (1 if ignore else 0, entity_type, store_key, key),
        )

    def observe_incident(
        self,
        *,
        event_type: str,
        subject: str,
        window_label: str,
        severity: str,
        session_id: str,
        observed_at: float,
        summary: str,
        detail: Optional[dict] = None,
        kismet_db: str = "",
        entity_type: str = "wifi_mac",
        suppressed: bool = False,
        evidence: Optional[dict] = None,
    ) -> IncidentResult:
        mode = (self.cfg.get("mode") or "durable").lower()
        if mode == "ephemeral_events":
            return IncidentResult(id=0, is_new=False, observation_count=0)

        entity_id = self.upsert_entity(entity_type, subject, observed_at)
        # incident_key uses plaintext subject in-process identity (not stored as path)
        # For uniqueness under field crypto we use encrypted subject in key material
        subj_token = self._enc_key(subject) if self._field_crypto else subject
        incident_key = f"{event_type}|{subj_token}|{window_label}|{session_id}"
        detail_json = json.dumps(detail) if detail else None
        evidence_json = json.dumps(evidence) if evidence else None
        sup = 1 if suppressed else 0

        row = self.conn.execute(
            "SELECT * FROM incidents WHERE incident_key=?", (incident_key,)
        ).fetchone()

        if row is None:
            cur = self.conn.execute(
                """
                INSERT INTO incidents(
                  incident_key, entity_id, event_type, window_label, severity,
                  session_id, first_seen, last_seen, observation_count, status,
                  closed_at, summary, detail_json, kismet_db, suppressed, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'open', NULL, ?, ?, ?, ?, ?)
                """,
                (
                    incident_key,
                    entity_id,
                    event_type,
                    window_label,
                    severity,
                    session_id,
                    observed_at,
                    observed_at,
                    summary,
                    detail_json,
                    kismet_db,
                    sup,
                    evidence_json,
                ),
            )
            iid = int(cur.lastrowid)
            self.conn.execute(
                """
                INSERT INTO events(ts, event_type, incident_id, entity_id, severity, summary, detail_json, session_id)
                VALUES (?, 'incident_opened', ?, ?, ?, ?, ?, ?)
                """,
                (observed_at, iid, entity_id, severity, summary, detail_json, session_id),
            )
            return IncidentResult(
                id=iid, is_new=True, observation_count=1, suppressed=suppressed
            )

        if row["status"] == "closed":
            self.conn.execute(
                """
                UPDATE incidents SET status='open', last_seen=?, observation_count=observation_count+1,
                  closed_at=NULL, summary=?, detail_json=COALESCE(?, detail_json), kismet_db=?,
                  severity=?, suppressed=?, evidence_json=COALESCE(?, evidence_json)
                WHERE id=?
                """,
                (
                    observed_at,
                    summary,
                    detail_json,
                    kismet_db,
                    severity,
                    sup,
                    evidence_json,
                    row["id"],
                ),
            )
            new_count = int(row["observation_count"]) + 1
            self.conn.execute(
                """
                INSERT INTO events(ts, event_type, incident_id, entity_id, severity, summary, detail_json, session_id)
                VALUES (?, 'incident_reopened', ?, ?, ?, ?, ?, ?)
                """,
                (observed_at, row["id"], entity_id, severity, summary, detail_json, session_id),
            )
            return IncidentResult(
                id=int(row["id"]),
                is_new=False,
                observation_count=new_count,
                reopened=True,
                suppressed=suppressed,
            )

        self.conn.execute(
            """
            UPDATE incidents SET last_seen=?, observation_count=observation_count+1,
              detail_json=COALESCE(?, detail_json), kismet_db=?,
              suppressed=?, evidence_json=COALESCE(?, evidence_json)
            WHERE id=?
            """,
            (observed_at, detail_json, kismet_db, sup, evidence_json, row["id"]),
        )
        return IncidentResult(
            id=int(row["id"]),
            is_new=False,
            observation_count=int(row["observation_count"]) + 1,
            suppressed=suppressed,
        )

    def close_stale_incidents(self, now: float, close_after_seconds: float) -> int:
        cutoff = now - close_after_seconds
        rows = self.conn.execute(
            """
            SELECT id, entity_id, severity, summary, session_id FROM incidents
            WHERE status='open' AND last_seen < ?
            """,
            (cutoff,),
        ).fetchall()
        closed = 0
        for row in rows:
            self.conn.execute(
                "UPDATE incidents SET status='closed', closed_at=? WHERE id=?",
                (now, row["id"]),
            )
            self.conn.execute(
                """
                INSERT INTO events(ts, event_type, incident_id, entity_id, severity, summary, detail_json, session_id)
                VALUES (?, 'incident_closed', ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    row["id"],
                    row["entity_id"],
                    row["severity"],
                    f"closed: {row['summary']}",
                    None,
                    row["session_id"],
                ),
            )
            closed += 1
        return closed

    def write_heartbeat(
        self,
        component: str,
        ok: bool,
        cycle: Optional[int] = None,
        detail: Optional[str] = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO heartbeats(component, ts, ok, detail, pid, cycle)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (component, time.time(), 1 if ok else 0, detail, os.getpid(), cycle),
        )

    def get_status_inputs(self, hold_seconds: float) -> StatusInputs:
        now = time.time()
        hold_cutoff = now - hold_seconds
        # Threat counts exclude suppressed
        watch_open = self.conn.execute(
            """
            SELECT COUNT(*) AS c FROM incidents
            WHERE status='open' AND severity='watch' AND last_seen >= ?
              AND COALESCE(suppressed, 0)=0
            """,
            (hold_cutoff,),
        ).fetchone()["c"]
        alert_open = self.conn.execute(
            """
            SELECT COUNT(*) AS c FROM incidents
            WHERE status='open' AND severity='alert' AND last_seen >= ?
              AND COALESCE(suppressed, 0)=0
            """,
            (hold_cutoff,),
        ).fetchone()["c"]
        watch_total = self.conn.execute(
            """
            SELECT COUNT(*) AS c FROM incidents
            WHERE status='open' AND severity='watch' AND COALESCE(suppressed, 0)=0
            """
        ).fetchone()["c"]
        alert_total = self.conn.execute(
            """
            SELECT COUNT(*) AS c FROM incidents
            WHERE status='open' AND severity='alert' AND COALESCE(suppressed, 0)=0
            """
        ).fetchone()["c"]
        suppressed_open = self.conn.execute(
            """
            SELECT COUNT(*) AS c FROM incidents
            WHERE status='open' AND COALESCE(suppressed, 0)=1 AND last_seen >= ?
            """,
            (hold_cutoff,),
        ).fetchone()["c"]
        events_hour = self.conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE ts >= ?",
            (now - 3600,),
        ).fetchone()["c"]
        hb = self.conn.execute(
            """
            SELECT ts, ok FROM heartbeats WHERE component='analyzer'
            ORDER BY ts DESC LIMIT 1
            """
        ).fetchone()
        return StatusInputs(
            now=now,
            hold_cutoff=hold_cutoff,
            watch_open=int(watch_open),
            alert_open=int(alert_open),
            watch_open_total=int(watch_total),
            alert_open_total=int(alert_total),
            events_last_hour=int(events_hour),
            last_heartbeat_ts=float(hb["ts"]) if hb else None,
            last_heartbeat_ok=bool(hb["ok"]) if hb else None,
            suppressed_open=int(suppressed_open),
        )

    def list_open_incident_evidence(self, hold_seconds: float, limit: int = 5) -> List[dict]:
        now = time.time()
        hold_cutoff = now - hold_seconds
        rows = self.conn.execute(
            """
            SELECT severity, summary, evidence_json, observation_count, window_label, suppressed
            FROM incidents
            WHERE status='open' AND last_seen >= ? AND COALESCE(suppressed, 0)=0
            ORDER BY
              CASE severity WHEN 'alert' THEN 0 ELSE 1 END,
              last_seen DESC
            LIMIT ?
            """,
            (hold_cutoff, limit),
        ).fetchall()
        out = []
        for r in rows:
            ev = None
            if r["evidence_json"]:
                try:
                    ev = json.loads(r["evidence_json"])
                except json.JSONDecodeError:
                    ev = None
            out.append(
                {
                    "severity": r["severity"],
                    "summary": r["summary"],
                    "window": r["window_label"],
                    "observation_count": r["observation_count"],
                    "evidence": ev,
                }
            )
        return out

    def append_status_history(
        self, state: str, reason: str, snapshot: dict
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO status_history(ts, state, reason, snapshot_json)
            VALUES (?, ?, ?, ?)
            """,
            (time.time(), state, reason, json.dumps(snapshot)),
        )

    # --- baselines ---
    def bump_baseline_sighting(
        self, place_id: str, entity_type: str, entity_key: str, ts: float
    ) -> int:
        """Increment candidate/learned sighting counter; return new count."""
        ek = self._enc_key(entity_key)
        # Upsert last-seen marker
        self.conn.execute(
            """
            INSERT INTO baseline_sightings(place_id, entity_type, entity_key, ts)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(place_id, entity_type, entity_key) DO UPDATE SET ts=excluded.ts
            """,
            (place_id, entity_type, ek, ts),
        )
        row = self.conn.execute(
            """
            SELECT id, sighting_count, source FROM baselines
            WHERE place_id=? AND entity_type=? AND (entity_key=? OR entity_key=?)
            """,
            (place_id, entity_type, ek, entity_key),
        ).fetchone()
        if row:
            nc = int(row["sighting_count"]) + 1
            self.conn.execute(
                """
                UPDATE baselines SET sighting_count=?, last_seen=?, entity_key=?
                WHERE id=?
                """,
                (nc, ts, ek, row["id"]),
            )
            return nc
        self.conn.execute(
            """
            INSERT INTO baselines(
              place_id, entity_type, entity_key, first_seen, last_seen, sighting_count, source
            ) VALUES (?, ?, ?, ?, ?, 1, 'candidate')
            """,
            (place_id, entity_type, ek, ts, ts),
        )
        return 1

    def ensure_baseline(
        self,
        place_id: str,
        entity_type: str,
        entity_key: str,
        ts: float,
        *,
        source: str,
        sighting_count: int,
    ) -> bool:
        """Return True if newly promoted from candidate or freshly inserted."""
        ek = self._enc_key(entity_key)
        row = self.conn.execute(
            """
            SELECT id, source, sighting_count FROM baselines
            WHERE place_id=? AND entity_type=? AND (entity_key=? OR entity_key=?)
            """,
            (place_id, entity_type, ek, entity_key),
        ).fetchone()
        if row:
            was_candidate = row["source"] == "candidate"
            new_count = max(int(row["sighting_count"]), int(sighting_count))
            new_source = source if was_candidate or row["source"] == "candidate" else row["source"]
            if source in ("manual", "mark_false", "learned"):
                new_source = source if was_candidate else (
                    source if row["source"] == "candidate" else row["source"]
                )
                if source in ("manual", "mark_false"):
                    new_source = source
                elif was_candidate:
                    new_source = source
            self.conn.execute(
                """
                UPDATE baselines SET last_seen=?, sighting_count=?, entity_key=?, source=?
                WHERE id=?
                """,
                (ts, new_count, ek, new_source, row["id"]),
            )
            return was_candidate and new_source != "candidate"
        self.conn.execute(
            """
            INSERT INTO baselines(place_id, entity_type, entity_key, first_seen, last_seen, sighting_count, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (place_id, entity_type, ek, ts, ts, sighting_count, source),
        )
        return True

    def list_baselines(self) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM baselines WHERE source != 'candidate' ORDER BY place_id, last_seen DESC"
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "place_id": r["place_id"],
                    "entity_type": r["entity_type"],
                    "entity_key": self._dec_key(r["entity_key"]),
                    "entity_key_fp": r["entity_key"][:20],
                    "sighting_count": r["sighting_count"],
                    "source": r["source"],
                    "last_seen": r["last_seen"],
                }
            )
        return out

    def delete_baseline(
        self, place_id: str, entity_type: str, entity_key: str
    ) -> int:
        ek = self._enc_key(entity_key)
        cur = self.conn.execute(
            """
            DELETE FROM baselines
            WHERE place_id=? AND entity_type=? AND (entity_key=? OR entity_key=?)
            """,
            (place_id, entity_type, ek, entity_key),
        )
        return cur.rowcount

    def purge_retention(self, now: Optional[float] = None) -> Dict[str, int]:
        now = now or time.time()
        days = float(self.cfg.get("retention_days") or 14)
        hb_days = float(self.cfg.get("heartbeat_keep_days") or 7)
        ent_days = float(self.cfg.get("entity_retention_days") or 30)
        cut = now - days * 86400
        hb_cut = now - hb_days * 86400
        ent_cut = now - ent_days * 86400
        c = self.conn.cursor()
        r1 = c.execute("DELETE FROM events WHERE ts < ?", (cut,)).rowcount
        r2 = c.execute(
            "DELETE FROM incidents WHERE status='closed' AND COALESCE(closed_at, last_seen) < ?",
            (cut,),
        ).rowcount
        r3 = c.execute("DELETE FROM status_history WHERE ts < ?", (cut,)).rowcount
        r4 = c.execute("DELETE FROM heartbeats WHERE ts < ?", (hb_cut,)).rowcount
        r5 = c.execute(
            "DELETE FROM entities WHERE last_seen < ? AND ignore=0",
            (ent_cut,),
        ).rowcount
        r6 = c.execute(
            "DELETE FROM push_queue WHERE status='sent' AND COALESCE(sent_ts, created_ts) < ?",
            (cut,),
        ).rowcount
        return {
            "events": r1,
            "incidents": r2,
            "status_history": r3,
            "heartbeats": r4,
            "entities": r5,
            "push_sent": r6,
        }

    # --- P2/P3 helpers ---
    def enqueue_push(
        self,
        *,
        severity: str,
        title: str,
        body: str,
        payload: Optional[dict] = None,
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO push_queue(
              created_ts, severity, title, body, payload_json, status, attempts
            ) VALUES (?, ?, ?, ?, ?, 'pending', 0)
            """,
            (
                time.time(),
                severity,
                title,
                body,
                json.dumps(payload) if payload else None,
            ),
        )
        return int(cur.lastrowid)

    def list_push_pending(self, limit: int = 20) -> List[dict]:
        rows = self.conn.execute(
            """
            SELECT * FROM push_queue
            WHERE status='pending'
            ORDER BY created_ts ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_push(
        self,
        push_id: int,
        *,
        status: str,
        error: Optional[str] = None,
    ) -> None:
        now = time.time()
        if status == "sent":
            self.conn.execute(
                """
                UPDATE push_queue
                SET status='sent', sent_ts=?, last_attempt=?, attempts=attempts+1, last_error=NULL
                WHERE id=?
                """,
                (now, now, push_id),
            )
        else:
            self.conn.execute(
                """
                UPDATE push_queue
                SET status=?, last_attempt=?, attempts=attempts+1, last_error=?
                WHERE id=?
                """,
                (status, now, error, push_id),
            )

    def record_location_sighting(
        self,
        entity_type: str,
        entity_key: str,
        location_id: str,
        lat: float,
        lon: float,
        ts: float,
    ) -> None:
        ek = self._enc_key(entity_key)
        row = self.conn.execute(
            """
            SELECT id, see_count FROM location_sightings
            WHERE entity_type=? AND entity_key=? AND location_id=?
            """,
            (entity_type, ek, location_id),
        ).fetchone()
        if row is None:
            row = self.conn.execute(
                """
                SELECT id, see_count FROM location_sightings
                WHERE entity_type=? AND entity_key=? AND location_id=?
                """,
                (entity_type, entity_key, location_id),
            ).fetchone()
        if row:
            self.conn.execute(
                """
                UPDATE location_sightings
                SET last_seen=?, see_count=see_count+1, lat=?, lon=?, entity_key=?
                WHERE id=?
                """,
                (ts, lat, lon, ek, row["id"]),
            )
        else:
            self.conn.execute(
                """
                INSERT INTO location_sightings(
                  entity_type, entity_key, location_id, lat, lon, first_seen, last_seen, see_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (entity_type, ek, location_id, lat, lon, ts, ts),
            )

    def upsert_cotravel(
        self,
        entity_type: str,
        entity_key: str,
        *,
        location_count: int,
        score: float,
        first_seen: float,
        last_seen: float,
        detail: Optional[dict] = None,
    ) -> None:
        ek = self._enc_key(entity_key)
        detail_json = json.dumps(detail) if detail else None
        self.conn.execute(
            """
            INSERT INTO cotravel(
              entity_type, entity_key, location_count, score, first_seen, last_seen, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_type, entity_key) DO UPDATE SET
              location_count=excluded.location_count,
              score=excluded.score,
              last_seen=excluded.last_seen,
              detail_json=excluded.detail_json
            """,
            (entity_type, ek, location_count, score, first_seen, last_seen, detail_json),
        )

    def upsert_fingerprint(
        self,
        fingerprint_type: str,
        fingerprint_hash: str,
        features: dict,
        ts: float,
    ) -> int:
        row = self.conn.execute(
            """
            SELECT id FROM fingerprints
            WHERE fingerprint_type=? AND fingerprint_hash=?
            """,
            (fingerprint_type, fingerprint_hash),
        ).fetchone()
        if row:
            self.conn.execute(
                "UPDATE fingerprints SET last_seen=?, features_json=? WHERE id=?",
                (ts, json.dumps(features), row["id"]),
            )
            return int(row["id"])
        cur = self.conn.execute(
            """
            INSERT INTO fingerprints(
              fingerprint_type, fingerprint_hash, features_json, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (fingerprint_type, fingerprint_hash, json.dumps(features), ts, ts),
        )
        return int(cur.lastrowid)

    def link_entity_fingerprint(
        self, entity_id: int, fingerprint_id: int, confidence: float = 0.5
    ) -> bool:
        """Return True if link is new."""
        row = self.conn.execute(
            """
            SELECT 1 FROM entity_fingerprints
            WHERE entity_id=? AND fingerprint_id=?
            """,
            (entity_id, fingerprint_id),
        ).fetchone()
        if row:
            self.conn.execute(
                """
                UPDATE entity_fingerprints
                SET confidence=CASE WHEN confidence > ? THEN confidence ELSE ? END,
                    linked_ts=?
                WHERE entity_id=? AND fingerprint_id=?
                """,
                (confidence, confidence, time.time(), entity_id, fingerprint_id),
            )
            return False
        self.conn.execute(
            """
            INSERT INTO entity_fingerprints(entity_id, fingerprint_id, confidence, linked_ts)
            VALUES (?, ?, ?, ?)
            """,
            (entity_id, fingerprint_id, confidence, time.time()),
        )
        return True

    def entities_for_fingerprint(self, fingerprint_id: int) -> List[int]:
        rows = self.conn.execute(
            "SELECT entity_id FROM entity_fingerprints WHERE fingerprint_id=?",
            (fingerprint_id,),
        ).fetchall()
        return [int(r["entity_id"]) for r in rows]

