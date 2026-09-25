"""CytStore — SQLite WAL durable store with optional sealed encryption (P0+P1)."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

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

# D8 retention classes: every user table is classified exactly once.
#
#   raw     — high-churn sensor data; ages out fastest
#             (heartbeat_keep_days / observation_retention_days)
#   medium  — sightings, aggregates, and audit trails
#             (retention_days)
#   entity  — identity rows (entity_retention_days, non-ignored only)
#   closed  — incidents, purged only after closing (retention_days)
#   sent    — delivery queue rows, purged after delivery (retention_days)
#   keep    — never purged: operational state or operator-confirmed learning
RETENTION_CLASSES: Dict[str, str] = {
    "observations": "raw",
    "heartbeats": "raw",
    "events": "medium",
    "status_history": "medium",
    "location_sightings": "medium",
    "cotravel": "medium",
    "fingerprints": "medium",
    "entity_fingerprints": "medium",
    "baseline_sightings": "medium",
    "incidents": "closed",
    # Incident audit children purge as orphans of their parent incident
    # (see purge_retention) — they live exactly as long as the record
    # they explain.
    "incident_timeline": "closed",
    "incident_contributions": "closed",
    "entities": "entity",
    "push_queue": "sent",
    "schema_meta": "keep",
    "runtime_state": "keep",
    "baselines": "keep",
    # identity_hypotheses: stale "candidate" rows purge with the entity
    # window — they regenerate as evidence recurs. "linked" hypotheses are
    # load-bearing for detection joins and "rejected" ones prevent relink
    # churn, so only stale candidates are eligible.
    "identity_hypotheses": "candidate",
}

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

# Schema v4 (D1): canonical provenance-bearing observation store.
#
# Observations are the evidence substrate every later layer (replay,
# identity, fusion, incidents) reads from. They capture WHAT was seen
# (kind + identity_key), WHEN (ts is the source-corrected timestamp,
# recorded_ts the wall clock at insert), WHERE (optional lat/lon), and
# the PROVENANCE needed to reproduce a conclusion from recorded data
# (source, source_ref, cycle_id, detector, input_digest).
#
# Append-only: UPDATE is rejected at the database level by trigger —
# correct an observation by recording a new one. identity_key is stored
# unencrypted so provenance queries stay deterministic; at-rest lifecycle
# for these rows is owned by retention (D8), not by this schema.
SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS observations (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            REAL NOT NULL,
  recorded_ts   REAL NOT NULL,
  source        TEXT NOT NULL CHECK (length(source) > 0),
  kind          TEXT NOT NULL CHECK (length(kind) > 0),
  identity_key  TEXT NOT NULL CHECK (length(identity_key) > 0),
  detector      TEXT,
  lat           REAL,
  lon           REAL,
  accuracy_m    REAL,
  payload_json  TEXT,
  cycle_id      INTEGER NOT NULL,
  source_ref    TEXT NOT NULL CHECK (length(source_ref) > 0),
  input_digest  TEXT NOT NULL CHECK (length(input_digest) > 0),
  session_id    TEXT,
  CHECK (source != 'detector' OR (detector IS NOT NULL AND length(detector) > 0))
);
CREATE INDEX IF NOT EXISTS idx_obs_identity_ts ON observations(identity_key, ts);
CREATE INDEX IF NOT EXISTS idx_obs_source_ts ON observations(source, ts);
CREATE INDEX IF NOT EXISTS idx_obs_cycle ON observations(cycle_id);

CREATE TRIGGER IF NOT EXISTS trg_observations_no_update
BEFORE UPDATE ON observations
BEGIN
  SELECT RAISE(ABORT, 'observations is append-only: record a new observation instead');
END;
"""

# Schema v4, D3 identity hypotheses: links between two radio identities are
# stored as confidence-rated hypotheses with reasons — never silently merged.
# This completes the build spec's v4 store definition (which names
# identity_hypotheses alongside observations); the DDL is idempotent and runs
# on every open so stores already at v4 pick the table up without a schema
# version bump. Keys follow the observations.identity_key decision: stored
# unencrypted so provenance/idempotency queries stay deterministic; at-rest
# lifecycle is owned by retention (D8).
SCHEMA_V4_IDENTITY = """
CREATE TABLE IF NOT EXISTS identity_hypotheses (
  hypothesis_id  TEXT PRIMARY KEY,
  key_a          TEXT NOT NULL CHECK (length(key_a) > 0),
  key_b          TEXT NOT NULL CHECK (length(key_b) > 0),
  confidence     REAL NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('candidate','linked','rejected')),
  reasons_json   TEXT NOT NULL DEFAULT '[]',
  created_ts     REAL NOT NULL,
  updated_ts     REAL NOT NULL,
  CHECK (key_a < key_b)
);
CREATE INDEX IF NOT EXISTS idx_hyp_status ON identity_hypotheses(status, updated_ts DESC);
CREATE INDEX IF NOT EXISTS idx_hyp_key_a ON identity_hypotheses(key_a);
CREATE INDEX IF NOT EXISTS idx_hyp_key_b ON identity_hypotheses(key_b);
"""

# Schema v4, D2 incident lifecycle v2: the phenomenon incident carries its
# lifecycle state, fused confidence, operator disposition, and a
# session-independent phenomenon key on the incidents row itself (additive
# columns), with an append-only incident_timeline recording every state move
# (the confidence history) and incident_contributions recording which
# detectors/evidence classes feed the phenomenon. Same pattern as
# identity_hypotheses above: idempotent DDL run on every open — part of v4,
# no schema_meta bump. The timeline is the audit trail; the events table
# still receives one event per transition for the existing audit surface.
SCHEMA_V4_INCIDENTS = """
CREATE TABLE IF NOT EXISTS incident_timeline (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id   INTEGER NOT NULL REFERENCES incidents(id),
  ts            REAL NOT NULL,
  from_state    TEXT,
  to_state      TEXT NOT NULL,
  reason        TEXT NOT NULL,
  confidence    REAL,
  detail_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id, id);
CREATE INDEX IF NOT EXISTS idx_timeline_ts ON incident_timeline(ts);

CREATE TABLE IF NOT EXISTS incident_contributions (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id    INTEGER NOT NULL REFERENCES incidents(id),
  detector       TEXT NOT NULL,
  evidence_class TEXT NOT NULL,
  hits           INTEGER NOT NULL DEFAULT 1,
  first_ts       REAL NOT NULL,
  last_ts        REAL NOT NULL,
  detail_json    TEXT,
  UNIQUE(incident_id, detector, evidence_class)
);
CREATE INDEX IF NOT EXISTS idx_contrib_incident ON incident_contributions(incident_id);
"""

# Additive incidents columns for the D2 lifecycle (guarded idempotent ALTERs,
# same pattern as the v2 suppressed/evidence_json columns).
_LIFECYCLE_COLUMNS = (
    ("lifecycle_state", "TEXT"),
    ("confidence", "REAL"),
    ("disposition", "TEXT"),
    ("phenomenon_key", "TEXT"),
)


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
        # Each pragma returns a row; fetch it so the statement finalizes —
        # unconsumed cursors make the later VACUUM fail with
        # "SQL statements in progress".
        c = self.conn.cursor()
        c.execute("PRAGMA journal_mode=WAL").fetchall()
        c.execute(f"PRAGMA synchronous={sync}").fetchall()
        c.execute("PRAGMA temp_store=MEMORY").fetchall()
        c.execute("PRAGMA foreign_keys=ON").fetchall()
        c.execute("PRAGMA busy_timeout=5000").fetchall()
        c.execute("PRAGMA wal_autocheckpoint=1000").fetchall()
        self._enable_incremental_vacuum()

    def _enable_incremental_vacuum(self) -> None:
        """D8: incremental vacuum so purged rows actually leave the file.

        Without auto_vacuum, DELETE only moves pages to the freelist —
        deleted identifiers stay recoverable in the file until a full
        VACUUM. auto_vacuum=INCREMENTAL lets purge reclaim space in
        bounded chunks (vacuum_incremental). The mode only takes effect
        on a rebuilt database, so an existing DB is rebuilt once here;
        fresh databases pick the mode up before their first table exists.
        """
        try:
            av = int(self.conn.execute("PRAGMA auto_vacuum").fetchone()[0])
            if av != 2:  # 0=NONE, 1=FULL, 2=INCREMENTAL
                self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
                self.conn.execute("VACUUM")
        except sqlite3.Error as e:
            logger.warning("incremental vacuum setup failed: %s", e)

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
            version = 3
        if version < 4:
            self._migrate_v4(c)
            c.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES (?, ?)",
                ("version", "4"),
            )
        # D3 completes the v4 store definition with identity_hypotheses.
        # Idempotent DDL (CREATE IF NOT EXISTS) so databases already at v4
        # pick the table up on next open — no schema_meta bump, this is part
        # of v4, not a new schema version.
        c.executescript(SCHEMA_V4_IDENTITY)

        # D2 completes the v4 store definition with the incident lifecycle:
        # timeline + contributions tables and additive incidents columns
        # (lifecycle_state, confidence, disposition, phenomenon_key).
        self._migrate_v4_incidents(c)

    def _migrate_v4_incidents(self, c: sqlite3.Cursor) -> None:
        """D2 incident lifecycle: idempotent additive DDL, no version bump."""
        c.executescript(SCHEMA_V4_INCIDENTS)
        existing = {
            r["name"] for r in c.execute("PRAGMA table_info(incidents)").fetchall()
        }
        for name, decl in _LIFECYCLE_COLUMNS:
            if name not in existing:
                c.execute(f"ALTER TABLE incidents ADD COLUMN {name} {decl}")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_phenomenon "
            "ON incidents(phenomenon_key)"
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

    def _migrate_v4(self, c: sqlite3.Cursor) -> None:
        """Canonical observation store: additive, no existing table is altered."""
        c.executescript(SCHEMA_V4)

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
            WHERE status='open' AND last_seen < ? AND lifecycle_state IS NULL
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

    # --- D2 incident lifecycle persistence ---------------------------------

    def get_incident_by_key(self, incident_key: str) -> Optional[sqlite3.Row]:
        """Fetch one incident row by its (unique) incident key."""
        return self.conn.execute(
            "SELECT * FROM incidents WHERE incident_key=?", (incident_key,)
        ).fetchone()

    def ensure_phenomenon_incident(
        self,
        *,
        incident_key: str,
        entity_type: str,
        subject: str,
        ts: float,
        session_id: str,
    ) -> Tuple[int, bool]:
        """Find-or-create the phenomenon incident for ``incident_key``.

        Session-independent: the key is subject-based (one phenomenon per
        subject, regardless of which detector fired), never session-scoped,
        so a restart rehydrates the SAME incident — the D2 replacement for
        session-scoped keys. On creation the row
        starts at lifecycle NEW with an opening timeline row (NULL -> new)
        and an ``incident_opened`` audit event.
        """
        row = self.get_incident_by_key(incident_key)
        if row is not None:
            return int(row["id"]), False
        entity_id = self.upsert_entity(entity_type, subject, ts)
        cur = self.conn.execute(
            """
            INSERT INTO incidents(
              incident_key, entity_id, event_type, window_label, severity,
              session_id, first_seen, last_seen, observation_count, status,
              closed_at, summary, detail_json, kismet_db,
              lifecycle_state, confidence, disposition, phenomenon_key
            ) VALUES (?, ?, 'phenomenon', 'fused', 'info', ?, ?, ?, 0,
                      'open', NULL, ?, NULL, NULL, 'new', NULL, NULL, ?)
            """,
            (
                incident_key,
                entity_id,
                session_id,
                ts,
                ts,
                f"phenomenon {entity_type} {subject}",
                incident_key,
            ),
        )
        iid = int(cur.lastrowid)
        self._append_timeline(iid, ts, None, "new", "first_observation", None)
        self.conn.execute(
            """
            INSERT INTO events(ts, event_type, incident_id, entity_id, severity, summary, detail_json, session_id)
            VALUES (?, 'incident_opened', ?, ?, 'info', ?, ?, ?)
            """,
            (
                ts,
                iid,
                entity_id,
                f"phenomenon opened: {subject}",
                json.dumps({"phenomenon_key": incident_key}, sort_keys=True),
                session_id,
            ),
        )
        return iid, True

    def _append_timeline(
        self,
        incident_id: int,
        ts: float,
        from_state: Optional[str],
        to_state: str,
        reason: str,
        confidence: Optional[float],
    ) -> None:
        """Append one incident_timeline row (transition or note record)."""
        self.conn.execute(
            """
            INSERT INTO incident_timeline(
              incident_id, ts, from_state, to_state, reason, confidence
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, ts, from_state, to_state, reason, confidence),
        )

    def apply_transition(self, plan: Any) -> None:
        """Persist one validated lifecycle move: row update + timeline + event.

        The persistence half of ``incidents.transition`` — the ONLY writer
        of incidents.lifecycle_state. Updates the row (lifecycle state,
        confidence, the legacy status/severity columns, closed_at,
        disposition), appends the timeline row, and emits the
        ``incident_transition`` audit event.
        """
        from cyt_platform.incidents import (
            ACTIVE_STATES,
            SEVERITY_FOR_STATE,
            IncidentStatus,
        )

        new_severity = SEVERITY_FOR_STATE[plan.to_state]
        active = plan.to_state in ACTIVE_STATES
        disposition = (
            plan.to_state.value
            if plan.to_state
            in (
                IncidentStatus.RESOLVED,
                IncidentStatus.FALSE_POSITIVE,
                IncidentStatus.KNOWN_DEVICE,
            )
            else None
        )
        self.conn.execute(
            """
            UPDATE incidents SET lifecycle_state=?, confidence=?,
              severity=COALESCE(?, severity), status=?,
              closed_at=?, disposition=?
            WHERE id=?
            """,
            (
                plan.to_state.value,
                plan.confidence,
                new_severity,
                "open" if active else "closed",
                None if active else plan.ts,
                disposition,
                plan.incident_id,
            ),
        )
        row = self.conn.execute(
            "SELECT incident_key, entity_id, severity, session_id FROM incidents WHERE id=?",
            (plan.incident_id,),
        ).fetchone()
        detail = {
            "incident_key": row["incident_key"],
            "from": plan.from_state.value,
            "to": plan.to_state.value,
            "confidence": plan.confidence,
            "reason": plan.reason,
        }
        self._append_timeline(
            plan.incident_id,
            plan.ts,
            plan.from_state.value,
            plan.to_state.value,
            plan.reason,
            plan.confidence,
        )
        self.conn.execute(
            """
            INSERT INTO events(ts, event_type, incident_id, entity_id, severity, summary, detail_json, session_id)
            VALUES (?, 'incident_transition', ?, ?, ?, ?, ?, ?)
            """,
            (
                plan.ts,
                plan.incident_id,
                int(row["entity_id"]),
                str(new_severity or row["severity"]),
                f"lifecycle {plan.from_state.value} -> {plan.to_state.value}: {plan.reason}",
                json.dumps(detail, sort_keys=True),
                row["session_id"],
            ),
        )

    def update_incident_confidence(self, incident_id: int, confidence: float) -> None:
        """Refresh the fused confidence between transitions.

        The transition history (with the confidence at each move) lives in
        incident_timeline; this keeps the row's current number fresh for
        surfaces that read the column directly.
        """
        self.conn.execute(
            "UPDATE incidents SET confidence=? WHERE id=?", (confidence, incident_id)
        )

    def touch_incident(self, incident_id: int, ts: float) -> None:
        """Stamp the freshest EVIDENCE time on a phenomenon incident.

        Kept separate from apply_transition on purpose: state moves are
        engine events, evidence is what staleness/decay measure. A
        transition that bumped last_seen would let the engine's own moves
        defer staleness indefinitely.
        """
        self.conn.execute(
            "UPDATE incidents SET last_seen=MAX(last_seen, ?) WHERE id=?",
            (float(ts), incident_id),
        )

    def record_contribution(
        self,
        incident_id: int,
        detector: str,
        evidence_class: str,
        ts: float,
        detail: Optional[dict] = None,
    ) -> None:
        """Upsert one detector's contribution to a phenomenon incident.

        A contribution is a cumulative fact about the phenomenon, not a
        per-cycle event: the same (incident, detector, evidence class)
        recurring across cycles extends the window (hits + 1, last_ts
        moves forward) instead of duplicating. The first detail sticks —
        later details ride on the detector rows and the timeline.
        """
        self.conn.execute(
            """
            INSERT INTO incident_contributions(
              incident_id, detector, evidence_class, hits, first_ts, last_ts, detail_json
            ) VALUES (?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(incident_id, detector, evidence_class)
            DO UPDATE SET hits=hits+1, last_ts=MAX(last_ts, excluded.last_ts)
            """,
            (
                incident_id,
                detector,
                evidence_class,
                float(ts),
                float(ts),
                json.dumps(detail, sort_keys=True) if detail is not None else None,
            ),
        )

    def list_incident_contributions(self, incident_id: int) -> List[dict]:
        """The incident's detector contributions, deterministic order."""
        rows = self.conn.execute(
            """
            SELECT detector, evidence_class, hits, first_ts, last_ts, detail_json
            FROM incident_contributions WHERE incident_id = ?
            ORDER BY detector, evidence_class
            """,
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count_incident_contributions(self, incident_id: int) -> int:
        """Distinct (detector, evidence-class) contributions recorded so far."""
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM incident_contributions WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
        return int(row["c"])

    def append_incident_note(
        self,
        incident_id: int,
        ts: float,
        reason: str,
        confidence: Optional[float] = None,
    ) -> None:
        """Record a non-transition observation on the timeline (from==to).

        Used for reopen-suppressed evidence on disposed incidents: the
        operator's disposition sticks, but the observation is not silently
        dropped — it goes on the record. Notes do not emit events; the
        events table is for state changes.
        """
        row = self.conn.execute(
            "SELECT lifecycle_state FROM incidents WHERE id=?", (incident_id,)
        ).fetchone()
        if row is None or row["lifecycle_state"] is None:
            return
        self._append_timeline(
            incident_id,
            ts,
            row["lifecycle_state"],
            row["lifecycle_state"],
            f"note: {reason}",
            confidence,
        )

    def touched_incidents_since(self, since_ts: float) -> List[dict]:
        """Detector-owned incident rows last observed after ``since_ts``.

        The engine's per-cycle input: legacy detection rows (lifecycle_state
        IS NULL, never phenomenon rows), oldest first — deterministic order
        for deterministic fusion.
        """
        rows = self.conn.execute(
            """
            SELECT i.id, i.incident_key, i.event_type, i.window_label,
                   i.severity, i.session_id, i.first_seen, i.last_seen,
                   i.summary, i.evidence_json,
                   e.entity_type, e.key AS entity_key
            FROM incidents i JOIN entities e ON e.id = i.entity_id
            WHERE i.last_seen > ?
              AND i.lifecycle_state IS NULL
              AND i.event_type != 'phenomenon'
            ORDER BY i.last_seen, i.incident_key
            """,
            (float(since_ts),),
        ).fetchall()
        return [dict(r) for r in rows]

    def active_phenomenon_incidents(self) -> List[dict]:
        """Engine-owned incident rows in an active lifecycle state."""
        rows = self.conn.execute(
            """
            SELECT id, incident_key, phenomenon_key, lifecycle_state,
                   confidence, disposition, severity, last_seen, first_seen,
                   session_id
            FROM incidents
            WHERE phenomenon_key IS NOT NULL
              AND lifecycle_state IN ('new', 'observing', 'watch', 'alert')
            ORDER BY incident_key
            """,
        ).fetchall()
        return [dict(r) for r in rows]

    def list_incident_timeline(self, incident_id: int) -> List[dict]:
        """The append-only transition timeline, oldest first."""
        rows = self.conn.execute(
            """
            SELECT id, ts, from_state, to_state, reason, confidence
            FROM incident_timeline WHERE incident_id = ? ORDER BY id
            """,
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]

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
        """Purge every table per its retention class; return per-table row counts.

        Retention is the only sanctioned deletion path for observations:
        explicit, bounded, and class-driven — never incidental. Space is
        reclaimed by vacuum_incremental (run outside any transaction).
        """
        now = now or time.time()
        medium_days = float(self.cfg.get("retention_days") or 14)
        hb_days = float(self.cfg.get("heartbeat_keep_days") or 7)
        ent_days = float(self.cfg.get("entity_retention_days") or 30)
        obs_days = float(self.cfg.get("observation_retention_days") or 7)
        medium_cut = now - medium_days * 86400
        hb_cut = now - hb_days * 86400
        ent_cut = now - ent_days * 86400
        obs_cut = now - obs_days * 86400
        c = self.conn.cursor()
        counts: Dict[str, int] = {}
        counts["observations"] = c.execute(
            "DELETE FROM observations WHERE ts < ?", (obs_cut,)
        ).rowcount
        counts["heartbeats"] = c.execute(
            "DELETE FROM heartbeats WHERE ts < ?", (hb_cut,)
        ).rowcount
        counts["events"] = c.execute(
            "DELETE FROM events WHERE ts < ?", (medium_cut,)
        ).rowcount
        counts["status_history"] = c.execute(
            "DELETE FROM status_history WHERE ts < ?", (medium_cut,)
        ).rowcount
        counts["location_sightings"] = c.execute(
            "DELETE FROM location_sightings WHERE last_seen < ?", (medium_cut,)
        ).rowcount
        counts["cotravel"] = c.execute(
            "DELETE FROM cotravel WHERE last_seen < ?", (medium_cut,)
        ).rowcount
        counts["fingerprints"] = c.execute(
            "DELETE FROM fingerprints WHERE last_seen < ?", (medium_cut,)
        ).rowcount
        counts["entity_fingerprints"] = c.execute(
            "DELETE FROM entity_fingerprints WHERE linked_ts < ?", (medium_cut,)
        ).rowcount
        counts["baseline_sightings"] = c.execute(
            "DELETE FROM baseline_sightings WHERE ts < ?", (medium_cut,)
        ).rowcount
        counts["incidents"] = c.execute(
            "DELETE FROM incidents WHERE status='closed' AND COALESCE(closed_at, last_seen) < ?",
            (medium_cut,),
        ).rowcount
        # Incident audit children (D2): orphan purge — rows whose parent
        # incident is gone have no meaning. Keeps each timeline/contribution
        # exactly as long as the incident it explains.
        counts["incident_timeline"] = c.execute(
            "DELETE FROM incident_timeline "
            "WHERE incident_id NOT IN (SELECT id FROM incidents)"
        ).rowcount
        counts["incident_contributions"] = c.execute(
            "DELETE FROM incident_contributions "
            "WHERE incident_id NOT IN (SELECT id FROM incidents)"
        ).rowcount
        # Entities referenced by surviving rows (open incidents, live
        # fingerprint links) are pinned — FKs must not break and the
        # reference chain is the audit trail.
        counts["entities"] = c.execute(
            "DELETE FROM entities WHERE last_seen < ? AND ignore=0 "
            "AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.entity_id = entities.id) "
            "AND NOT EXISTS (SELECT 1 FROM entity_fingerprints ef WHERE ef.entity_id = entities.id)",
            (ent_cut,),
        ).rowcount
        # identity_hypotheses "candidate" class: only stale candidates go —
        # linked rows are load-bearing for detection joins, rejected rows
        # prevent relink churn.
        counts["identity_hypotheses"] = c.execute(
            "DELETE FROM identity_hypotheses "
            "WHERE status='candidate' AND updated_ts < ?",
            (ent_cut,),
        ).rowcount
        counts["push_sent"] = c.execute(
            "DELETE FROM push_queue WHERE status='sent' AND COALESCE(sent_ts, created_ts) < ?",
            (medium_cut,),
        ).rowcount
        return counts

    def vacuum_incremental(self, max_pages: int = 512) -> Dict[str, int]:
        """Reclaim file space after purge via incremental vacuum.

        Must be called OUTSIDE a store transaction (it runs its own).
        Returns page/freelist counts before and after so callers — and the
        D8 retention test — can assert real space reclamation, not just
        row deletion.
        """
        if self._in_txn:
            raise RuntimeError(
                "vacuum_incremental must run outside a store transaction"
            )
        self.checkpoint()
        c = self.conn.cursor()
        pages_before = int(c.execute("PRAGMA page_count").fetchone()[0])
        free_before = int(c.execute("PRAGMA freelist_count").fetchone()[0])
        try:
            c.execute("PRAGMA incremental_vacuum(%d)" % max(1, int(max_pages)))
        except sqlite3.Error as e:
            logger.warning("incremental_vacuum failed: %s", e)
        return {
            "page_count_before": pages_before,
            "freelist_before": free_before,
            "page_count": int(c.execute("PRAGMA page_count").fetchone()[0]),
            "freelist_count": int(c.execute("PRAGMA freelist_count").fetchone()[0]),
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

    # --- observations (schema v4, D1) ---
    @staticmethod
    def _observation_row_to_dict(row: sqlite3.Row) -> dict:
        out = dict(row)
        payload_json = out.pop("payload_json", None)
        if payload_json:
            try:
                out["payload"] = json.loads(payload_json)
            except json.JSONDecodeError:
                out["payload"] = None
        else:
            out["payload"] = None
        return out

    def record_observation(
        self,
        *,
        ts: float,
        source: str,
        kind: str,
        identity_key: str,
        cycle_id: int,
        source_ref: str,
        input_digest: str,
        detector: Optional[str] = None,
        lat: Optional[float] = None,
        lon: Optional[float] = None,
        accuracy_m: Optional[float] = None,
        payload: Optional[dict] = None,
        session_id: Optional[str] = None,
        recorded_ts: Optional[float] = None,
    ) -> int:
        """Persist one canonical observation; return its row id.

        Provenance fields (source, source_ref, cycle_id, input_digest) are
        mandatory — an observation without provenance cannot exist. There
        is deliberately no update path: correct an observation by recording
        a new one.
        """
        missing = [
            name
            for name, value in (
                ("ts", ts),
                ("source", source),
                ("kind", kind),
                ("identity_key", identity_key),
                ("cycle_id", cycle_id),
                ("source_ref", source_ref),
                ("input_digest", input_digest),
            )
            if value is None or (isinstance(value, str) and not value.strip())
        ]
        if missing:
            raise ValueError(
                "observation missing provenance fields: " + ", ".join(missing)
            )
        if source == "detector" and not (detector and detector.strip()):
            raise ValueError(
                "observation with source='detector' requires a detector identity"
            )
        if payload is not None and not isinstance(payload, dict):
            raise ValueError("observation payload must be a dict or None")

        ts_f = float(ts)
        if not math.isfinite(ts_f):
            raise ValueError("observation ts must be a finite epoch value")
        cycle = int(cycle_id)
        recorded = float(recorded_ts) if recorded_ts is not None else time.time()

        cur = self.conn.execute(
            """
            INSERT INTO observations(
              ts, recorded_ts, source, kind, identity_key, detector,
              lat, lon, accuracy_m, payload_json, cycle_id,
              source_ref, input_digest, session_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts_f,
                recorded,
                str(source),
                str(kind),
                str(identity_key),
                detector,
                lat,
                lon,
                accuracy_m,
                json.dumps(payload) if payload else None,
                cycle,
                str(source_ref),
                str(input_digest),
                session_id,
            ),
        )
        return int(cur.lastrowid)

    def get_observation(self, obs_id: int) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM observations WHERE id = ?", (int(obs_id),)
        ).fetchone()
        if row is None:
            return None
        return self._observation_row_to_dict(row)

    def query_observations(
        self,
        *,
        identity_key: Optional[str] = None,
        source: Optional[str] = None,
        kind: Optional[str] = None,
        detector: Optional[str] = None,
        cycle_id: Optional[int] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 500,
    ) -> List[dict]:
        """Query observations by device, time range, source, or cycle.

        All filters are parameterized; results order by (ts, id) so a
        given query is deterministic. Returns dicts with payload parsed.
        """
        clauses: List[str] = []
        params: List[object] = []
        if identity_key is not None:
            clauses.append("identity_key = ?")
            params.append(identity_key)
        if source is not None:
            clauses.append("source = ?")
            params.append(source)
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        if detector is not None:
            clauses.append("detector = ?")
            params.append(detector)
        if cycle_id is not None:
            clauses.append("cycle_id = ?")
            params.append(int(cycle_id))
        if since is not None:
            clauses.append("ts >= ?")
            params.append(float(since))
        if until is not None:
            clauses.append("ts <= ?")
            params.append(float(until))
        sql = "SELECT * FROM observations"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts ASC, id ASC LIMIT ?"
        params.append(max(1, min(int(limit), 5000)))
        rows = self.conn.execute(sql, tuple(params)).fetchall()
        return [self._observation_row_to_dict(r) for r in rows]

    # --- identity hypotheses (schema v4, D3) ---
    @staticmethod
    def _hypothesis_row_to_dict(row: sqlite3.Row) -> dict:
        out = dict(row)
        reasons_json = out.pop("reasons_json", None)
        if reasons_json:
            try:
                out["reasons"] = json.loads(reasons_json)
            except json.JSONDecodeError:
                out["reasons"] = []
        else:
            out["reasons"] = []
        return out

    def upsert_identity_hypothesis(
        self,
        *,
        key_a: str,
        key_b: str,
        confidence: float,
        status: str,
        reasons: List[str],
        ts: float,
    ) -> dict:
        """Persist one scored identity-link hypothesis; returns the stored row.

        Keys are canonicalized (key_a < key_b) and hypothesis_id derives from
        the sorted pair, so A→B and B→A are the same hypothesis. Merge rules:
        a co-observation veto ('rejected') is sticky and demotes any prior
        state; otherwise confidence is monotone up and the best-scoring
        evaluation's status and reasons stand. Lower re-scores never downgrade
        a hypothesis (decay is incident territory, not hypothesis territory).
        """
        a, b = sorted((str(key_a), str(key_b)))
        if a == b:
            raise ValueError("identity hypothesis requires two distinct keys")
        if status not in ("candidate", "linked", "rejected"):
            raise ValueError(f"invalid hypothesis status: {status}")
        conf = max(0.0, min(1.0, float(confidence)))
        hid = hashlib.sha256(f"{a}|{b}".encode("utf-8")).hexdigest()[:16]
        reasons_json = json.dumps(list(reasons))
        ts_f = float(ts)

        row = self.conn.execute(
            "SELECT status, confidence FROM identity_hypotheses WHERE hypothesis_id = ?",
            (hid,),
        ).fetchone()
        if row is None:
            self.conn.execute(
                """
                INSERT INTO identity_hypotheses(
                  hypothesis_id, key_a, key_b, confidence, status,
                  reasons_json, created_ts, updated_ts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (hid, a, b, conf, status, reasons_json, ts_f, ts_f),
            )
        elif row["status"] == "rejected":
            pass  # veto is sticky — later scores cannot resurrect the link
        elif status == "rejected":
            self.conn.execute(
                """
                UPDATE identity_hypotheses
                SET confidence=0.0, status='rejected', reasons_json=?, updated_ts=?
                WHERE hypothesis_id=?
                """,
                (reasons_json, ts_f, hid),
            )
        elif conf >= row["confidence"]:
            self.conn.execute(
                """
                UPDATE identity_hypotheses
                SET confidence=?, status=?, reasons_json=?, updated_ts=?
                WHERE hypothesis_id=?
                """,
                (conf, status, reasons_json, ts_f, hid),
            )
        else:
            self.conn.execute(
                "UPDATE identity_hypotheses SET updated_ts=? WHERE hypothesis_id=?",
                (ts_f, hid),
            )
        stored = self.get_identity_hypothesis(hid)
        if stored is None:  # pragma: no cover - defensive; row was just written
            raise RuntimeError(f"hypothesis {hid} missing after upsert")
        return stored

    def get_identity_hypothesis(self, hypothesis_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM identity_hypotheses WHERE hypothesis_id = ?",
            (str(hypothesis_id),),
        ).fetchone()
        if row is None:
            return None
        return self._hypothesis_row_to_dict(row)

    def list_identity_hypotheses(
        self,
        *,
        status: Optional[str] = None,
        key: Optional[str] = None,
        limit: int = 200,
    ) -> List[dict]:
        """List hypotheses, optionally filtered by status or either key.

        All filters are parameterized; results order by confidence so the
        strongest links surface first.
        """
        clauses: List[str] = []
        params: List[object] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if key is not None:
            clauses.append("(key_a = ? OR key_b = ?)")
            params.extend([key, key])
        sql = "SELECT * FROM identity_hypotheses"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY confidence DESC, key_a ASC LIMIT ?"
        params.append(max(1, min(int(limit), 5000)))
        rows = self.conn.execute(sql, tuple(params)).fetchall()
        return [self._hypothesis_row_to_dict(r) for r in rows]

    def macs_for_fingerprint(self, fingerprint_id: int) -> List[str]:
        """Decrypted identity keys for every entity linked to a fingerprint row.

        Supports hypothesis pairing across cycles: identities sharing a
        persisted fingerprint are candidates for the same device claim.
        """
        rows = self.conn.execute(
            """
            SELECT e.key AS key FROM entity_fingerprints ef
            JOIN entities e ON e.id = ef.entity_id
            WHERE ef.fingerprint_id = ?
            """,
            (int(fingerprint_id),),
        ).fetchall()
        return [self._dec_key(r["key"]) for r in rows]

    def features_for_identity(self, entity_type: str, key: str) -> List[dict]:
        """Fingerprint rows linked to an identity key (additive query, D3).

        Prior-cycle identities are not in the current device list, so the
        fingerprint features they presented come from this join. Returns dicts
        with fingerprint_id, fingerprint_type, fingerprint_hash, features.
        """
        store_key = self._enc_key(key)
        rows = self.conn.execute(
            """
            SELECT f.id AS id, f.fingerprint_type AS fingerprint_type,
                   f.fingerprint_hash AS fingerprint_hash,
                   f.features_json AS features_json
            FROM entities e
            JOIN entity_fingerprints ef ON ef.entity_id = e.id
            JOIN fingerprints f ON f.id = ef.fingerprint_id
            WHERE e.entity_type = ? AND (e.key = ? OR e.key = ?)
            """,
            (entity_type, store_key, key),
        ).fetchall()
        out: List[dict] = []
        for r in rows:
            features = None
            if r["features_json"]:
                try:
                    features = json.loads(r["features_json"])
                except json.JSONDecodeError:
                    features = None
            out.append(
                {
                    "fingerprint_id": int(r["id"]),
                    "fingerprint_type": r["fingerprint_type"],
                    "fingerprint_hash": r["fingerprint_hash"],
                    "features": features,
                }
            )
        return out

