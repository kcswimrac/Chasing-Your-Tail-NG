"""Panic wipe — secure erase of CYT sensitive paths (P1)."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from cyt_platform.crypto import sealed_path_for, secure_delete
from cyt_platform.privacy import sanitize_error

logger = logging.getLogger(__name__)


def wipe_inventory(config: dict) -> List[Path]:
    """All paths that may hold third-party RF identity or operator secrets."""
    paths_cfg = config.get("paths") or {}
    store_cfg = config.get("store") or {}
    status_cfg = config.get("status") or {}
    enc = store_cfg.get("encryption") or {}

    candidates: List[Path] = []

    def add(p: Optional[str]) -> None:
        if not p:
            return
        candidates.append(Path(p))

    add(store_cfg.get("path"))
    db = Path(store_cfg.get("path") or "data/cyt.db")
    candidates.append(sealed_path_for(db))
    candidates.append(Path(str(db) + "-wal"))
    candidates.append(Path(str(db) + "-shm"))
    candidates.append(db.parent / ".open" / db.name)
    candidates.append(db.parent / ".open" / (db.name + "-wal"))
    candidates.append(db.parent / ".open" / (db.name + "-shm"))

    # tmpfs runtime
    rt = enc.get("runtime_dir") or f"/dev/shm/cyt-{os.getuid()}"
    candidates.append(Path(rt) / db.name)
    candidates.append(Path(rt) / (db.name + "-wal"))
    candidates.append(Path(rt) / (db.name + "-shm"))

    add(status_cfg.get("file"))
    status_p = Path(status_cfg.get("file") or "data/run/status.json")
    candidates.append(status_p.with_suffix(status_p.suffix + ".tmp"))

    add(enc.get("key_file"))
    add(enc.get("salt_file") or "data/store_salt.bin")
    add(enc.get("password_file"))
    if os.environ.get("CYT_STORE_KEY_FILE"):
        candidates.append(Path(os.environ["CYT_STORE_KEY_FILE"]))
    if os.environ.get("CYT_STORE_PASSWORD_FILE"):
        candidates.append(Path(os.environ["CYT_STORE_PASSWORD_FILE"]))

    log_dir = Path(paths_cfg.get("log_dir") or "logs")
    if log_dir.is_dir():
        for p in log_dir.glob("cyt_log_*"):
            candidates.append(p)
        candidates.append(log_dir / "analyzer.log")
        for p in log_dir.glob("analyzer.log.*"):
            candidates.append(p)

    # LED state
    runtime = Path(paths_cfg.get("runtime_dir") or "data/run")
    candidates.append(runtime / "led.state")
    candidates.append(runtime / "led.json")

    # de-dupe preserve order
    seen = set()
    out: List[Path] = []
    for p in candidates:
        rp = p.resolve() if p.exists() else p
        key = str(rp)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def panic_wipe(config: dict, *, confirm: str = "", passes: int = 1) -> Dict[str, int]:
    """
    Secure-delete inventory. Requires confirm == 'YES' (or 'WIPE').
    Returns counts of deleted/missing/errors.
    """
    if confirm not in ("YES", "WIPE"):
        raise ValueError("panic_wipe requires confirm='YES' or 'WIPE'")

    deleted = 0
    missing = 0
    errors = 0
    for path in wipe_inventory(config):
        try:
            if path.is_file():
                secure_delete(path, passes=passes)
                deleted += 1
            elif path.is_dir():
                # only remove known empty-ish runtime dirs we own under .open / shm
                name = path.name
                if name in (".open",) or str(path).startswith("/dev/shm/cyt-"):
                    shutil.rmtree(path, ignore_errors=True)
                    deleted += 1
                else:
                    missing += 1
            else:
                missing += 1
        except Exception as e:
            logger.error("wipe error %s: %s", path, sanitize_error(e))
            errors += 1

    return {"deleted": deleted, "missing": missing, "errors": errors}
