"""Analyzer logging setup — journald-friendly stdout + optional private file."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from cyt_platform.privacy import chmod_private_file, ensure_dir


def setup_logging(config: dict, level: int = logging.INFO) -> logging.Logger:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    log_dir = Path((config.get("paths") or {}).get("log_dir") or "logs")
    ensure_dir(log_dir, 0o700)
    log_path = log_dir / "analyzer.log"
    try:
        fh = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
        chmod_private_file(log_path, 0o600)
    except OSError:
        pass

    return logging.getLogger("cyt_platform")
