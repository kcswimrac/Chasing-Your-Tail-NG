"""Analyzer logging setup — journald-friendly stdout + optional private file.

Every handler carries a ``PrivacyFilter``: log records are a leak surface
(journald, analyzer.log), so identities are redacted and injection is
neutralized at the logging layer — no matter which module emitted the
record (S7).
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from cyt_platform.privacy import (
    chmod_private_file,
    configured_subjects,
    ensure_dir,
    redact_evidence_text,
    redact_subjects_in_text,
)


class PrivacyFilter(logging.Filter):
    """Redact identities and neutralize injection in every emitted record.

    The last line of defense before any handler writes:

    * subject values the operator named in config (trusted/monitored
      SSIDs) are replaced by their stable ``ssid(len=N,h=XXXX)`` token
      wherever they appear in the composed message;
    * MAC-shaped tokens are masked via ``redact_evidence_text``;
    * control characters, markup metacharacters, and every whitespace
      run — including the newlines a hostile SSID needs to forge a
      standalone log line — collapse to single spaces, so one record is
      always exactly one emitted line.

    Attached per handler (not per logger) so records from any module —
    including ones that interpolate raw subjects into their messages —
    pass through it on the way out.
    """

    def __init__(self, config: dict | None = None) -> None:
        super().__init__()
        self._subjects = configured_subjects(config or {})

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # A malformed format/arg pair must never bypass redaction.
            message = str(record.msg)
        message = redact_subjects_in_text(message, self._subjects)
        record.msg = redact_evidence_text(message)
        record.args = None
        return True


def setup_logging(config: dict, level: int = logging.INFO) -> logging.Logger:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    privacy_filter = PrivacyFilter(config)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh.addFilter(privacy_filter)
    root.addHandler(sh)

    log_dir = Path((config.get("paths") or {}).get("log_dir") or "logs")
    ensure_dir(log_dir, 0o700)
    log_path = log_dir / "analyzer.log"
    try:
        fh = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(fmt)
        fh.addFilter(privacy_filter)
        root.addHandler(fh)
        chmod_private_file(log_path, 0o600)
    except OSError:
        pass

    return logging.getLogger("cyt_platform")
