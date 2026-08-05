"""Optional legacy cyt_log_* dual-write sink (EDC default: off)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional, TextIO

from cyt_platform.privacy import chmod_private_file, ensure_dir, redact_subject


class NullSink:
    def write(self, text: str) -> None:
        pass

    def close(self) -> None:
        pass


class LogFileSink:
    """File-like sink compatible with SecureCYTMonitor.log_file.write."""

    def __init__(self, path: Path, redact: bool = True):
        self.path = path
        self.redact = redact
        self._fh: TextIO = open(path, "w", buffering=1, encoding="utf-8")
        chmod_private_file(path, 0o600)

    @classmethod
    def create(cls, config: dict) -> "LogFileSink":
        paths = config.get("paths") or {}
        log_dir = Path(paths.get("log_dir") or "logs")
        ensure_dir(log_dir, 0o700)
        name = f"cyt_log_{time.strftime('%m%d%y_%H%M%S')}"
        redact = bool((config.get("service") or {}).get("legacy_log_redact", True))
        return cls(log_dir / name, redact=redact)

    def write(self, text: str) -> None:
        if self.redact and text:
            # Best-effort: leave structural messages; full MAC redaction is done
            # at emit sites when redacting — here we still write as-is for
            # compatibility when monitor already formatted messages.
            # When redacting is on, callers should prefer redacted messages;
            # we strip obvious MACs.
            import re
            text = re.sub(
                r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
                lambda m: redact_subject(m.group(0), "mac"),
                text,
            )
        self._fh.write(text)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass
