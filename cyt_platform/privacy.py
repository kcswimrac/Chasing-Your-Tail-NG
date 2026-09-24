"""PR1 privacy floor helpers: umask, permissions, error sanitization."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional, Union

# MAC-shaped tokens (xx:xx:xx:xx:xx:xx)
_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_HOME_PATH_RE = re.compile(r"(?:/home|/Users)/[^\s:]+")
_ABS_PATH_RE = re.compile(r"(?:/var|/opt|/tmp|/run)/[^\s:]+")


def apply_umask(config: Optional[dict] = None) -> int:
    """Set process umask to 0o077 (owner-only files by default)."""
    return os.umask(0o077)


def ensure_dir(path: Union[str, Path], mode: int = 0o700) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, mode)
    except OSError:
        pass
    return p


def chmod_private_file(path: Union[str, Path], mode: int = 0o600) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def sanitize_error(exc: BaseException, max_len: int = 200) -> str:
    """Sanitize exception detail for heartbeats / logs (no MACs, no home paths)."""
    name = type(exc).__name__
    msg = str(exc) if exc else ""
    msg = _MAC_RE.sub("<mac>", msg)
    msg = _HOME_PATH_RE.sub("<path>", msg)
    msg = _ABS_PATH_RE.sub("<path>", msg)
    # collapse whitespace
    msg = " ".join(msg.split())
    out = f"{name}: {msg}" if msg else name
    if len(out) > max_len:
        out = out[: max_len - 3] + "..."
    return out


def redact_subject(subject: str, kind: str = "mac") -> str:
    """Redact identity for legacy logs when legacy_log_redact is true."""
    if not subject:
        return "?"
    if kind == "mac" or ":" in subject:
        parts = subject.split(":")
        if len(parts) == 6:
            return f"{parts[0]}:{parts[1]}:xx:xx:xx:{parts[5]}"
    # SSID: length + short hash prefix
    h = abs(hash(subject)) % 0xFFFF
    return f"ssid(len={len(subject)},h={h:04x})"


def fde_ack_present(ack_path: str = "/etc/cyt/fde_ack") -> bool:
    return Path(ack_path).is_file()


def log_fde_notice_if_needed(config: dict, logger: Any) -> None:
    privacy = config.get("privacy") or {}
    if not privacy.get("require_fde_notice", True):
        return
    ack = privacy.get("fde_ack_path", "/etc/cyt/fde_ack")
    if not fde_ack_present(ack):
        logger.warning(
            "FIELD PRIVACY: FDE acknowledgment missing (%s). "
            "Full-disk encryption (or fscrypt on data_dir) is required before "
            "carrying this device in public until app-level store encryption lands. "
            "See deploy/FIELD_DEPLOY.md",
            ack,
        )
