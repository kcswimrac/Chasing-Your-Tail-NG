"""PR1 privacy floor helpers: umask, permissions, error sanitization."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Optional, Union

# MAC-shaped tokens (xx:xx:xx:xx:xx:xx)
_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_HOME_PATH_RE = re.compile(r"(?:/home|/Users)/[^\s:]+")
_ABS_PATH_RE = re.compile(r"(?:/var|/opt|/tmp|/run)/[^\s:]+")

# Markup metacharacters that make free text active in HTML/XML/markdown
# sinks (script tags, CDATA terminators, markdown links/code spans).
_MARKUP_CHARS_RE = re.compile(r"[<>\[\]`]")

# Control/format characters: C0, DEL, C1, zero-width, and bidi/RTL
# overrides (direction spoofs are markup-adjacent operator tricks).
_EVIDENCE_CONTROL_RE = re.compile(
    "[\x00-\x1f\x7f\x80-\x9f\u200b-\u200f\u202a-\u202e\u2028\u2029\ufeff]"
)


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


def _stable_digest(subject: str) -> str:
    """4-hex digest of a subject, stable across processes and runs.

    Python's builtin ``hash()`` is salted per process (PYTHONHASHSEED), so
    any redacted value derived from it would break the deterministic-core
    contract (locked decision 4) the moment it lands in a replayed report.
    Same sha1-derived pattern as ``detectors.subject_fingerprint``.
    """
    digest = hashlib.sha1(subject.encode("utf-8")).digest()
    return f"{int.from_bytes(digest[:2], 'big'):04x}"


def redact_subject(subject: str, kind: str = "mac") -> str:
    """Redact identity for evidence/logs; stable across processes.

    MACs keep OUI + last octet (correlation survives, rest is masked);
    every other subject (SSID, device name, capability text) is replaced
    by a neutral ``ssid(len=N,h=XXXX)`` token carrying neither the raw
    text nor its markup.
    """
    if not subject:
        return "?"
    if kind == "mac" or ":" in subject:
        parts = subject.split(":")
        if len(parts) == 6:
            return f"{parts[0]}:{parts[1]}:xx:xx:xx:{parts[5]}"
    # SSID: length + stable short hash prefix
    return f"ssid(len={len(subject)},h={_stable_digest(subject)})"


def configured_subjects(config: dict) -> list:
    """Subject values (SSIDs) the operator named in config.

    These are the highest-sensitivity strings on the deployment — the
    operator's own trusted/monitored network names — so the logging layer
    redacts them wherever they appear, in any record, from any module.
    """
    rogue = config.get("rogue_ap_detection") or {}
    subjects = set(rogue.get("monitored_ssids") or [])
    for ap in rogue.get("trusted_aps") or []:
        ssid = ap.get("ssid") if isinstance(ap, dict) else None
        if ssid:
            subjects.add(ssid)
    return sorted(subjects)


def redact_subjects_in_text(text: str, subjects) -> str:
    """Replace every occurrence of a known subject with its stable token.

    Longest first, so overlapping names cannot leave a partial token.
    Pure and deterministic (``redact_subject`` is sha1-derived), so the
    logging filter that applies it stays replay- and test-stable.
    """
    if not isinstance(text, str):
        return text
    for subject in sorted({s for s in subjects if s}, key=len, reverse=True):
        if subject in text:
            text = text.replace(subject, redact_subject(subject, "ssid"))
    return text


def redact_evidence_text(text: str) -> str:
    """Neutralize identity and markup in one free-text evidence string.

    The evidence-path policy: no raw MAC, no raw subject text, nothing
    active in downstream HTML/XML/markdown sinks. MAC-shaped tokens are
    masked via ``redact_subject``; control/bidi characters and markup
    metacharacters are stripped, so a hostile SSID or device name that a
    detector embedded in a reason line renders as inert literal text.

    Pure and deterministic — safe inside the replay report contract.
    """
    if not isinstance(text, str):
        return text
    out = _MAC_RE.sub(lambda m: redact_subject(m.group(0), "mac"), text)
    out = _EVIDENCE_CONTROL_RE.sub(" ", out)
    out = _MARKUP_CHARS_RE.sub(" ", out)
    return " ".join(out.split())


# Evidence keys whose string values ARE the subject itself (device-derived
# names), so they get the full redact_subject treatment, not just
# markup stripping. Values under any other key are free text.
_SUBJECT_KEYS = frozenset(
    {"ssid", "name", "devicename", "commonname", "manuf", "manufacturer"}
)


def redact_evidence_object(obj: Any) -> Any:
    """Recursively redact every string in evidence-shaped data.

    Walks dicts/lists/tuples from stored evidence_json; non-string scalars
    pass through untouched. Dict keys are code-authored and kept.
    """
    if isinstance(obj, str):
        return redact_evidence_text(obj)
    if isinstance(obj, dict):
        return {
            key: (
                redact_subject(value, "ssid")
                if key in _SUBJECT_KEYS and isinstance(value, str)
                else redact_evidence_object(value)
            )
            for key, value in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [redact_evidence_object(item) for item in obj]
    return obj


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
