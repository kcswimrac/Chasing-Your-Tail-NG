"""Explainable alert evidence strings (P1)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from cyt_platform.detectors import subject_fingerprint


def build_evidence(
    *,
    kind: str,
    subject: str,
    window: str,
    severity: str,
    observation_count: int = 1,
    place_id: Optional[str] = None,
    baselined: bool = False,
    suppressed: bool = False,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    reasons: List[str] = []
    if kind == "mac_reappear":
        reasons.append(f"MAC reappeared in {window} minute window")
    elif kind == "ssid_probe_repeat":
        reasons.append(f"SSID probe repeated in {window} minute window")
    else:
        reasons.append(f"Event {kind} in window {window}")

    reasons.append(f"severity={severity}")
    if observation_count > 1:
        reasons.append(f"observed {observation_count} times this session open")
    if place_id:
        reasons.append(f"place={place_id}")
    if baselined:
        reasons.append("entity is on baseline for this place")
    if suppressed:
        reasons.append("suppressed from threat score (baseline/ignore)")

    evidence = {
        "reasons": reasons,
        "kind": kind,
        "window": window,
        "severity": severity,
        "observation_count": observation_count,
        "place_id": place_id,
        "suppressed": suppressed,
        # never put full MAC/SSID in status; subject_hash for correlation only
        "subject_fp": _fp(subject),
    }
    if extra:
        evidence.update(extra)
    return evidence


def format_evidence_line(evidence: Dict[str, Any]) -> str:
    reasons = evidence.get("reasons") or []
    return "; ".join(reasons)


def _fp(subject: str) -> str:
    # S5: the subject fingerprint must be stable across restarts (its only
    # purpose is cross-restart correlation), so it uses the sha1-based
    # detectors.subject_fingerprint — never CPython's salted hash().
    return f"{subject_fingerprint(subject):08x}"
