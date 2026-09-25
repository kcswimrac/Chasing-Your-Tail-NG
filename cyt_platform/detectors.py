"""Detector contracts (D6): DetectionResult + EvidenceLine.

The fixed shapes every detector emits and the D2 incident engine / D4
confidence fusion consume. A ``DetectionResult`` is one detector's
per-cycle conclusion about one subject: what was detected, the severity
it classifies today, the evidence lines that support it, and the lines
that contradict it. Evidence lines are provenance-ready — ``obs_ids``
point at persisted observation rows and ``weight`` is the signed
contribution the D4 confidence model will assign (0.0 until then).

Detectors never hand-build incident kwargs: ``incident_fields`` is the
single result→``CytStore.observe_incident`` mapping, so every incident in
the store is contract-shaped by construction and fusion can replay the
same conversion.

Results are plain frozen dataclasses; ``detail`` is shallow-copied at
construction and treated as read-only (results are not hashable, but are
comparable). Severity stays an open string vocabulary on purpose — the
ie-relink path emits ``info`` — validated only as non-empty.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


def subject_fingerprint(subject: str) -> int:
    """Deterministic privacy-safe fingerprint of a subject identity.

    Replaces salted ``hash()`` fingerprints: stable across processes and
    restarts (locked decision 4, deterministic core). Same 32-bit width as
    the pre-contract ``subject_fp`` surface.
    """
    digest = hashlib.sha1(subject.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % 0xFFFFFFFF


@dataclass(frozen=True)
class EvidenceLine:
    """One named piece of evidence for or against a detection.

    ``kind`` is a stable taxonomy token (e.g. ``deauth_pattern``,
    ``copresence``, ``tracker_name_match``); ``detail`` is the
    human-readable line, redacted per the privacy policy; ``obs_ids``
    are provenance pointers into the observations table (empty when the
    detector has not consumed the observation feed yet); ``weight`` is
    the signed confidence contribution, assigned by the D4 model.
    """

    kind: str
    detail: str
    obs_ids: Tuple[int, ...] = ()
    weight: float = 0.0

    def __post_init__(self) -> None:
        if not str(self.kind).strip():
            raise ValueError("EvidenceLine.kind must be a non-empty string")
        if not str(self.detail).strip():
            raise ValueError("EvidenceLine.detail must be a non-empty string")
        if not math.isfinite(self.weight):
            raise ValueError("EvidenceLine.weight must be finite")


@dataclass(frozen=True)
class DetectionResult:
    """One detector's per-cycle conclusion about one subject.

    Required fields identify the detection (``detector``/``kind``/``subject``
    family) and its current classification (``severity``, ``summary``).
    Optional fields carry what fusion needs next: ``evidence`` and ``contra``
    lines, a computed ``confidence`` when the detector has one (BLE and
    co-travel scores; None where only static severity exists today), and a
    deterministic ``subject_fp`` for privacy-safe correlation.
    """

    detector: str
    kind: str
    subject: str
    subject_type: str
    window_label: str
    severity: str
    observed_at: float
    summary: str
    detail: Dict[str, Any] = field(default_factory=dict)
    evidence: Tuple[EvidenceLine, ...] = ()
    contra: Tuple[EvidenceLine, ...] = ()
    confidence: Optional[float] = None
    subject_fp: Optional[int] = None

    def __post_init__(self) -> None:
        for name in (
            "detector",
            "kind",
            "subject",
            "subject_type",
            "window_label",
            "severity",
            "summary",
        ):
            if not str(getattr(self, name)).strip():
                raise ValueError(
                    f"DetectionResult.{name} must be a non-empty string"
                )
        if not math.isfinite(self.observed_at):
            raise ValueError("DetectionResult.observed_at must be finite")
        if self.confidence is not None and not (
            math.isfinite(self.confidence) and 0.0 <= self.confidence <= 1.0
        ):
            raise ValueError(
                "DetectionResult.confidence must be None or within [0, 1]"
            )
        # Defensive copy: results are frozen, so the caller's dict must not
        # be a live back-door into an emitted result.
        object.__setattr__(self, "detail", dict(self.detail))


def _line_dict(line: EvidenceLine) -> Dict[str, Any]:
    """JSON-safe serialization of one evidence line (tuples become lists)."""
    return {
        "kind": line.kind,
        "detail": line.detail,
        "obs_ids": list(line.obs_ids),
        "weight": line.weight,
    }


def incident_fields(result: DetectionResult, *, session_id: str) -> Dict[str, Any]:
    """Map a DetectionResult to ``CytStore.observe_incident`` kwargs.

    The only result→incident conversion in the codebase. The stored
    ``evidence`` keeps the legacy ``reasons`` list (the string surface
    status.json already renders) and adds the structured contract data
    (``evidence_lines``/``contra``) alongside it; ``subject_fp`` is
    included only when the result carries one.
    """
    evidence: Dict[str, Any] = {
        "kind": result.kind,
        "reasons": [line.detail for line in result.evidence],
    }
    if result.subject_fp is not None:
        evidence["subject_fp"] = result.subject_fp
    if result.evidence:
        evidence["evidence_lines"] = [
            _line_dict(line) for line in result.evidence
        ]
    if result.contra:
        evidence["contra"] = [_line_dict(line) for line in result.contra]
    return {
        "event_type": result.kind,
        "subject": result.subject,
        "window_label": result.window_label,
        "severity": result.severity,
        "session_id": session_id,
        "observed_at": result.observed_at,
        "summary": result.summary,
        "detail": dict(result.detail),
        "entity_type": result.subject_type,
        "evidence": evidence,
    }
