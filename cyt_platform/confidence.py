"""D4: confidence fusion — evidence-weighted, explainable, deterministic.

Locked decision 8 (build spec): the confidence model is transparent —
fixed, config-owned weights with documented rationale, no learned model.
Locked decision 1 is enforced here at the fusion level: repeated
observation alone is never sufficient for an alert, so an assessment may
carry alert severity only when its supporting evidence spans at least
``min_independent_kinds`` distinct independent evidence kinds.

The model, in one place:

* every ``EvidenceLine`` gets a signed weight from the config table
  (supporting lines positive, contradicting lines negative) — the weight
  is the contribution of one fully-satisfied line of that kind;
* supporting lines combine by noisy-OR, ``1 - Π(1 - w_i)``: monotone in
  evidence (adding a supporting line never lowers confidence) and
  saturating instead of diverging;
* contradicting lines multiply the support down, ``Π(1 - |c_j|)``: every
  contra line with non-zero weight strictly lowers a non-zero confidence
  and populates the assessment's ``against`` block;
* repetition (more lines of the same kind) still raises confidence but
  never raises the independent-kind count, and self-reference kinds
  (``score`` — the detector's own computed conclusion restated)
  contribute weight without ever counting as independent evidence.

Determinism (locked decision 4): lines fold in a canonical sorted order,
so the float result is identical across runs and CPython versions; the
same inputs always produce the same assessment.

D2 boundary: ``FusedAssessment`` is the interface the incident engine
consumes. ``alert_gate`` is the fusion-level severity decision D2 wires
into incident transitions — the live emit path keeps detector severity
until then, so this PR changes no published state. ``fuse_by_subject``
is the entry point for merging same-subject results across detectors;
``fused_evidence`` attaches the why/against block to incident evidence.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cyt_platform.config import DEFAULTS
from cyt_platform.detectors import DetectionResult, EvidenceLine


@dataclass(frozen=True)
class FusionConfig:
    """The fusion model's config-owned knobs (locked decision 8).

    Built from ``config["fusion"]`` over ``config.DEFAULTS["fusion"]``:
    weights merge per kind so an override touches only the kinds it
    names. Every weight must lie in ``[0, 1]``; validation errors name
    the offending key.
    """

    weights: Dict[str, float]
    self_ref_kinds: Tuple[str, ...]
    min_independent_kinds: int = 2
    max_confidence: float = 0.99
    default_weight: float = 0.10

    @classmethod
    def from_config(cls, config: Optional[Dict[str, Any]]) -> "FusionConfig":
        section: Dict[str, Any] = dict(DEFAULTS.get("fusion") or {})
        raw = (config or {}).get("fusion") or {}
        if not isinstance(raw, dict):
            raise ValueError("config['fusion'] must be a mapping")
        weights = dict(section.get("weights") or {})
        weights.update(raw.get("weights") or {})
        section["weights"] = weights
        # Overlay the remaining fusion keys so partial overrides are honored
        # rather than silently dropped.
        for key in (
            "min_independent_kinds",
            "max_confidence",
            "default_weight",
            "self_ref_kinds",
        ):
            if key in raw:
                section[key] = raw[key]

        parsed_weights = {
            str(kind): _validate_weight(value, f"fusion.weights.{kind}")
            for kind, value in section["weights"].items()
        }
        min_kinds = section.get("min_independent_kinds", 2)
        if not isinstance(min_kinds, int) or isinstance(min_kinds, bool) or min_kinds < 1:
            raise ValueError(
                "fusion.min_independent_kinds must be an integer >= 1, "
                f"got {min_kinds!r}"
            )
        max_conf = _validate_weight(
            section.get("max_confidence", 0.99), "fusion.max_confidence"
        )
        if max_conf <= 0.0:
            raise ValueError(
                f"fusion.max_confidence must be > 0, got {max_conf!r}"
            )
        default_weight = _validate_weight(
            section.get("default_weight", 0.10), "fusion.default_weight"
        )
        self_ref = section.get("self_ref_kinds", [])
        if not isinstance(self_ref, (list, tuple)):
            raise ValueError(
                f"fusion.self_ref_kinds must be a list, got {type(self_ref).__name__}"
            )
        return cls(
            weights=parsed_weights,
            self_ref_kinds=tuple(sorted(str(k) for k in self_ref)),
            min_independent_kinds=min_kinds,
            max_confidence=max_conf,
            default_weight=default_weight,
        )


def _validate_weight(value: Any, key: str) -> float:
    try:
        weight = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a number, got {value!r}") from None
    if not math.isfinite(weight) or not 0.0 <= weight <= 1.0:
        raise ValueError(f"{key} must be within [0, 1], got {weight!r}")
    return weight


@dataclass(frozen=True)
class EvidenceContribution:
    """One evidence line with its fusion-assigned weight and attribution.

    ``line.weight`` is signed: positive for supporting lines, negative
    for contradicting lines. ``detector`` attributes the line to the
    DetectionResult that supplied it (multi-detector fusion renders the
    attribution).
    """

    detector: str
    line: EvidenceLine


@dataclass(frozen=True)
class FusedAssessment:
    """The fusion output for one subject — the interface D2 consumes.

    ``confidence`` is the fused score (0..max_confidence). ``why`` holds
    supporting contributions sorted by weight (strongest first);
    ``against`` holds contradicting contributions sorted by impact.
    ``independent_kinds`` are the distinct independent evidence kinds
    backing the assessment; ``may_alert`` is the product-principle gate —
    False whenever the evidence is repetition-only.
    """

    subject: str
    subject_type: str
    detectors: Tuple[str, ...]
    confidence: float
    why: Tuple[EvidenceContribution, ...]
    against: Tuple[EvidenceContribution, ...]
    independent_kinds: Tuple[str, ...]
    may_alert: bool
    result_count: int


def assign_weights(
    result: DetectionResult, cfg: FusionConfig
) -> Tuple[Tuple[EvidenceContribution, ...], Tuple[EvidenceContribution, ...]]:
    """Fill signed weights for one result's evidence/contra lines (pure).

    Weights come from the config table by kind; kinds missing from the
    table get the conservative ``default_weight`` (and never count as
    independent evidence — see ``_independent``).
    """
    support: List[EvidenceContribution] = []
    for line in result.evidence:
        weight = cfg.weights.get(line.kind, cfg.default_weight)
        support.append(
            EvidenceContribution(
                result.detector,
                EvidenceLine(line.kind, line.detail, line.obs_ids, weight),
            )
        )
    contra: List[EvidenceContribution] = []
    for line in result.contra:
        weight = cfg.weights.get(line.kind, cfg.default_weight)
        contra.append(
            EvidenceContribution(
                result.detector,
                EvidenceLine(line.kind, line.detail, line.obs_ids, -weight),
            )
        )
    return tuple(support), tuple(contra)


def _independent(kind: str, cfg: FusionConfig) -> bool:
    """A kind is independent evidence when the weight table names it and
    it is not a self-reference kind. Unknown kinds stay conservative:
    they contribute weight but cannot justify alerting until the table
    deliberately lists them."""
    return kind in cfg.weights and kind not in cfg.self_ref_kinds


def _combine(
    support: Sequence[EvidenceContribution],
    contra: Sequence[EvidenceContribution],
    cfg: FusionConfig,
) -> Tuple[float, Tuple[EvidenceContribution, ...], Tuple[EvidenceContribution, ...], Tuple[str, ...]]:
    """Fold weighted lines into (confidence, why, against, kinds).

    Canonical fold order (kind, detail) makes the float product identical
    across runs and CPython versions — locked decision 4.
    """
    ordered_support = sorted(
        support, key=lambda c: (c.line.kind, c.line.detail)
    )
    ordered_contra = sorted(contra, key=lambda c: (c.line.kind, c.line.detail))

    support_survival = 1.0
    for contribution in ordered_support:
        support_survival *= 1.0 - contribution.line.weight
    support_value = 1.0 - support_survival

    contra_survival = 1.0
    for contribution in ordered_contra:
        contra_survival *= 1.0 - abs(contribution.line.weight)

    confidence = round(
        max(0.0, min(support_value * contra_survival, cfg.max_confidence)), 6
    )

    kinds = tuple(
        sorted({c.line.kind for c in ordered_support if _independent(c.line.kind, cfg)})
    )
    # Strongest first; ties broken deterministically by kind, then detail.
    why = tuple(
        sorted(
            ordered_support,
            key=lambda c: (-c.line.weight, c.line.kind, c.line.detail),
        )
    )
    # Largest impact first (most negative weight first).
    against = tuple(
        sorted(
            ordered_contra,
            key=lambda c: (c.line.weight, c.line.kind, c.line.detail),
        )
    )
    return confidence, why, against, kinds


def fuse(
    results: Sequence[DetectionResult], *, config: Optional[Dict[str, Any]] = None
) -> Optional[FusedAssessment]:
    """Fuse one subject's DetectionResults into an assessment.

    All results must share a subject (the per-subject grouping entry is
    ``fuse_by_subject``). Pure and deterministic: no store, no wall clock.
    Returns ``None`` for an empty sequence.
    """
    if not results:
        return None
    cfg = FusionConfig.from_config(config)
    ordered = sorted(
        results, key=lambda r: (r.detector, r.kind, r.observed_at, r.summary)
    )
    subjects = {r.subject for r in ordered}
    if len(subjects) > 1:
        raise ValueError(
            "fuse() requires results for one subject; got: "
            + ", ".join(sorted(subjects))
        )

    support: List[EvidenceContribution] = []
    contra: List[EvidenceContribution] = []
    for result in ordered:
        result_support, result_contra = assign_weights(result, cfg)
        support.extend(result_support)
        contra.extend(result_contra)

    confidence, why, against, kinds = _combine(support, contra, cfg)
    return FusedAssessment(
        subject=ordered[0].subject,
        subject_type=ordered[0].subject_type,
        detectors=tuple(sorted({r.detector for r in ordered})),
        confidence=confidence,
        why=why,
        against=against,
        independent_kinds=kinds,
        may_alert=len(kinds) >= cfg.min_independent_kinds,
        result_count=len(ordered),
    )


def fuse_by_subject(
    results: Sequence[DetectionResult], *, config: Optional[Dict[str, Any]] = None
) -> Dict[str, FusedAssessment]:
    """Group results by subject and fuse each group (deterministic order).

    The entry point for same-subject results across detectors — the D2
    incident engine merges groups into incidents through this.
    """
    groups: Dict[str, List[DetectionResult]] = {}
    for result in results:
        groups.setdefault(result.subject, []).append(result)
    return {
        subject: fuse(groups[subject], config=config)
        for subject in sorted(groups)
    }


def alert_gate(assessment: FusedAssessment, base_severity: str) -> str:
    """The fusion-level severity decision (locked decision 1).

    Repetition alone never alerts: an ``alert`` classification survives
    only when the fused evidence spans at least ``min_independent_kinds``
    distinct independent kinds. The gate only demotes — it never upgrades
    a detector's own classification.

    D2 wires this into incident transitions; the live emit path keeps
    detector severity until the incident engine owns state.
    """
    if base_severity == "alert" and not assessment.may_alert:
        return "watch"
    return base_severity
