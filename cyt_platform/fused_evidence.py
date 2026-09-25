"""D4: the explainable why/against block — render + attach.

Every alert must carry what supports it and what contradicts it, and
every number in that block must trace to a named evidence line (the
product principle). This module turns a ``FusedAssessment`` into:

* ``fused_evidence`` — the JSON-safe block stored on incident evidence
  (flows verbatim into status.json's explainable top hits and the push
  body, both of which already render ``evidence`` keys); and
* ``render_confidence_block`` — the human-readable text form.

RF-sourced text (detector summaries/evidence details can embed
device-derived strings) is escaped with the repo's canonical
``InputValidator.escape_markdown_text`` before entering the rendered
text form — the same tested helper the KML/markdown render paths use —
so a hostile SSID or tracker name is inert in any downstream sink. The
JSON block stores the raw (already redacted-by-detector) details
unescaped: JSON is not a markup sink.

``attach`` is the single wiring helper for emit paths: it fuses one
result and stores the block on ``incident_fields()`` output. Fusion
failure never blocks a detection emit — it is logged and the incident
ships without the block (fail-open for visibility, never for evidence).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from cyt_platform.confidence import FusedAssessment, fuse
from cyt_platform.detectors import DetectionResult
from input_validation import InputValidator

logger = logging.getLogger(__name__)


def _contribution_dict(contribution) -> Dict[str, Any]:
    line = contribution.line
    return {
        "kind": line.kind,
        "detail": line.detail,
        "weight": line.weight,
        "detector": contribution.detector,
        "obs_ids": list(line.obs_ids),
    }


def fused_evidence(assessment: FusedAssessment) -> Dict[str, Any]:
    """JSON-safe why/against block for one assessment.

    Stored on incident evidence under the ``fusion`` key; the numbers
    (confidence, per-line weights) are exactly the model's outputs, so
    the stored block is a faithful trace of the fused decision.
    """
    return {
        "confidence": assessment.confidence,
        "independent_kinds": list(assessment.independent_kinds),
        "may_alert": assessment.may_alert,
        "detectors": list(assessment.detectors),
        "why": [_contribution_dict(c) for c in assessment.why],
        "against": [_contribution_dict(c) for c in assessment.against],
        "text": render_confidence_block(assessment),
    }


def render_confidence_block(assessment: FusedAssessment) -> str:
    """Human-readable explainable block (spec D4's Confidence/Why/Against).

    Every number cites its evidence kind; RF-sourced details are escaped
    with the canonical markdown/HTML escaping so a hostile SSID or
    tracker name renders as inert literal text in any downstream sink.
    """
    lines: List[str] = [
        f"Confidence: {assessment.confidence:.0%} "
        f"({len(assessment.independent_kinds)} independent kinds, "
        f"{len(assessment.detectors)} detector(s))"
    ]
    if assessment.why:
        lines.append("Why:")
        for c in assessment.why:
            lines.append(
                f"  + {c.line.kind} {c.line.weight:+.2f} — "
                f"{InputValidator.escape_markdown_text(c.line.detail)} "
                f"({c.detector})"
            )
    else:
        lines.append("Why: (no supporting evidence)")
    if assessment.against:
        lines.append("Against:")
        for c in assessment.against:
            lines.append(
                f"  - {c.line.kind} {c.line.weight:+.2f} — "
                f"{InputValidator.escape_markdown_text(c.line.detail)} "
                f"({c.detector})"
            )
    if not assessment.may_alert:
        lines.append(
            "Not alertable: independent evidence below the required kinds "
            "(repetition alone is never sufficient)."
        )
    return "\n".join(lines)


def attach(fields: Dict[str, Any], result: DetectionResult) -> None:
    """Fuse one result and attach the block to ``incident_fields()`` output.

    In-place on the field mapping's ``evidence`` dict, so emit paths stay
    one line: ``fields = incident_fields(...); attach(fields, result)``.
    A fusion failure is logged with traceback and the incident still
    ships (detection visibility outranks explanation richness).
    """
    try:
        assessment: Optional[FusedAssessment] = fuse([result])
    except Exception:
        logger.exception(
            "confidence fusion failed for %s; incident ships without the "
            "explainable block",
            result.summary,
        )
        return
    if assessment is not None:
        fields["evidence"]["fusion"] = fused_evidence(assessment)
