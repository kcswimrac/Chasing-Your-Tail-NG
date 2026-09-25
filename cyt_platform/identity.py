"""
D3: identity hypothesis layer — confidence-rated linking between radio
identities.

Locked decision 3 (build spec): MACs are never silently merged. A claim that
two radio identities are the same device is an ``IdentityHypothesis`` with a
confidence, named evidence reasons, and a status, persisted so detection can
join identities only through stored hypotheses.

``score_link`` is a pure function of two ``DeviceView`` objects and a
``LinkContext``: fixed weights, monotone in evidence, no learned model — same
inputs produce the same hypothesis (deterministic core, locked decision 4).
Reason lines carry counts and ratios only, never raw SSID text: scored inputs
are normalized identity keys and SSID comparison keys, matching the privacy
policy for the v4 observation store (identity keys stored, payload text kept
out).

Severity mapping: ``relink_severity`` maps a hypothesis confidence onto the
severity an ``ie_relink`` incident may carry. Fingerprint-style evidence
(probe SSIDs + IE tags) alone justifies WATCH; ALERT additionally requires
presence corroboration (temporal handoff or spatial continuity), so a cloned
probe set cannot mint an alert by itself.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

# Hypothesis statuses (spec D3): candidate = persisted but not yet actionable;
# linked = may join identities in detection; rejected = vetoed (sticky).
STATUS_CANDIDATE = "candidate"
STATUS_LINKED = "linked"
STATUS_REJECTED = "rejected"

# Candidate floor (spec default 0.30): below this a pair is not even a
# candidate — no hypothesis row exists for it.
CANDIDATE_FLOOR = 0.30
# Link threshold: at or above this a hypothesis may join identities in
# detection. This replaces the old hardcoded 0.7 — the same number must now
# be earned from evidence instead of being assigned unconditionally.
LINK_THRESHOLD = 0.70
# Minimum shared probe SSIDs for LINKED status: a single shared SSID is a
# routine collision between distinct devices (the audit's min_probe_ssids=1
# finding) and must never link on its own.
MIN_SUPPORT_FOR_LINK = 2
# Confidence at which an ie_relink incident maps to severity "alert" (given
# presence corroboration — see relink_severity).
RELINK_ALERT_FLOOR = 0.95

# Fixed, documented weights (locked decision 8 — transparent, no learned
# model). Values are the contribution of a fully-satisfied signal.
SIGNAL_WEIGHTS = {
    # Probe-SSID set overlap: the strongest single signal for randomized-MAC
    # tracking (probe sets are stable across MAC rotation and rarely collide
    # between distinct owners).
    "ssid_jaccard": 0.45,
    # Per-shared-SSID support beyond the first (capped at 5): distinguishes
    # "identical rich probe sets" from "one common SSID collision".
    "ssid_support": 0.06,
    # IE tag / capability fingerprint overlap.
    "ie_similarity": 0.25,
    # Temporal handoff: one identity last seen, the other first seen shortly
    # after (the classic MAC-rotation signature).
    "temporal_continuity": 0.15,
    # Sightings trace the same ground positions.
    "spatial_continuity": 0.10,
    # Similar observation duty cycle.
    "behavioral_cadence": 0.05,
}
# Cap on the support term so an identical 10-SSID clone cannot outscore the
# cap: 0.06 * (5 - 1) = 0.24 max.
SUPPORT_SSID_MAX_SHARED = 5

# Two identities whose presence spans come within this window are treated as
# co-observed (veto). A handoff must be strictly farther apart than this.
CO_OCCURRENCE_WINDOW_S = 30.0
# A handoff gap longer than this is too long to imply succession.
HANDOFF_MAX_S = 300.0
# Two locations within this radius are the "same place" for spatial continuity.
SPATIAL_RADIUS_M = 50.0
_EARTH_RADIUS_M = 6371000.0


@dataclass(frozen=True)
class DeviceView:
    """What the platform knows about one radio identity.

    ``probe_ssids`` are normalized comparison keys (lowercase); they never
    re-enter evidence as text. ``locations`` are (lat, lon) tuples.
    ``first_ts``/``last_ts``/``seen_count`` describe observed presence.
    """

    identity_key: str
    probe_ssids: Tuple[str, ...] = ()
    ie_tags: Tuple[int, ...] = ()
    caps: Tuple[str, ...] = ()
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    seen_count: int = 0
    locations: Tuple[Tuple[float, float], ...] = ()


@dataclass(frozen=True)
class LinkContext:
    """Scoring parameters for one analysis cycle.

    ``now`` stamps the hypothesis (created_ts/updated_ts); passing it
    explicitly keeps scoring deterministic under replay.
    """

    now: Optional[float] = None
    window_s: float = CO_OCCURRENCE_WINDOW_S
    handoff_max_s: float = HANDOFF_MAX_S
    spatial_radius_m: float = SPATIAL_RADIUS_M
    candidate_floor: float = CANDIDATE_FLOOR
    link_threshold: float = LINK_THRESHOLD
    min_support: int = MIN_SUPPORT_FOR_LINK


@dataclass(frozen=True)
class IdentityHypothesis:
    """A confidence-rated claim that two radio identities are one device.

    ``key_a`` < ``key_b`` canonically; ``hypothesis_id`` derives from the
    sorted pair so A→B and B→A are the same hypothesis. MACs are never
    merged — data joins identities only through a stored hypothesis row.
    """

    hypothesis_id: str
    key_a: str
    key_b: str
    confidence: float
    reasons: Tuple[str, ...]
    status: str
    created_ts: float
    updated_ts: float


def hypothesis_id(key_a: str, key_b: str) -> str:
    """Deterministic id for a pair, order-independent (spec D3)."""
    lo, hi = sorted((str(key_a), str(key_b)))
    return hashlib.sha256(f"{lo}|{hi}".encode("utf-8")).hexdigest()[:16]


def _jaccard(a: Tuple[str, ...], b: Tuple[str, ...]) -> float:
    sa, sb = set(a), set(b)
    union = sa | sb
    if not union:
        return 0.0
    return len(sa & sb) / len(union)


def _distance_m(
    p: Tuple[float, float], q: Tuple[float, float]
) -> float:
    """Haversine distance in meters (self-contained: no shared geometry with D5)."""
    lat1, lon1 = p
    lat2, lon2 = q
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    h = (
        math.sin(dphi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2.0) ** 2
    )
    return 2.0 * _EARTH_RADIUS_M * math.asin(math.sqrt(min(1.0, h)))


def _co_observed(a: DeviceView, b: DeviceView, window_s: float) -> bool:
    """True when both identities were present at effectively the same time.

    Presence spans [first_ts, last_ts] overlapping (or coming within
    ``window_s`` of each other) mean two distinct radios were seen live —
    that can never support a same-device claim, so it vetoes the link.
    """
    if a.first_ts is None or b.first_ts is None:
        return False
    gap = max(a.first_ts, b.first_ts) - min(a.last_ts, b.last_ts)
    return gap <= window_s


def _signal_ssid(a: DeviceView, b: DeviceView):
    if not a.probe_ssids or not b.probe_ssids:
        return None
    value = _jaccard(a.probe_ssids, b.probe_ssids)
    shared = len(set(a.probe_ssids) & set(b.probe_ssids))
    return value, f"probe-SSID Jaccard {value:.2f} ({shared} shared)"


def _signal_support(shared: int):
    if shared < 2:
        return None
    value = float(min(SUPPORT_SSID_MAX_SHARED, shared - 1))
    return value, f"support: {shared} shared probe SSIDs"


def _signal_ie(a: DeviceView, b: DeviceView):
    if not a.ie_tags or not b.ie_tags:
        return None
    value = _jaccard(a.ie_tags, b.ie_tags)
    shared = len(set(a.ie_tags) & set(b.ie_tags))
    return value, f"IE tag Jaccard {value:.2f} ({shared} shared tags)"


def _signal_temporal(a: DeviceView, b: DeviceView, ctx: LinkContext):
    if a.first_ts is None or b.first_ts is None:
        return None
    handoffs = 0
    for last, first in ((a.last_ts, b.first_ts), (b.last_ts, a.first_ts)):
        if last is None or first is None:
            continue
        gap = first - last
        if ctx.window_s < gap <= ctx.handoff_max_s:
            handoffs += 1
    if not handoffs:
        return None
    value = min(1.0, handoffs / 2.0)
    return value, f"temporal handoff x{handoffs} (gap within {ctx.handoff_max_s:.0f}s)"


def _signal_spatial(a: DeviceView, b: DeviceView, ctx: LinkContext):
    if not a.locations or not b.locations:
        return None

    def coverage(xs, ys):
        hits = sum(
            1 for p in xs if any(_distance_m(p, q) <= ctx.spatial_radius_m for q in ys)
        )
        return hits / len(xs)

    value = (coverage(a.locations, b.locations) + coverage(b.locations, a.locations)) / 2.0
    # Zero overlap between located sighting sets is recorded as contra-evidence
    # (it lowers confidence), not treated as missing data.
    return value, f"spatial continuity {value:.2f} (within {ctx.spatial_radius_m:.0f}m)"


def _signal_cadence(a: DeviceView, b: DeviceView):
    if a.seen_count < 3 or b.seen_count < 3:
        return None
    if a.first_ts is None or a.last_ts is None or b.first_ts is None or b.last_ts is None:
        return None
    duty_a = (a.last_ts - a.first_ts) / (a.seen_count - 1)
    duty_b = (b.last_ts - b.first_ts) / (b.seen_count - 1)
    if duty_a <= 0 or duty_b <= 0:
        return None
    value = min(duty_a, duty_b) / max(duty_a, duty_b)
    return value, f"duty-cycle ratio {value:.2f}"


def score_link(
    a: DeviceView, b: DeviceView, ctx: Optional[LinkContext] = None
) -> Optional[IdentityHypothesis]:
    """Score a candidate identity link; ``None`` means nothing to record.

    Returns None when the pair cannot even be a candidate: same identity,
    or fused confidence below the candidate floor. Hard rules (locked
    decision 3):
      * co-observed pairs never link (veto, not a weight) — the veto is
        itself a definitive negative, so it returns a REJECTED hypothesis
        for the caller to persist (S15): the contradiction must outlive
        observation retention, or a later rescore mints the link the veto
        existed to prevent,
      * nothing below the candidate floor persists,
      * LINKED requires the confidence threshold AND >= ``min_support``
        shared probe SSIDs — a single shared SSID is a routine collision.
    """
    if ctx is None:
        ctx = LinkContext()
    if a.identity_key == b.identity_key:
        return None
    if _co_observed(a, b, ctx.window_s):
        now = ctx.now if ctx.now is not None else time.time()
        lo, hi = sorted((a.identity_key, b.identity_key))
        return IdentityHypothesis(
            hypothesis_id=hypothesis_id(a.identity_key, b.identity_key),
            key_a=lo,
            key_b=hi,
            confidence=0.0,
            reasons=(
                "co-observation veto: both identities present within "
                f"{ctx.window_s:.0f}s — two distinct radios seen live",
            ),
            status=STATUS_REJECTED,
            created_ts=now,
            updated_ts=now,
        )

    shared = len(set(a.probe_ssids) & set(b.probe_ssids))
    confidence = 0.0
    reasons: list = []
    parts = (
        ("ssid_jaccard", _signal_ssid(a, b)),
        ("ssid_support", _signal_support(shared)),
        ("ie_similarity", _signal_ie(a, b)),
        ("temporal_continuity", _signal_temporal(a, b, ctx)),
        ("spatial_continuity", _signal_spatial(a, b, ctx)),
        ("behavioral_cadence", _signal_cadence(a, b)),
    )
    for name, signal in parts:
        if signal is None:
            continue
        value, reason = signal
        confidence += SIGNAL_WEIGHTS[name] * value
        reasons.append(reason)

    confidence = max(0.0, min(1.0, confidence))
    if confidence < ctx.candidate_floor:
        return None
    if confidence >= ctx.link_threshold and shared >= ctx.min_support:
        status = STATUS_LINKED
    else:
        status = STATUS_CANDIDATE

    now = ctx.now if ctx.now is not None else time.time()
    lo, hi = sorted((a.identity_key, b.identity_key))
    return IdentityHypothesis(
        hypothesis_id=hypothesis_id(a.identity_key, b.identity_key),
        key_a=lo,
        key_b=hi,
        confidence=round(confidence, 6),
        reasons=tuple(reasons),
        status=status,
        created_ts=now,
        updated_ts=now,
    )


def relink_severity(confidence: float, reasons: Sequence[str]) -> str:
    """Map a stored hypothesis score onto ``ie_relink`` incident severity.

    The alert band is reachable — but only when presence corroboration
    (temporal handoff or spatial continuity) backs the fingerprint evidence,
    so probe-set cloning alone cannot mint an alert.
    """
    if confidence < LINK_THRESHOLD:
        return "info"
    presence = any(
        r.startswith(("temporal handoff", "spatial continuity")) for r in reasons
    )
    if confidence >= RELINK_ALERT_FLOOR and presence:
        return "alert"
    return "watch"
