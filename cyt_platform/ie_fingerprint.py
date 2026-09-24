"""
D3: nested-IE fingerprinting with hypothesis-based identity linking.

Per the build spec (locked decision 3), this module no longer merges entities
or assigns a hardcoded link confidence. Instead it:

  * extracts probe SSIDs and arbitrarily nested IE-tag / capability features
    from Kismet device JSON (the old extraction loop was a ``pass`` placeholder
    that silently dropped nested keys),
  * scores candidate identity pairs through ``cyt_platform.identity.score_link``
    and persists every result as a confidence-rated ``IdentityHypothesis`` with
    named reasons,
  * emits ``ie_relink`` incidents per fingerprint whose MAC set is joined by
    LINKED hypotheses, with severity mapped from the hypothesis score via
    ``identity.relink_severity``.

Evidence reason lines carry counts and ratios only — raw SSID text never
reaches incident evidence (privacy policy for the status/push surfaces).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from cyt_platform.gps_live import extract_gps_from_device_json
from cyt_platform.identity import (
    CO_OCCURRENCE_WINDOW_S,
    CANDIDATE_FLOOR,
    HANDOFF_MAX_S,
    LINK_THRESHOLD,
    MIN_SUPPORT_FOR_LINK,
    STATUS_LINKED,
    DeviceView,
    LinkContext,
    hypothesis_id,
    relink_severity,
    score_link,
)
from cyt_platform.privacy import sanitize_error

logger = logging.getLogger(__name__)

# Nested-walk key matchers -----------------------------------------------------
#
# Kismet nests IE records at varying depths (dot11.device -> dot11.device.ie_*
# -> per-tag dicts), and device JSON differs across Kismet versions, so the
# walker matches on key text instead of a fixed path.
_TAG_KEY_MARKERS = ("ie", "tag")  # key contains both "ie" and "tag"
_CAP_KEY_MARKERS = ("ht_cap", "vht_cap", "he_cap", "extended_cap")
_TAG_KEY_SUFFIXES = (".tag", "tag_number")
# IE tag identifiers are 0..255; out-of-range values are not tag ids.
_TAG_ID_MAX = 255


def _as_tag_id(value: Any) -> Optional[int]:
    """Coerce a JSON scalar to an IE tag id, or None when it is not one."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        n = value
    elif isinstance(value, float):
        n = int(value)
    elif isinstance(value, str):
        try:
            n = int(value.strip(), 10)
        except ValueError:
            return None
    else:
        return None
    return n if 0 <= n <= _TAG_ID_MAX else None


def _numbers_in(obj: Any) -> List[int]:
    """Flatten nested dicts/lists and collect every coercible tag id."""
    out: List[int] = []
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
        else:
            n = _as_tag_id(cur)
            if n is not None:
                out.append(n)
    return out


def _walk_ie_features(obj: Any) -> Tuple[Set[int], Set[str]]:
    """Collect IE tag ids and capability fragments from arbitrarily nested
    Kismet device JSON.

    This replaces the previous ``pass`` placeholder (the audit's
    ie_fingerprint.py:24-27 finding): nested IE keys are now actually walked,
    so fingerprint hashes reflect the full capability tree instead of only the
    top-level keys.
    """
    tags: Set[int] = set()
    caps: Set[str] = set()
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                kl = str(k).lower()
                if any(m in kl for m in _CAP_KEY_MARKERS):
                    if isinstance(v, (dict, list)):
                        caps.add(str(k))
                    else:
                        caps.add(f"{k}={v}")
                if (
                    all(m in kl for m in _TAG_KEY_MARKERS)
                    or kl.endswith(_TAG_KEY_SUFFIXES)
                ):
                    if isinstance(v, (dict, list)):
                        tags.update(_numbers_in(v))
                    else:
                        n = _as_tag_id(v)
                        if n is not None:
                            tags.add(n)
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(x for x in cur if isinstance(x, (dict, list)))
    return tags, caps


def extract_probe_ssids(device_data: dict) -> List[str]:
    """Return the probe SSID records from Kismet device JSON."""
    probes = []

    dot11 = device_data.get("dot11.device") or {}
    probe_map = dot11.get("dot11.device.probed_ssid_map") or {}
    if isinstance(probe_map, dict):
        values = list(probe_map.values())
    elif isinstance(probe_map, list):
        values = probe_map
    else:
        values = []
    for rec in values:
        if not isinstance(rec, dict):
            continue
        ssid = rec.get("dot11.probedssid.ssid")
        if isinstance(ssid, str) and ssid:
            probes.append(ssid)

    last = dot11.get("dot11.device.last_probed_ssid_record") or {}
    if isinstance(last, dict):
        ssid = last.get("dot11.probedssid.ssid")
        if isinstance(ssid, str) and ssid:
            probes.append(ssid)

    return probes


def extract_ie_fingerprint(device_data: dict) -> Optional[Dict[str, Any]]:
    """Return a stable fingerprint over probe SSIDs + nested IE features."""
    if not isinstance(device_data, dict):
        return None

    ssids = extract_probe_ssids(device_data)
    tags, caps = _walk_ie_features(device_data.get("dot11.device") or device_data)
    if not ssids and not tags and not caps:
        return None

    features = {
        "probe_ssids": sorted(set(ssids)),
        "ie_tags": sorted(tags)[:64],
        "caps": sorted(caps)[:40],
    }
    payload = json.dumps(features, sort_keys=True)
    return {
        "hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "features": features,
        "raw": payload,
    }


def device_view(identity_key: str, device_data: dict) -> DeviceView:
    """Build a DeviceView from one Kismet device JSON record.

    Probe SSIDs are normalized to lowercase comparison keys; they never
    re-enter evidence as text. A location is taken from the device's own GPS
    tag when present.
    """
    ssids = extract_probe_ssids(device_data)
    tags, caps = _walk_ie_features(device_data.get("dot11.device") or device_data)

    first = _as_epoch(device_data.get("kismet.device.base.first_time"))
    last = _as_epoch(device_data.get("kismet.device.base.last_time"))
    if first is None and last is not None:
        first = last
    if last is None and first is not None:
        last = first

    locations: Tuple[Tuple[float, float], ...] = ()
    try:
        loc = extract_gps_from_device_json(dict(device_data))
        if loc is not None:
            locations = ((loc[0], loc[1]),)
    except Exception as exc:  # location context is best-effort, never fatal
        logger.debug("identity view location extraction failed: %s", sanitize_error(exc))

    return DeviceView(
        identity_key=identity_key,
        probe_ssids=tuple(sorted({s.lower() for s in ssids})),
        ie_tags=tuple(sorted(tags)),
        caps=tuple(sorted(caps)),
        first_ts=first,
        last_ts=last,
        seen_count=1 if (first is not None or ssids or tags) else 0,
        locations=locations,
    )


def _as_epoch(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    return ts if ts > 0 else None


class IEFingerprintEngine:
    """Links randomized MACs through stored identity hypotheses (D3).

    Per cycle: extract fingerprints (probe SSIDs + nested IE/capability
    features), register entity/fingerprint rows, then score candidate pairs —
    within-cycle probe-SSID-sharing pairs plus every pair sharing a persisted
    fingerprint — through ``identity.score_link``. Scores persist as
    hypotheses; only LINKED hypotheses may join identities, and ``ie_relink``
    incidents carry severity mapped from the hypothesis score. Nothing merges
    silently; nothing links below the candidate floor.
    """

    def __init__(self, store: Any, config: dict):
        self.store = store
        self.cfg = config.get("ie_fingerprint") or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.min_ssids = int(self.cfg.get("min_probe_ssids") or 1)

    def _context(self, now: float) -> LinkContext:
        cfg = self.cfg or {}
        return LinkContext(
            now=now,
            window_s=float(cfg.get("co_window_s", CO_OCCURRENCE_WINDOW_S)),
            handoff_max_s=float(cfg.get("handoff_max_s", HANDOFF_MAX_S)),
            candidate_floor=float(cfg.get("candidate_floor", CANDIDATE_FLOOR)),
            link_threshold=float(cfg.get("link_threshold", LINK_THRESHOLD)),
            min_support=int(cfg.get("min_support", MIN_SUPPORT_FOR_LINK)),
        )

    def process_devices(self, devices: List[dict], now: Optional[float] = None) -> int:
        """Extract, score, and persist identity hypotheses for one cycle.

        Returns the number of newly linked entity↔fingerprint rows (first
        sightings), matching the previous contract of this method.
        """
        if not self.enabled:
            return 0
        now = time.time() if now is None else float(now)
        session_id = self.store.get_runtime("session_id") or "ie"
        links = 0

        current: Dict[str, dict] = {}
        for d in devices or []:
            mac = (d.get("mac") or "").upper()
            dd = d.get("device_data") or {}
            if not mac or mac in current:
                continue
            fp = extract_ie_fingerprint(dd)
            if fp is None:
                continue
            feats = fp["features"]
            if len(feats.get("probe_ssids") or []) < self.min_ssids and len(feats.get("ie_tags") or []) < 3:
                continue
            fid = self.store.upsert_fingerprint("ie_probe", fp["hash"], feats, now)
            eid = self.store.upsert_entity("wifi_mac", mac, now)
            if self.store.link_entity_fingerprint(eid, fid, confidence=0.5):
                links += 1
            current[mac] = {"view": device_view(mac, dd), "eid": eid, "fid": fid, "hash": fp["hash"]}

        if current:
            self._score_pairs(current, now)
            self._emit_relink_incidents(current, session_id, now)
        return links

    # -- scoring ----------------------------------------------------------------

    def _score_pairs(self, current: Dict[str, dict], now: float) -> None:
        ctx = self._context(now)
        history: Dict[str, DeviceView] = {}

        def view_for(mac: str) -> DeviceView:
            if mac in current:
                base = current[mac]["view"]
            else:
                # prior-cycle identity: fingerprint features come from the
                # store (observations deliberately carry no SSID/IE text)
                base = self._persisted_view(mac)
            if mac not in history:
                history[mac] = self._with_history(base, mac)
            return history[mac]

        # Candidate pairs: within-cycle probe-SSID sharing, plus every pair
        # sharing a persisted fingerprint (cross-cycle pairing). Bounded by
        # SSID-group sizes; a busy channel yields mostly singletons.
        pairs: Set[Tuple[str, str]] = set()
        by_ssid: Dict[str, List[str]] = {}
        for mac, info in current.items():
            for s in info["view"].probe_ssids:
                by_ssid.setdefault(s, []).append(mac)
        for group in by_ssid.values():
            if len(group) > 1:
                pairs.update(itertools.combinations(sorted(set(group)), 2))
        for mac, info in current.items():
            try:
                prior = self.store.macs_for_fingerprint(info["fid"])
            except Exception as exc:
                logger.warning(
                    "identity candidate lookup failed: %s", sanitize_error(exc)
                )
                continue
            for other in prior:
                if other != mac:
                    pairs.add(tuple(sorted((mac, other))))

        linked: Dict[Tuple[str, str], dict] = {}
        for pair in sorted(pairs):
            ma, mb = pair
            hyp = score_link(view_for(ma), view_for(mb), ctx)
            if hyp is None:
                continue
            try:
                stored = self.store.upsert_identity_hypothesis(
                    key_a=hyp.key_a,
                    key_b=hyp.key_b,
                    confidence=hyp.confidence,
                    status=hyp.status,
                    reasons=list(hyp.reasons),
                    ts=ctx.now,
                )
            except Exception as exc:
                logger.warning(
                    "identity hypothesis persist failed for %s/%s: %s",
                    ma,
                    mb,
                    sanitize_error(exc),
                )
                continue
            if stored["status"] == STATUS_LINKED:
                linked[pair] = stored
                # The entity-fingerprint row is bookkeeping; keep its
                # confidence at the earned hypothesis level (monotone up).
                for m in pair:
                    info = current.get(m)
                    if info:
                        try:
                            self.store.link_entity_fingerprint(
                                info["eid"], info["fid"], confidence=stored["confidence"]
                            )
                        except Exception as exc:
                            logger.warning(
                                "identity link confidence update failed: %s",
                                sanitize_error(exc),
                            )

    def _persisted_view(self, mac: str) -> DeviceView:
        """View for a prior-cycle identity, from its persisted fingerprint features.

        Observations carry no SSID/IE text (privacy policy), so the features a
        prior MAC presented are read from the fingerprints table through the
        additive store query. This is what makes cross-cycle candidate pairing
        scoreable at all: a MAC seen only in earlier cycles still contributes
        its probe-SSID/IE evidence to the pair.
        """
        ssids: Set[str] = set()
        tags: Set[int] = set()
        caps: Set[str] = set()
        try:
            rows = self.store.features_for_identity("wifi_mac", mac)
        except Exception as exc:
            logger.warning(
                "identity features lookup failed for %s: %s", mac, sanitize_error(exc)
            )
            rows = []
        for row in rows:
            if row.get("fingerprint_type") != "ie_probe":
                continue
            feats = row.get("features") or {}
            ssids.update(feats.get("probe_ssids") or [])
            tags.update(feats.get("ie_tags") or [])
            caps.update(feats.get("caps") or [])
        return DeviceView(
            identity_key=mac,
            probe_ssids=tuple(sorted({s.lower() for s in ssids})),
            ie_tags=tuple(sorted(tags)),
            caps=tuple(sorted(caps)),
        )

    def _with_history(self, view: DeviceView, mac: str) -> DeviceView:
        """Merge observation-store history into a view (presence + locations).

        Observation payloads deliberately carry no SSID/IE text (privacy
        policy), so history contributes presence spans and locations only;
        fingerprint features come from the live device JSON.
        """
        try:
            rows = self.store.query_observations(identity_key=mac, limit=200)
        except Exception as exc:
            logger.warning(
                "identity history read failed for %s: %s", mac, sanitize_error(exc)
            )
            return view
        rows = [r for r in rows if r.get("source") == "kismet.devices"]
        if not rows:
            return view
        stamps = [r["ts"] for r in rows]
        firsts = stamps + ([view.first_ts] if view.first_ts is not None else [])
        lasts = stamps + ([view.last_ts] if view.last_ts is not None else [])
        locs = set(view.locations)
        for r in rows:
            if r.get("lat") is not None and r.get("lon") is not None:
                locs.add((round(r["lat"], 6), round(r["lon"], 6)))
        return DeviceView(
            identity_key=view.identity_key,
            probe_ssids=view.probe_ssids,
            ie_tags=view.ie_tags,
            caps=view.caps,
            first_ts=min(firsts),
            last_ts=max(lasts),
            seen_count=max(view.seen_count, len(rows)),
            locations=tuple(sorted(locs)),
        )

    # -- incident emission --------------------------------------------------------

    def _emit_relink_incidents(self, current: Dict[str, dict], session_id: str, now: float) -> None:
        """One ie_relink incident per fingerprint joined by LINKED hypotheses.

        Severity maps from the strongest supporting hypothesis score via
        ``identity.relink_severity``; evidence carries hypothesis ids and
        counts — never MAC or SSID text.
        """
        reported: Set[int] = set()
        for mac, info in current.items():
            if info["fid"] in reported:
                continue
            reported.add(info["fid"])
            try:
                macs = sorted(set(self.store.macs_for_fingerprint(info["fid"])) | {mac})
            except Exception as exc:
                logger.warning("identity roster lookup failed: %s", sanitize_error(exc))
                continue
            if len(macs) < 2:
                continue
            pair_scores = self._linked_scores_for(macs)
            if not pair_scores:
                continue
            best = max(pair_scores, key=lambda h: h["confidence"])
            confidence = float(best["confidence"])
            severity = relink_severity(confidence, best["reasons"])
            try:
                self.store.observe_incident(
                    event_type="ie_relink",
                    subject=info["hash"],
                    window_label="identity",
                    severity=severity,
                    session_id=session_id,
                    observed_at=now,
                    summary=(
                        f"Identity hypotheses joined {len(macs)} MACs "
                        f"(confidence {confidence:.2f}, {severity})"
                    ),
                    detail={
                        "mac_count": len(macs),
                        "confidence": round(confidence, 4),
                        "hypothesis_count": len(pair_scores),
                    },
                    entity_type="fingerprint",
                    evidence={
                        "kind": "ie_relink",
                        "subject_fp": info["hash"][:16],
                        "reasons": list(best["reasons"][:4])
                        + [
                            f"stored hypotheses: {len(pair_scores)} linked pair(s)",
                            f"severity {severity} mapped from confidence {confidence:.2f}",
                        ],
                        "hypothesis_ids": [h["hypothesis_id"] for h in pair_scores[:5]],
                    },
                )
            except Exception as exc:
                logger.warning("ie_relink incident persist failed: %s", sanitize_error(exc))

    def _linked_scores_for(self, macs: List[str]) -> List[dict]:
        """Stored LINKED hypotheses joining any two of ``macs``."""
        scores: List[dict] = []
        for a, b in itertools.combinations(macs, 2):
            try:
                hyp = self.store.get_identity_hypothesis(hypothesis_id(a, b))
            except Exception as exc:
                logger.warning("identity hypothesis lookup failed: %s", sanitize_error(exc))
                continue
            if hyp and hyp["status"] == STATUS_LINKED:
                scores.append(hyp)
        return scores
