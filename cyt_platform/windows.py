"""D8: rolling time-window persistence — serialize, age, rehydrate.

The window-matching detection state in SecureCYTMonitor (past-5, 5-10,
10-15, 15-20 minute slots for MACs and probe SSIDs) is in-memory only.
A service restart empties it, and refill depends on the capture DB still
holding the pre-restart history — a rolled Kismet log or a restart loses
it, giving a following device a ~20-minute grace period on every boot.
This module makes that state durable: snapshot at rotation and shutdown,
rehydrate on boot with slots aged forward by elapsed time so no subject
outlives its natural 20-minute expiry.

Slots are 300 s wide (matching SecureTimeWindows' 5/10/15/20-minute
boundaries). Slot index k holds subjects seen roughly k*300..(k+1)*300
seconds ago (k=0 is the past-5 slot). Aging shifts every subject forward
by ``elapsed // 300`` slots; anything pushed past the oldest slot is
dropped — rehydration extends no one's window lifetime beyond what the
next rotation would have done anyway.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

WINDOW_RUNTIME_KEY = "window_sets"
WINDOW_SLOT_S = 300
SLOT_COUNT = 4  # past5, 5-10, 10-15, 15-20
# State older than the full window span cannot contain a live subject.
MAX_AGE_S = SLOT_COUNT * WINDOW_SLOT_S + WINDOW_SLOT_S

# slot name -> SecureCYTMonitor attribute (legacy file stays untouched)
_MONITOR_MAC_ATTRS = {
    "past5": "past_five_mins_macs",
    "5-10": "five_ten_min_ago_macs",
    "10-15": "ten_fifteen_min_ago_macs",
    "15-20": "fifteen_twenty_min_ago_macs",
}
_MONITOR_SSID_ATTRS = {
    "past5": "past_five_mins_ssids",
    "5-10": "five_ten_min_ago_ssids",
    "10-15": "ten_fifteen_min_ago_ssids",
    "15-20": "fifteen_twenty_min_ago_ssids",
}

_SLOTS = ("past5", "5-10", "10-15", "15-20")


def collect_window_sets(monitor) -> Dict[str, Dict[str, List[str]]]:
    """Read a monitor's slot sets into a serializable, sorted structure."""
    out: Dict[str, Dict[str, List[str]]] = {}
    for kind, mapping in (("mac", _MONITOR_MAC_ATTRS), ("ssid", _MONITOR_SSID_ATTRS)):
        collected: Dict[str, List[str]] = {}
        for slot, attr in mapping.items():
            values = getattr(monitor, attr, set()) or ()
            collected[slot] = sorted(str(v) for v in values)
        out[kind] = collected
    return out


def save_window_sets(
    store,
    sets: Dict[str, Dict[str, List[str]]],
    saved_ts: Optional[float] = None,
) -> None:
    """Persist window slot sets to the durable store (runtime_state).

    S13: the blob holds raw MACs and probe SSIDs, so it is encrypted with
    the store key when field encryption is on (``get_runtime`` decrypts
    transparently on load).
    """
    payload = {
        "version": 1,
        "saved_ts": float(saved_ts if saved_ts is not None else time.time()),
        "mac": {slot: sorted(sets.get("mac", {}).get(slot, [])) for slot in _SLOTS},
        "ssid": {slot: sorted(sets.get("ssid", {}).get(slot, [])) for slot in _SLOTS},
    }
    store.set_runtime(
        WINDOW_RUNTIME_KEY, json.dumps(payload, sort_keys=True), encrypt=True
    )


def age_window_sets(
    sets: Dict[str, Dict[str, List[str]]],
    *,
    saved_ts: float,
    now: float,
    slot_s: int = WINDOW_SLOT_S,
) -> Dict[str, Dict[str, List[str]]]:
    """Pure: shift every subject forward by the elapsed slot count.

    A subject in slot k (age k*slot_s at save time) moves k slots ahead;
    anything shifted past the oldest slot is expired and dropped.
    """
    if slot_s <= 0:
        slot_s = WINDOW_SLOT_S
    shift = int(max(0.0, float(now) - float(saved_ts)) // slot_s)
    out: Dict[str, Dict[str, List[str]]] = {}
    for kind in ("mac", "ssid"):
        aged: Dict[str, List[str]] = {slot: [] for slot in _SLOTS}
        source = sets.get(kind) or {}
        for idx, slot in enumerate(_SLOTS):
            target = idx + shift
            if target >= SLOT_COUNT:
                continue  # expired
            aged[_SLOTS[target]] = sorted(
                set(aged[_SLOTS[target]]) | set(source.get(slot) or ())
            )
        out[kind] = aged
    return out


def load_window_sets(
    store,
    *,
    now: float,
    max_age_s: float = MAX_AGE_S,
) -> Optional[Dict[str, Dict[str, List[str]]]]:
    """Load persisted window sets, aged forward to ``now``.

    Returns None when nothing is recoverable: no snapshot, corrupt JSON,
    or state older than the window span (only expired subjects possible).
    """
    raw = store.get_runtime(WINDOW_RUNTIME_KEY)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        saved_ts = float(data.get("saved_ts") or 0.0)
    except (json.JSONDecodeError, TypeError, ValueError):
        logger.warning("window snapshot unreadable; starting with empty slots")
        return None
    if saved_ts <= 0 or (now - saved_ts) > max_age_s:
        return None
    combined = {"mac": data.get("mac") or {}, "ssid": data.get("ssid") or {}}
    return age_window_sets(
        combined,
        saved_ts=saved_ts,
        now=now,
    )


def merge_into_monitor(
    monitor,
    rehydrated: Dict[str, Dict[str, List[str]]],
) -> int:
    """Union rehydrated subjects into a monitor's slot sets (no replacement).

    Capture-DB initialization on boot is ground truth for what the current
    capture still knows; rehydration adds only what it lost. Returns the
    number of newly added subjects.
    """
    added = 0
    for kind, mapping in (
        ("mac", _MONITOR_MAC_ATTRS),
        ("ssid", _MONITOR_SSID_ATTRS),
    ):
        for slot, attr in mapping.items():
            subjects = set(rehydrated.get(kind, {}).get(slot) or ())
            if not subjects:
                continue
            existing = set(getattr(monitor, attr, set()) or ())
            new = subjects - existing
            if new:
                setattr(monitor, attr, existing | new)
                added += len(new)
    return added
