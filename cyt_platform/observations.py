"""Canonical observation normalizer (D1).

Converts raw source rows — Kismet device JSON, Kismet alert rows, GPS
fixes, BLE advertisements — into provenance-bearing observation records
and persists them through the CytStore observation API.

Every observation answers WHAT was seen (kind + identity), WHEN (the
source-corrected timestamp, not the wall clock), WHERE (optional lat/lon),
and PROVENANCE (source, source_ref into the capture, cycle_id, digest of
the raw input). Raw rows are never mutated; malformed rows are skipped
with a warning rather than aborting the cycle.

Raw SSID text is deliberately kept out of observation payloads (privacy
policy: renderers redact/escape at the surface layer), but alert text is
retained: the alert body is the evidence a later replay must reproduce.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
from typing import Any, List, Mapping, Optional, Sequence

from cyt_platform.gps_live import extract_gps_from_device_json

logger = logging.getLogger(__name__)

# Sources (stored in observations.source)
SOURCE_KISMET_DEVICES = "kismet.devices"
SOURCE_KISMET_ALERTS = "kismet.alerts"
SOURCE_GPS = "gps"
SOURCE_BLE = "ble"
SOURCE_DETECTOR = "detector"

# Kinds (stored in observations.kind)
KIND_WIFI_DEVICE = "wifi_device"
KIND_PROBE = "probe"
KIND_BLE_ADV = "ble_adv"
KIND_DEAUTH_ALERT = "deauth_alert"
KIND_KISMET_ALERT = "kismet_alert"
KIND_GPS_FIX = "gps_fix"
KIND_AP_BEACON = "ap_beacon"

# Alert headers that classify an alert observation as a deauth-class event
# (same keyword family the deauth detector scans for).
_DEAUTH_ALERT_KEYWORDS = (
    "deauth",
    "disassoc",
    "deauthentication",
    "disassociation",
    "deauthflood",
)

# identity_key used for observations of the operator's own receiver: a GPS
# fix has no radio identity, but the evidence substrate needs a stable key.
OPERATOR_IDENTITY = "operator"


def normalize_mac(raw: Any) -> Optional[str]:
    """Normalize a Kismet MAC/BSSID string.

    Kismet sometimes writes ``AA:BB:CC:DD:EE:FF/01`` (mask suffix) and uses
    varying case; identity keys are upper-case with the mask stripped.
    Returns None for anything that is not a usable identity string.
    """
    if not isinstance(raw, str):
        return None
    mac = raw.strip().split("/")[0].strip().upper()
    return mac or None


def input_digest(raw: Any) -> str:
    """Stable sha256 digest of a raw input row (canonical JSON).

    Same raw row -> same digest, so a replayed or re-read row can be
    matched byte-for-byte against the observation that captured it.
    """
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def db_ref(db_path: Any) -> str:
    """Short stable reference for a capture database path (source_ref prefix)."""
    return hashlib.sha1(str(db_path or "").encode("utf-8")).hexdigest()[:12]


def _first(mapping: Mapping, *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value is not None and value != "":
            return value
    return None


def _as_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _device_payload(device_data: Mapping, row: Mapping) -> dict:
    """Whitelisted device fields only — no raw SSID text."""
    signal = device_data.get("kismet.device.base.signal") or {}
    if not isinstance(signal, Mapping):
        signal = {}
    dot11 = device_data.get("dot11.device") or {}
    probed = dot11.get("dot11.device.probed_ssid_map") if isinstance(dot11, Mapping) else None
    payload: dict = {}
    rssi = _as_float(
        _first(
            signal,
            "kismet.common.signal.last_signal",
        )
    )
    if rssi is not None:
        payload["rssi"] = rssi
    channel = _first(device_data, "kismet.device.base.channel")
    if channel is not None:
        payload["channel"] = str(channel)
    freq = _as_float(_first(device_data, "kismet.device.base.frequency"))
    if freq is not None:
        payload["frequency"] = freq
    device_type = _first(row, "type") or _first(device_data, "kismet.device.base.type")
    if device_type is not None:
        payload["device_type"] = str(device_type)
    if isinstance(probed, Mapping):
        payload["ssid_count"] = len(probed)
    return payload


def normalize_device_row(
    row: Any,
    *,
    cycle_id: int,
    db_ref: str,
    session_id: Optional[str] = None,
) -> Optional[dict]:
    """Normalize one Kismet ``devices`` table row into observation kwargs.

    Accepts the row shape detectors already read:
    ``{devmac, type, last_time, device}`` where ``device`` is the Kismet
    device JSON (string or pre-parsed dict). Returns None for malformed
    rows (missing identity or timestamp) — never raises.
    """
    if not isinstance(row, Mapping):
        return None
    device_data: Any = _first(row, "device_data", "device")
    if isinstance(device_data, str):
        try:
            device_data = json.loads(device_data)
        except (ValueError, TypeError):
            device_data = {}
    if not isinstance(device_data, Mapping):
        device_data = {}

    identity = normalize_mac(
        _first(row, "devmac", "macaddr")
        or device_data.get("kismet.device.base.macaddr")
    )
    ts = _as_float(_first(row, "last_time") or device_data.get("kismet.device.base.last_time"))
    if identity is None or ts is None:
        return None

    devid = (
        _first(device_data, "kismet.device.base.key")
        or _first(row, "device_id", "devid")
        or identity
    )
    location: Optional[tuple] = None
    try:
        location = extract_gps_from_device_json(dict(device_data))
    except Exception:  # noqa: BLE001 — malformed location must not abort ingest
        location = None

    record: dict = {
        "ts": ts,
        "source": SOURCE_KISMET_DEVICES,
        "kind": KIND_WIFI_DEVICE,
        "identity_key": identity,
        "cycle_id": cycle_id,
        "source_ref": f"kismet:{db_ref}:devices:devid={devid}",
        "input_digest": input_digest(dict(row)),
        "payload": _device_payload(device_data, row),
        "session_id": session_id,
    }
    if location is not None:
        lat, lon, _ = location
        record["lat"] = lat
        record["lon"] = lon
    return record


def normalize_alert_row(
    row: Any,
    *,
    cycle_id: int,
    db_ref: str,
    session_id: Optional[str] = None,
) -> Optional[dict]:
    """Normalize one Kismet ``alerts`` table row into observation kwargs.

    Row shape from the capture DB: ``{ts_sec, header, json, src_mac, dst_mac,
    bssid, rowid}`` — ``json`` is the Kismet alert JSON (string or dict);
    ``src_mac``/``dst_mac``/``bssid``/``rowid`` are optional. Returns None
    when no radio identity can be resolved from the row.
    """
    if not isinstance(row, Mapping):
        return None
    ts = _as_float(_first(row, "ts_sec", "ts"))
    if ts is None:
        return None

    alert_json: Any = row.get("json")
    if isinstance(alert_json, str):
        try:
            alert_json = json.loads(alert_json)
        except (ValueError, TypeError):
            alert_json = {}
    if not isinstance(alert_json, Mapping):
        alert_json = {}

    identity = normalize_mac(
        _first(row, "src_mac", "devmac", "bssid", "dst_mac")
        or _first(
            alert_json,
            "kismet.alert.src_mac",
            "kismet.alert.tx_mac",
            "kismet.alert.bssid",
            "src_mac",
            "bssid",
        )
    )
    if identity is None:
        return None

    header = str(_first(row, "header") or alert_json.get("kismet.alert.header") or "")
    alert_text = str(alert_json.get("kismet.alert.text") or header or "")
    header_l = header.lower()
    text_l = alert_text.lower()
    is_deauth = any(
        kw in header_l or kw in text_l for kw in _DEAUTH_ALERT_KEYWORDS
    )
    kind = KIND_DEAUTH_ALERT if is_deauth else KIND_KISMET_ALERT

    rowid = row.get("rowid")
    if rowid is not None:
        locator = f"rowid={rowid}"
    else:
        locator = f"digest={input_digest(dict(row))[:12]}"

    return {
        "ts": ts,
        "source": SOURCE_KISMET_ALERTS,
        "kind": kind,
        "identity_key": identity,
        "cycle_id": cycle_id,
        "source_ref": f"kismet:{db_ref}:alerts:{locator}",
        "input_digest": input_digest(dict(row)),
        "payload": {
            "header": header,
            "text": alert_text,
        },
        "session_id": session_id,
    }


def normalize_gps_fix(
    *,
    lat: Any,
    lon: Any,
    ts: Any,
    cycle_id: int,
    accuracy_m: Any = None,
    session_id: Optional[str] = None,
) -> Optional[dict]:
    """Normalize one operator GPS fix into observation kwargs.

    GPS fixes carry no radio identity; the stable key OPERATOR_IDENTITY
    marks them. Returns None for out-of-range or non-numeric fixes.
    """
    lat_f = _as_float(lat)
    lon_f = _as_float(lon)
    ts_f = _as_float(ts)
    if lat_f is None or lon_f is None or ts_f is None:
        return None
    if not (-90.0 <= lat_f <= 90.0) or not (-180.0 <= lon_f <= 180.0):
        return None
    acc = _as_float(accuracy_m)
    raw = {"lat": lat_f, "lon": lon_f, "ts": ts_f}
    return {
        "ts": ts_f,
        "source": SOURCE_GPS,
        "kind": KIND_GPS_FIX,
        "identity_key": OPERATOR_IDENTITY,
        "cycle_id": cycle_id,
        "source_ref": f"gps:fix:{ts_f}",
        "input_digest": input_digest(raw),
        "payload": {},
        "lat": lat_f,
        "lon": lon_f,
        "accuracy_m": acc,
        "session_id": session_id,
    }


def normalize_ble_advertisement(
    *,
    mac: Any,
    ts: Any,
    cycle_id: int,
    db_ref: Optional[str] = None,
    name: Any = None,
    rssi: Any = None,
    company_id: Any = None,
    session_id: Optional[str] = None,
) -> Optional[dict]:
    """Normalize one BLE advertisement into observation kwargs."""
    identity = normalize_mac(mac)
    ts_f = _as_float(ts)
    if identity is None or ts_f is None:
        return None
    prefix = f"ble:{db_ref}:" if db_ref else "ble:"
    payload: dict = {}
    if name is not None and str(name) != "":
        payload["name"] = str(name)
    rssi_f = _as_float(rssi)
    if rssi_f is not None:
        payload["rssi"] = rssi_f
    if company_id is not None and str(company_id) != "":
        payload["company_id"] = str(company_id)
    return {
        "ts": ts_f,
        "source": SOURCE_BLE,
        "kind": KIND_BLE_ADV,
        "identity_key": identity,
        "cycle_id": cycle_id,
        "source_ref": f"{prefix}adv:mac={identity}",
        "input_digest": input_digest(
            {"mac": identity, "ts": ts_f, "name": str(name or ""), "rssi": rssi_f}
        ),
        "payload": payload,
        "session_id": session_id,
    }


def _ingest_rows(
    store: Any,
    records: Sequence[Optional[dict]],
    origin: str,
) -> List[int]:
    ids: List[int] = []
    for record in records:
        if record is None:
            continue
        try:
            ids.append(store.record_observation(**record))
        except (TypeError, ValueError) as exc:
            logger.warning("%s: skipping unrecordable row: %s", origin, exc)
    return ids


def ingest_kismet_cycle(
    store: Any,
    ro_conn: Any,
    *,
    cycle_id: int,
    db_path: str,
    session_id: Optional[str] = None,
    since_ts: float = 0.0,
    gps_fix: Optional[Mapping] = None,
) -> List[int]:
    """Normalize and persist one analysis cycle from a Kismet capture DB.

    ``ro_conn`` must be a read-only connection (kismet_ro.connect_readonly)
    over a Kismet database. Reads the ``devices`` and ``alerts`` tables from
    ``since_ts`` forward, normalizes each row (malformed rows are skipped
    with a warning), and records everything in one store transaction. An
    optional ``gps_fix`` mapping (``lat``, ``lon``, ``ts``, ``accuracy_m``)
    records the operator fix for the same cycle.

    Returns the persisted observation ids.
    """
    ref = db_ref(db_path)
    records: List[Optional[dict]] = []

    try:
        device_rows = ro_conn.execute(
            """
            SELECT devmac, type, device, last_time FROM devices
            WHERE last_time >= ?
            ORDER BY last_time
            """,
            (since_ts,),
        ).fetchall()
        for row in device_rows:
            records.append(
                normalize_device_row(
                    {
                        "devmac": row["devmac"],
                        "type": row["type"],
                        "device_data": row["device"],
                        "last_time": row["last_time"],
                    },
                    cycle_id=cycle_id,
                    db_ref=ref,
                    session_id=session_id,
                )
            )
    except Exception as exc:  # sqlite3.Error and missing-table variants
        logger.warning("observation ingest: device scan failed: %s", exc)

    try:
        alert_rows = ro_conn.execute(
            """
            SELECT ts_sec, header, json, src_mac, dst_mac, bssid, rowid
            FROM alerts WHERE ts_sec >= ? ORDER BY ts_sec
            """,
            (since_ts,),
        ).fetchall()
        for row in alert_rows:
            records.append(
                normalize_alert_row(
                    {
                        "ts_sec": row["ts_sec"],
                        "header": row["header"],
                        "json": row["json"],
                        "src_mac": row["src_mac"],
                        "dst_mac": row["dst_mac"],
                        "bssid": row["bssid"],
                        "rowid": row["rowid"],
                    },
                    cycle_id=cycle_id,
                    db_ref=ref,
                    session_id=session_id,
                )
            )
    except Exception as exc:  # sqlite3.Error and missing-table variants
        logger.warning("observation ingest: alert scan failed: %s", exc)

    if gps_fix is not None:
        records.append(
            normalize_gps_fix(
                lat=gps_fix.get("lat"),
                lon=gps_fix.get("lon"),
                ts=gps_fix.get("ts"),
                cycle_id=cycle_id,
                accuracy_m=gps_fix.get("accuracy_m"),
                session_id=session_id,
            )
        )

    with store.transaction():
        return _ingest_rows(store, records, f"cycle={cycle_id}")
