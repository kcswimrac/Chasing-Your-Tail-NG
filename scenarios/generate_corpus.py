#!/usr/bin/env python3
"""Corpus generator for the D7b eval scenarios (scenarios/replay/*.json).

Regenerate the 25 generated scenarios from the repo root:

    python3 scenarios/generate_corpus.py [output-dir]   # default: scenarios/replay

Byte-identical regeneration is itself a property: any generator change that
shifts scenario content shifts a committed fixture and shows up as a diff.
The seven hand-authored fixtures from the replay-engine PRs (cafe-evil-twin,
commute-deauth-burst, commute-quiet, cotravel-deauth-merge, detector_failure,
walk-ble-tracker, walk-cotravel) are intentionally NOT generated — they are
original artifacts of PRs #7/#10 and are edited by hand.

Row shapes mirror the merged scenarios' conventions:
- kismet.devices rows: devmac/type/last_time/device dict
- kismet.alerts rows:  ts_sec/header/json/src_mac/dst_mac/bssid
- gps fixes:           {fix: {lat, lon, ts, accuracy_m}}
- Device pull window is [clock-120, clock] -> every visible device row uses
  last_time within that window of its cycle's clock_ts.
- Co-travel places: P1/P2/P3 are ~1.5 km apart (feasible at 27 m/s for 55-60s
  hops; feasibility drops transitions faster than 35 m/s).
- Geopoint order is [lon, lat] (Kismet convention).
"""
import json
import pathlib
import sys

OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "scenarios/replay")

P1 = (33.400, -112.000)
P2 = (33.410, -112.010)  # ~1.45 km from P1
P3 = (33.420, -112.020)  # ~1.45 km from P2
P2C = (33.4009, -112.0009)  # ~130 m from P1 (distinct cluster, walk-speed hop)
HOSTILE = "<script>alert(1)</script>"

T0 = 1700000000.0


def dev(mac, typ, ts, device=None):
    row = {"devmac": mac, "type": typ, "last_time": round(ts, 1)}
    if device is not None:
        row["device"] = device
    return {"source": "kismet.devices", "row": row}


def ap(mac, ssid, crypt, ch, ts):
    return dev(
        mac,
        "Wi-Fi AP",
        ts,
        {
            "dot11.device": {
                "dot11.device.advertised_ssid_map": [
                    {
                        "dot11.advertisedssid.ssid": ssid,
                        "dot11.advertisedssid.crypt_string": crypt,
                    }
                ]
            },
            "kismet.device.base.channel": str(ch),
        },
    )


def client(mac, ts, sig=-60, ch=6):
    return dev(
        mac,
        "Wi-Fi Client",
        ts,
        {
            "kismet.device.base.signal": {
                "kismet.common.signal.last_signal": sig
            },
            "kismet.device.base.channel": str(ch),
        },
    )


def located(mac, ts, place, typ="Wi-Fi Client"):
    lat, lon = place
    return dev(
        mac,
        typ,
        ts,
        {
            "kismet.device.base.type": typ,
            "kismet.device.base.location": {
                "kismet.common.location.geopoint": [lon, lat],
                "kismet.common.location.time_sec": round(ts, 1),
            },
        },
    )


def btle(mac, name, ts):
    return dev(
        mac,
        "BTLE Device",
        ts,
        {
            "kismet.device.base.type": "BTLE Device",
            "kismet.device.base.commonname": name,
        },
    )


def alert(ts, src, dst, header="DEAUTH"):
    return {
        "source": "kismet.alerts",
        "row": {
            "ts_sec": round(ts, 1),
            "header": header,
            "json": {
                "kismet.alert.header": header,
                "kismet.alert.text": "Detected deauthentication attack",
                "kismet.alert.source_mac": src,
                "kismet.alert.dest_mac": dst,
                "kismet.alert.channel": 6,
            },
            "src_mac": src,
            "dst_mac": dst,
            "bssid": "",
        },
    }


def gps(place, ts, acc=8.0):
    lat, lon = place
    return {
        "source": "gps",
        "fix": {"lat": lat, "lon": lon, "ts": round(ts, 1), "accuracy_m": acc},
    }


def cycle(cid, ts, rows):
    return {"cycle_id": cid, "clock_ts": round(ts, 1), "rows": rows}


def scenario(sid, desc, kind, expect, cycles, overrides=None, restarts=None,
             close_after=None, session=None):
    doc = {
        "scenario_version": 1,
        "scenario_id": sid,
        "description": desc,
        "session_id": session or f"replay-{sid}",
        "labels": {"kind": kind, "expect": expect},
    }
    if overrides:
        doc["config_overrides"] = overrides
    if restarts:
        doc["restarts"] = restarts
    if close_after is not None:
        doc["close_after_seconds"] = close_after
    doc["cycles"] = cycles
    return doc


scenarios = []

# ---------------------------------------------------------------- normal ----

# 1. apartment-evening: neighbor APs and ordinary clients, defaults only.
c = [
    cycle(1, T0, [ap("BB:BB:CC:01:00:01", "UnitB-WiFi", "WPA2-PSK", 11, T0 - 5),
                  client("AA:BB:CC:DD:EE:01", T0 - 8),
                  client("AA:BB:CC:DD:EE:02", T0 - 12)]),
    cycle(2, T0 + 30, [ap("BB:BB:CC:01:00:02", "CasaDeAna", "WPA2-PSK", 1, T0 + 25),
                       client("AA:BB:CC:DD:EE:01", T0 + 22)]),
    cycle(3, T0 + 60, [ap("BB:BB:CC:01:00:01", "UnitB-WiFi", "WPA2-PSK", 11, T0 + 55),
                       client("AA:BB:CC:DD:EE:03", T0 + 52)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "apartment-evening",
    "Evening at home: neighbor networks and ordinary client traffic, nothing hostile. "
    "Random neighbors' APs must never alert on their own (rogue fires on monitored SSIDs only).",
    "normal", {"detect": False, "state": "clear"}, c))

# 2. office-dense-afternoon: dense office, GPS on, no device co-travels.
# The operator's phone (EE:01) is the located device feeding GPS health;
# everyone else is unlocated, so density alone can never co-travel.
c = [
    cycle(1, T0, [located("AA:BB:CC:DD:EE:01", T0 - 5, P1),
                  client("AA:BB:CC:DD:EE:02", T0 - 8),
                  ap("BB:BB:CC:02:00:01", "CorpHQ", "WPA2-ENT", 6, T0 - 3)]),
    cycle(2, T0 + 30, [located("AA:BB:CC:DD:EE:01", T0 + 25, P1),
                       client("AA:BB:CC:DD:EE:03", T0 + 22),
                       ap("BB:BB:CC:02:00:02", "CorpHQ-Guest", "WPA2-PSK", 11, T0 + 27)]),
    cycle(3, T0 + 60, [located("AA:BB:CC:DD:EE:01", T0 + 55, P2),
                       client("AA:BB:CC:DD:EE:02", T0 + 52),
                       client("AA:BB:CC:DD:EE:04", T0 + 52),
                       ap("BB:BB:CC:02:00:01", "CorpHQ", "WPA2-ENT", 6, T0 + 57)]),
    cycle(4, T0 + 90, [located("AA:BB:CC:DD:EE:01", T0 + 85, P2),
                       client("AA:BB:CC:DD:EE:03", T0 + 82)]),
    cycle(5, T0 + 120, [located("AA:BB:CC:DD:EE:01", T0 + 115, P2)]),
]
scenarios.append(scenario(
    "office-dense-afternoon",
    "Dense office afternoon: many static clients and APs while the operator moves between two "
    "work areas. Unlocated devices can never co-travel; density alone must not alert.",
    "normal",
    {"detect": False, "state": "clear"},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 3. park-walk-single-sightings: GPS walk, each device seen exactly once.
c = [
    cycle(1, T0, [located("AA:BB:CC:DD:EE:11", T0 - 5, P1), gps(P1, T0 - 3)]),
    cycle(2, T0 + 30, [located("AA:BB:CC:DD:EE:12", T0 + 25, P2), gps(P2, T0 + 27)]),
    cycle(3, T0 + 60, [located("AA:BB:CC:DD:EE:13", T0 + 55, P3), gps(P3, T0 + 57)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "park-walk-single-sightings",
    "Park walk: passers-by each seen at a single place once. One sighting can never form the "
    "two distinct co-located visits co-travel requires.",
    "normal",
    {"detect": False, "state": "clear"},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 4. coffee-shop-dwell: stationary operator, co-located devices, ONE place.
c = [
    cycle(1, T0, [located("AA:BB:CC:DD:EE:21", T0 - 5, P1),
                  located("AA:BB:CC:DD:EE:22", T0 - 8, P1),
                  gps(P1, T0 - 3)]),
    cycle(2, T0 + 30, [located("AA:BB:CC:DD:EE:21", T0 + 25, P1), gps(P1, T0 + 27)]),
    cycle(3, T0 + 60, [located("AA:BB:CC:DD:EE:21", T0 + 55, P1), gps(P1, T0 + 57)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "coffee-shop-dwell",
    "Long dwell at one coffee shop: the same devices stay co-located with the operator at a "
    "single place the whole session. Repetition at one place is presence, not tracking — the "
    "evidence-first floor: repeated observation alone never alerts.",
    "normal",
    {"detect": False, "state": "clear"},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 5. deauth-single-frame: one stray deauth frame, below the attack floor.
c = [
    cycle(1, T0, [client("AA:BB:CC:DD:EE:02", T0 - 5)]),
    cycle(2, T0 + 30, [alert(T0 + 25, "AA:BB:CC:0D:00:09", "AA:BB:CC:DD:EE:02")]),
    cycle(3, T0 + 60, [client("AA:BB:CC:DD:EE:02", T0 + 55)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "deauth-single-frame",
    "A single stray deauthentication frame in an otherwise quiet session. Below "
    "min_events_for_attack=2, one frame must never file an attack incident.",
    "normal",
    {"detect": False, "state": "clear"},
    c,
    overrides={"deauth_detection": {"min_events_for_attack": 2}}))

# 6. ble-headphones-ambient: BLE devices with ordinary names.
c = [
    cycle(1, T0, [btle("DD:DD:DD:DD:11:01", "Studio Headphones", T0 - 5),
                  btle("DD:DD:DD:DD:11:02", "Car Speakerphone", T0 - 8)]),
    cycle(2, T0 + 30, [btle("DD:DD:DD:DD:11:01", "Studio Headphones", T0 + 25)]),
    cycle(3, T0 + 60, []),
]
scenarios.append(scenario(
    "ble-headphones-ambient",
    "BLE peripherals with ordinary product names around the operator. Sub-threshold BLE "
    "devices become entities, never tracker incidents.",
    "normal",
    {"detect": False, "state": "clear"},
    c,
    overrides={"ble_tracker": {"enabled": True}}))

# 7. rogue-trusted-ap-normal: the real trusted AP, seen repeatedly.
c = [
    cycle(1, T0, [ap("BB:BB:CC:00:11:01", "CafeNet", "WPA2-PSK", 6, T0 - 5)]),
    cycle(2, T0 + 30, [ap("BB:BB:CC:00:11:01", "CafeNet", "WPA2-PSK", 6, T0 + 25)]),
    cycle(3, T0 + 60, []),
]
scenarios.append(scenario(
    "rogue-trusted-ap-normal",
    "The operator's own trusted AP advertising exactly the configured SSID, BSSID, "
    "encryption, and channel. A trusted AP must never self-alert.",
    "normal",
    {"detect": False, "state": "clear"},
    c,
    overrides={"rogue_ap_detection": {"trusted_aps": [
        {"ssid": "CafeNet", "bssid": "BB:BB:CC:00:11:01",
         "encryption": "WPA2-PSK", "channel": 6}]}}))

# 8. quiet-restart-mid-session: declared restart on quiet air.
c = [
    cycle(1, T0, [client("AA:BB:CC:DD:EE:01", T0 - 5)]),
    cycle(2, T0 + 30, [client("AA:BB:CC:DD:EE:01", T0 + 25)]),
    cycle(3, T0 + 60, [client("AA:BB:CC:DD:EE:02", T0 + 55)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "quiet-restart-mid-session",
    "Quiet session with a service restart mid-air. A restart must never manufacture "
    "incidents on silent RF.",
    "normal", {"detect": False, "state": "clear"}, c, restarts=[2]))

# 9. conference-density-ambient: high device count, nothing hostile.
conf_rows_1 = [client(f"AA:BB:CC:DD:{i:02d}:{i + 1:02d}", T0 - 5 - i)
               for i in range(4)]
conf_rows_1 += [ap("BB:BB:CC:03:00:01", "ConfWiFi", "WPA2-ENT", 6, T0 - 3),
                ap("BB:BB:CC:03:00:02", "ConfWiFi-Lobby", "WPA2-ENT", 11, T0 - 4)]
conf_rows_2 = [client(f"AA:BB:CC:DD:{i:02d}:{i + 1:02d}", T0 + 30 - i)
               for i in range(4, 8)]
conf_rows_2 += [ap("BB:BB:CC:03:00:03", "VendorBooth", "WPA2-PSK", 1, T0 + 27),
                ap("BB:BB:CC:03:00:04", "AP-4F", "Open", 3, T0 + 26)]
c = [
    cycle(1, T0, conf_rows_1),
    cycle(2, T0 + 30, conf_rows_2),
    cycle(3, T0 + 60, [client(f"AA:BB:CC:DD:{i:02d}:{i + 1:02d}", T0 + 55 - i)
                       for i in range(4)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "conference-hall-density",
    "Conference hall: a dozen ambient devices across cycles. Crowding is context for the "
    "confidence model, never an alert on its own.",
    "normal", {"detect": False, "state": "clear"}, c))

# ----------------------------------------------------------- suspicious ----

# 10. library-evil-twin: trusted SSID spoofed with weaker encryption.
c = [
    cycle(1, T0, [ap("BB:BB:CC:00:22:01", "LibraryNet", "WPA2-PSK", 1, T0 - 5)]),
    cycle(2, T0 + 30, [ap("BB:BB:CC:00:22:99", "LibraryNet", "WEP", 1, T0 + 25)]),
    cycle(3, T0 + 60, [ap("BB:BB:CC:00:22:99", "LibraryNet", "WEP", 1, T0 + 55)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "library-evil-twin",
    "A second BSSID advertising the operator's trusted library network with WEP while the "
    "trusted AP runs WPA2-PSK: unknown-BSSID evil twin plus encryption downgrade.",
    "suspicious",
    {"detect": True, "state": "alert", "max_latency_cycles": 2,
     "entity_keys": ["BB:BB:CC:00:22:99"], "max_incidents": 1},
    c,
    overrides={"rogue_ap_detection": {"trusted_aps": [
        {"ssid": "LibraryNet", "bssid": "BB:BB:CC:00:22:01",
         "encryption": "WPA2-PSK", "channel": 1}]}}))

# 11. deauth-broadcast-flood: broadcast deauths across two cycles.
c = [
    cycle(1, T0, [alert(T0 - 8, "AA:BB:CC:0D:00:01", "FF:FF:FF:FF:FF:FF"),
                  alert(T0 - 5, "AA:BB:CC:0D:00:01", "FF:FF:FF:FF:FF:FF")]),
    cycle(2, T0 + 20, [alert(T0 + 12, "AA:BB:CC:0D:00:01", "FF:FF:FF:FF:FF:FF"),
                       alert(T0 + 15, "AA:BB:CC:0D:00:01", "FF:FF:FF:FF:FF:FF")]),
    cycle(3, T0 + 40, []),
    cycle(4, T0 + 60, []),
]
scenarios.append(scenario(
    "deauth-broadcast-flood",
    "Four broadcast deauthentication frames from one attacker across two cycles — a flooding "
    "pattern that must trip the attack classifier on cycle 1.",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 1,
     "entity_keys": ["FF:FF:FF:FF:FF:FF"], "max_incidents": 1},
    c,
    overrides={"deauth_detection": {"min_events_for_attack": 2}}))

# 12. deauth-targeted-operator-phone: frames aimed at the operator's phone.
c = [
    cycle(1, T0, [alert(T0 - 9, "AA:BB:CC:0D:00:07", "AA:BB:CC:00:00:01"),
                  alert(T0 - 6, "AA:BB:CC:0D:00:07", "AA:BB:CC:00:00:01"),
                  alert(T0 - 3, "AA:BB:CC:0D:00:07", "AA:BB:CC:00:00:01")]),
    cycle(2, T0 + 30, []),
    cycle(3, T0 + 60, [alert(T0 + 52, "AA:BB:CC:0D:00:07", "AA:BB:CC:00:00:01")]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "deauth-targeted-operator-phone",
    "Repeated deauthentication frames aimed at the operator's own phone: one targeted attack "
    "incident on the phone's identity, re-observed by the later frame.",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 1,
     "entity_keys": ["AA:BB:CC:00:00:01"], "max_incidents": 1},
    c,
    overrides={"deauth_detection": {"min_events_for_attack": 2}}))

# 13. ble-airtag-stalker: an AirTag-class tracker across cycles.
c = [
    cycle(1, T0, [btle("DD:DD:DD:DD:DD:02", "AirTag", T0 - 5)]),
    cycle(2, T0 + 30, [btle("DD:DD:DD:DD:DD:02", "AirTag", T0 - 5)]),
    cycle(3, T0 + 60, [btle("DD:DD:DD:DD:DD:02", "AirTag", T0 - 5)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "ble-airtag-stalker",
    "A BLE device advertising an AirTag-style tracker name follows the operator through a "
    "session: alert-band tracker score on first observation.",
    "suspicious",
    {"detect": True, "state": "alert", "max_latency_cycles": 1,
     "entity_keys": ["DD:DD:DD:DD:DD:02"], "max_incidents": 1},
    c,
    overrides={"ble_tracker": {"enabled": True}}))

# 14. ble-tracker-reappears: tracker drops out, comes back after a gap.
c = [
    cycle(1, T0, [btle("DD:DD:DD:DD:DD:03", "Tile Tracker", T0 - 5)]),
    cycle(2, T0 + 30, [btle("DD:DD:DD:DD:DD:03", "Tile Tracker", T0 - 5)]),
    cycle(3, T0 + 60, []),
    cycle(4, T0 + 90, []),
    cycle(5, T0 + 120, []),
    cycle(6, T0 + 150, [btle("DD:DD:DD:DD:DD:03", "Tile Tracker", T0 + 145)]),
    cycle(7, T0 + 180, []),
]
scenarios.append(scenario(
    "ble-tracker-reappears",
    "A Tile-style tracker is present, drops out long enough for staleness to close the "
    "incident, then reappears. The same subject must re-open its incident, not vanish.",
    "suspicious",
    {"detect": True, "state": "alert", "max_latency_cycles": 1,
     "entity_keys": ["DD:DD:DD:DD:DD:03"], "max_incidents": 1},
    c,
    overrides={"ble_tracker": {"enabled": True}},
    close_after=60.0))

# 15. cotravel-two-stop-follower: follower at two distinct operator stops.
# Co-located devices share IDENTICAL per-stop timestamps: co-travel requires
# time-overlapping operator visits (the canonical walk-cotravel pattern).
c = [
    cycle(1, T0, [located("AA:BB:CC:00:00:01", T0 - 10, P1),
                  located("AA:BB:CC:00:00:42", T0 - 10, P1)]),
    cycle(2, T0 + 60, [located("AA:BB:CC:00:00:01", T0 + 50, P2),
                       located("AA:BB:CC:00:00:42", T0 + 50, P2)]),
    cycle(3, T0 + 120, []),
]
scenarios.append(scenario(
    "cotravel-two-stop-follower",
    "A device co-present with the operator at two distinct places (~1.5 km apart): the "
    "co-travel floor. The operator's own phone co-travels with itself by construction "
    "(operator self-identity is out of scope per the build spec), so the phone and the "
    "follower both file and the follower's incident is the one the label pins.",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 2,
     "entity_keys": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:42"],
     "max_incidents": 2},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 16. cotravel-three-stops: follower persists across three stops.
c = [
    cycle(1, T0, [located("AA:BB:CC:00:00:01", T0 - 10, P1),
                  located("AA:BB:CC:00:00:42", T0 - 10, P1)]),
    cycle(2, T0 + 60, [located("AA:BB:CC:00:00:01", T0 + 50, P2),
                       located("AA:BB:CC:00:00:42", T0 + 50, P2)]),
    cycle(3, T0 + 120, [located("AA:BB:CC:00:00:01", T0 + 110, P3),
                        located("AA:BB:CC:00:00:42", T0 + 110, P3)]),
    cycle(4, T0 + 180, []),
]
scenarios.append(scenario(
    "cotravel-three-stops",
    "A follower co-present at three distinct operator stops: higher location count must keep "
    "the incident open and watch-band (score rises, band stays watch below 0.75).",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 2,
     "entity_keys": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:42"],
     "max_incidents": 2},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 17. cotravel-fast-follower: tight loop near the operator, short span.
c = [
    cycle(1, T0, [located("AA:BB:CC:00:00:01", T0 - 10, P1),
                  located("AA:BB:CC:00:00:43", T0 - 10, P1)]),
    cycle(2, T0 + 30, [located("AA:BB:CC:00:00:01", T0 + 20, P2C),
                       located("AA:BB:CC:00:00:43", T0 + 20, P2C)]),
    cycle(3, T0 + 60, []),
]
scenarios.append(scenario(
    "cotravel-fast-follower",
    "A close-range follower moving with the operator between two nearby (130 m) but distinct "
    "places within 30 seconds: a short-span tail that still crosses the two-location floor.",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 2,
     "entity_keys": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:43"],
     "max_incidents": 2},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 18. randomized-mac-follower: follower rotates MAC between place pairs.
c = [
    cycle(1, T0, [located("AA:BB:CC:00:00:01", T0 - 10, P1),
                  located("AA:BB:CC:07:00:01", T0 - 10, P1)]),
    cycle(2, T0 + 60, [located("AA:BB:CC:00:00:01", T0 + 50, P2),
                       located("AA:BB:CC:07:00:01", T0 + 50, P2)]),
    cycle(3, T0 + 120, [located("AA:BB:CC:00:00:01", T0 + 110, P2),
                        located("AA:BB:CC:07:00:02", T0 + 110, P2)]),
    cycle(4, T0 + 180, [located("AA:BB:CC:00:00:01", T0 + 170, P3),
                        located("AA:BB:CC:07:00:02", T0 + 170, P3)]),
    cycle(5, T0 + 240, []),
]
scenarios.append(scenario(
    "randomized-mac-follower",
    "A follower that rotates its MAC every two cycles. Replay v1 has no identity linking "
    "(hypotheses are D3 scope, out of replay), so each rotated identity is detected "
    "independently on its own co-located visits — tracking is caught per-identity, and "
    "the corpus pins that behavior until identity hypotheses join replay.",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 2,
     "entity_keys": ["AA:BB:CC:00:00:01", "AA:BB:CC:07:00:01", "AA:BB:CC:07:00:02"],
     "max_incidents": 3},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 19. cooperating-followers-deauth: two followers plus a deauth burst.
c = [
    cycle(1, T0, [located("AA:BB:CC:00:00:01", T0 - 10, P1),
                  located("AA:BB:CC:00:00:51", T0 - 10, P1),
                  located("AA:BB:CC:00:00:52", T0 - 10, P1),
                  alert(T0 - 9, "AA:BB:CC:0D:00:11", "AA:BB:CC:00:00:51"),
                  alert(T0 - 6, "AA:BB:CC:0D:00:11", "AA:BB:CC:00:00:51")]),
    cycle(2, T0 + 60, [located("AA:BB:CC:00:00:01", T0 + 50, P2),
                       located("AA:BB:CC:00:00:51", T0 + 50, P2),
                       located("AA:BB:CC:00:00:52", T0 + 50, P2)]),
    cycle(3, T0 + 120, []),
]
scenarios.append(scenario(
    "cooperating-followers-deauth",
    "Two devices travel with the operator across two stops while one of them is also hit by "
    "a deauthentication burst: independent evidence classes must all file (three cotravel "
    "subjects plus the deauth attack on the hit device), never collapse to one.",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 1,
     "entity_keys": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:51", "AA:BB:CC:00:00:52"],
     "max_incidents": 4},
    c,
    overrides={"gps_fusion": {"enabled": True, "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2},
               "deauth_detection": {"min_events_for_attack": 2}}))

# 20. deauth-persistent-across-restart: fresh post-restart frames update one incident.
c = [
    cycle(1, T0, [alert(1699999994.0, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"),
                  alert(1699999997.0, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")]),
    cycle(2, T0 + 30, []),
    cycle(3, T0 + 60, [alert(T0 + 58, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"),
                       alert(T0 + 59, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")]),
    cycle(4, T0 + 90, []),
    cycle(5, T0 + 120, []),
]
scenarios.append(scenario(
    "deauth-persistent-across-restart",
    "A deauth attack continues across a service restart: frames dated after the persisted "
    "watermark must re-observe the SAME incident (fresh last_seen), not duplicate it and not "
    "replay pre-restart history.",
    "suspicious",
    {"detect": True, "state": "watch", "max_latency_cycles": 1,
     "entity_keys": ["AA:BB:CC:DD:EE:02"], "max_incidents": 1},
    c,
    overrides={"deauth_detection": {"min_events_for_attack": 2}},
    restarts=[2]))

# 21. rogue-recurrence-autolearn: monitored-SSID auto-learn, then a new BSSID.
c = [
    cycle(1, T0, [ap("BB:BB:CC:00:33:01", "GuestNet", "WPA2-PSK", 6, T0 - 5)]),
    cycle(2, T0 + 30, [ap("BB:BB:CC:00:33:99", "GuestNet", "WPA2-PSK", 6, T0 + 25)]),
    cycle(3, T0 + 60, []),
    cycle(4, T0 + 90, [ap("BB:BB:CC:00:33:99", "GuestNet", "WPA2-PSK", 6, T0 + 85)]),
    cycle(5, T0 + 120, []),
]
scenarios.append(scenario(
    "rogue-recurrence-autolearn",
    "A monitored SSID is auto-learned from its first BSSID; a second BSSID then raises a "
    "new-BSSID alert. After the mid-session restart the recurring BSSID must not re-alert "
    "(post-restart auto-learn) nor duplicate the incident.",
    "suspicious",
    {"detect": True, "state": "alert", "max_latency_cycles": 2,
     "entity_keys": ["BB:BB:CC:00:33:99"], "max_incidents": 1},
    c,
    overrides={"rogue_ap_detection": {"monitored_ssids": ["GuestNet"]}},
    restarts=[2]))

# 22. evil-twin-hostile-ssid: markup-carrying SSID through the detection path.
c = [
    cycle(1, T0, [ap("BB:BB:CC:00:44:01", HOSTILE, "WPA2-PSK", 6, T0 - 5)]),
    cycle(2, T0 + 30, [ap("BB:BB:CC:00:44:99", HOSTILE, "WEP", 11, T0 + 25)]),
    cycle(3, T0 + 60, [ap("BB:BB:CC:00:44:99", HOSTILE, "WEP", 11, T0 + 55)]),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "evil-twin-hostile-ssid",
    "An evil twin whose advertised SSID carries HTML markup and a script payload: detection "
    "must still fire on the BSSID/downgrade evidence, and no display field of any incident "
    "(summary, entity, window label) may ever carry the raw SSID text. See the PR's known "
    "finding: evidence reason strings still carry raw SSID text into store events and "
    "status.json evidence — redaction is a detector-contract fix outside this task's scope.",
    "suspicious",
    {"detect": True, "state": "alert", "max_latency_cycles": 2,
     "entity_keys": ["BB:BB:CC:00:44:99"], "max_incidents": 1,
     "no_raw_strings": ["<script>", "alert(1)"]},
    c,
    overrides={"rogue_ap_detection": {"trusted_aps": [
        {"ssid": HOSTILE, "bssid": "BB:BB:CC:00:44:01",
         "encryption": "WPA2-PSK", "channel": 6}]}}))

# ------------------------------------------------------------------ edge ----

# 23. gps-dropout-mid-session: GPS dies after cycle 1 -> degraded, never clear.
c = [
    cycle(1, T0, [located("AA:BB:CC:DD:EE:31", T0 - 5, P1)]),
    cycle(2, T0 + 30, []),
    cycle(3, T0 + 60, []),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "gps-dropout-mid-session",
    "The GPS feed dies after one fix and never returns: the gps component must degrade the "
    "published state — 'cannot detect' must never read as 'no threat'.",
    "edge",
    {"detect": False, "state": "degraded"},
    c,
    overrides={"gps_fusion": {"enabled": True, "dropout_seconds": 10,
                              "min_locations_for_cotravel": 2,
                              "min_span_seconds": 1,
                              "incident_score_threshold": 0.2}}))

# 24. corrupt-rows-tolerated: malformed and degenerate rows, no crash.
dup = client("AA:BB:CC:DD:EE:42", T0 - 5)
c = [
    cycle(1, T0, [dev("AA:BB:CC:DD:EE:41", "", T0 - 6, {}),
                  dup,
                  dup,  # exact duplicate inside one cycle
                  alert(T0 - 4, "AA:BB:CC:0D:00:99", "AA:BB:CC:DD:EE:41",
                        header="CORRUPT"),
                  {"source": "ble", "row": {"mac": "DD:DD:DD:DD:DD:99",
                                            "ts": T0 - 5, "rssi": -80.0}}]),
    cycle(2, T0 + 30, [dev("AA:BB:CC:DD:EE:43", "Wi-Fi Client", T0 + 25, None)]),
    cycle(3, T0 + 60, []),
    cycle(4, T0 + 90, []),
]
scenarios.append(scenario(
    "corrupt-rows-tolerated",
    "Degenerate source rows: empty device type, empty device JSON, an exact duplicate row, a "
    "non-deauth alert header, a nameless BLE advertisement, a null device blob. The pipeline "
    "must tolerate all of them without crashing or filing incidents.",
    "edge", {"detect": False, "state": "clear"}, c))

# 25. clock-jump-quiet: a one-hour clock jump on quiet air.
c = [
    cycle(1, T0, [client("AA:BB:CC:DD:EE:01", T0 - 5)]),
    cycle(2, T0 + 30, [client("AA:BB:CC:DD:EE:01", T0 + 25)]),
    cycle(3, T0 + 3630, [client("AA:BB:CC:DD:EE:01", T0 + 3625)]),
    cycle(4, T0 + 3660, []),
]
scenarios.append(scenario(
    "clock-jump-quiet",
    "The scenario clock jumps forward one hour mid-session (NTP correction). Windowed pulls "
    "and staleness must stay sane across the jump and the quiet air must stay clear.",
    "edge", {"detect": False, "state": "clear"}, c))

OUT.mkdir(parents=True, exist_ok=True)
for doc in scenarios:
    path = OUT / f"{doc['scenario_id']}.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    print(f"wrote {path} ({len(doc['cycles'])} cycles)")
print(f"total: {len(scenarios)} scenarios")
