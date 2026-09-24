"""
Deauthentication Attack Detector for CYT
Monitors Kismet data for deauth/disassociation attacks targeting your devices.

Detection methods:
1. Kismet alerts table - captures DEAUTH and DISASSOCIATION alert types
2. Device JSON analysis - detects rapid client state changes indicating forced disconnects
3. Burst detection - identifies flood patterns (many deauth frames in short windows)
"""
import sqlite3
import json
import logging
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

from cyt_platform.kismet_ro import (
    connect_readonly,
    coerce_watermark,
    scan_start_from_watermark,
)

logger = logging.getLogger(__name__)


@dataclass
class DeauthEvent:
    """A detected deauthentication event"""
    timestamp: float
    target_mac: str
    source_mac: str
    channel: Optional[int] = None
    reason_code: Optional[int] = None
    event_type: str = "deauth"  # deauth, disassoc, or flood
    alert_text: str = ""

    @property
    def time_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')


@dataclass
class DeauthAttack:
    """A confirmed deauth attack pattern (multiple events correlated)"""
    target_mac: str
    attacker_mac: str
    events: List[DeauthEvent] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_frames: int = 0
    peak_rate_per_min: float = 0.0
    channels_used: List[int] = field(default_factory=list)
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    attack_type: str = "targeted"  # targeted, broadcast, flood

    @property
    def duration_seconds(self) -> float:
        return self.last_seen - self.first_seen if self.last_seen > self.first_seen else 0


# Standard 802.11 deauth reason codes
REASON_CODES = {
    1: "Unspecified",
    2: "Auth no longer valid",
    3: "Station leaving/has left",
    4: "Inactivity timer expired",
    5: "AP unable to handle all stations",
    6: "Class 2 frame from non-auth station",
    7: "Class 3 frame from non-assoc station",
    8: "Station leaving/has left BSS",
    9: "Association request before auth",
}


class DeauthDetector:
    """Detects deauthentication and disassociation attacks from Kismet data"""

    def __init__(
        self,
        config: Dict,
        watermark_loader: Optional[Callable[[], Optional[float]]] = None,
        watermark_saver: Optional[Callable[[float], None]] = None,
    ):
        self.config = config

        # Detection thresholds from config or defaults
        deauth_config = config.get('deauth_detection', {})
        self.burst_threshold = deauth_config.get('burst_threshold', 10)
        self.burst_window_seconds = deauth_config.get('burst_window_seconds', 60)
        self.min_events_for_attack = deauth_config.get('min_events_for_attack', 5)
        self.scan_interval_minutes = deauth_config.get('scan_interval_minutes', 5)
        # Max look-back for a scan with no (or a stale) persisted watermark;
        # bounds replay of old capture data after a restart.
        self.catchup_window_seconds = float(
            deauth_config.get('catchup_window_seconds', 1800)
        )

        # Protected devices (your own MACs to watch)
        self.protected_macs = set(
            mac.upper() for mac in deauth_config.get('protected_macs', [])
        )

        # Watermark: epoch second just past the newest durably handled alert.
        # Persisted by the host (store-backed) so a restart never re-reads
        # processed history; 0.0 means no watermark (first run).
        self._watermark_loader = watermark_loader
        self._watermark_saver = watermark_saver

        # State tracking
        self.events: List[DeauthEvent] = []
        self.attacks: List[DeauthAttack] = []
        self.last_scan_time: float = 0.0
        self.last_scan_error: Optional[str] = None
        persisted = coerce_watermark(
            watermark_loader() if watermark_loader else None
        )
        if persisted is not None:
            self.last_scan_time = persisted

    def _scan_start(self, now: float) -> float:
        """Earliest timestamp this scan should read (see kismet_ro)."""
        return scan_start_from_watermark(
            self.last_scan_time, now, self.catchup_window_seconds
        )

    def _advance_watermark(self, max_event_ts: float) -> None:
        """Advance the watermark past processed alerts.

        Called only after a clean scan; the saver write participates in the
        caller's store transaction (if any), so the watermark commits atomically
        with the incidents derived from these events — it never runs ahead of
        durable handling.
        """
        candidate = max_event_ts + 1.0
        if candidate <= self.last_scan_time:
            return
        self.last_scan_time = candidate
        if self._watermark_saver is not None:
            try:
                self._watermark_saver(candidate)
            except Exception as e:
                # Safe direction: watermark stays behind, alerts are re-read
                # (and re-deduped) next cycle rather than skipped.
                logger.error("Failed to persist deauth watermark: %s", e)

    def scan_kismet_db(
        self, db_path: str, now: Optional[float] = None
    ) -> List[DeauthEvent]:
        """Scan a Kismet database for deauth activity. Returns new events found.

        ``now`` is an injected clock (replay): wall clock only when omitted.
        """
        new_events = []
        self.last_scan_error = None

        try:
            conn = connect_readonly(db_path)

            try:
                new_events.extend(self._scan_alerts_table(conn, now=now))
                new_events.extend(self._scan_device_deauth_data(conn, now=now))
            finally:
                conn.close()

        except sqlite3.Error as e:
            self.last_scan_error = f"kismet_db_error: {e}"
            logger.error("Database error scanning for deauth events: %s", e)
        except Exception as e:
            self.last_scan_error = f"scan_error: {e}"
            logger.error("Error scanning for deauth events: %s", e)

        # Deduplicate by timestamp+target+source
        seen = set()
        unique_events = []
        for event in new_events:
            key = (round(event.timestamp, 1), event.target_mac, event.source_mac)
            if key not in seen:
                seen.add(key)
                unique_events.append(event)

        self.events.extend(unique_events)

        # Watermark advances on clean scans only; a failed scan must not
        # skip past data it could not read.
        if self.last_scan_error is None and unique_events:
            self._advance_watermark(
                max(event.timestamp for event in unique_events)
            )

        logger.info(f"Deauth scan found {len(unique_events)} new events")
        return unique_events

    def _scan_alerts_table(
        self, conn: sqlite3.Connection, now: Optional[float] = None
    ) -> List[DeauthEvent]:
        """Check Kismet's alerts table for deauth/disassoc alerts"""
        events = []
        cursor = conn.cursor()

        # Check if alerts table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        )
        if not cursor.fetchone():
            logger.debug("No alerts table in Kismet database")
            return events

        # Query deauth-related alerts
        try:
            scan_start = self._scan_start(time.time() if now is None else float(now))
            cursor.execute(
                """SELECT ts_sec, header, json FROM alerts
                   WHERE ts_sec >= ?
                   ORDER BY ts_sec""",
                (scan_start,)
            )

            deauth_keywords = [
                'deauth', 'disassoc', 'deauthentication',
                'disassociation', 'deauthflood', 'bssflood',
                'apspoof', 'changehostname'
            ]

            for row in cursor:
                try:
                    alert_json = json.loads(row['json']) if row['json'] else {}
                    header = row['header'] if row['header'] else ''
                    alert_text = alert_json.get('kismet.alert.text', header)
                    alert_type = alert_json.get('kismet.alert.header', header)

                    type_lower = alert_type.lower()
                    text_lower = alert_text.lower()
                    is_deauth = any(
                        kw in type_lower or kw in text_lower
                        for kw in deauth_keywords
                    )

                    if not is_deauth:
                        continue

                    source_mac = alert_json.get('kismet.alert.source_mac', 'FF:FF:FF:FF:FF:FF')
                    dest_mac = alert_json.get('kismet.alert.dest_mac', 'FF:FF:FF:FF:FF:FF')
                    channel = alert_json.get('kismet.alert.channel', None)

                    event = DeauthEvent(
                        timestamp=float(row['ts_sec']),
                        target_mac=dest_mac.upper(),
                        source_mac=source_mac.upper(),
                        channel=int(channel) if channel else None,
                        event_type="deauth" if "deauth" in alert_type.lower() else "disassoc",
                        alert_text=alert_text[:200]
                    )
                    events.append(event)

                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logger.debug(f"Error parsing alert row: {e}")
                    continue

        except sqlite3.Error as e:
            logger.debug(f"Error querying alerts table: {e}")

        return events

    def _scan_device_deauth_data(
        self, conn: sqlite3.Connection, now: Optional[float] = None
    ) -> List[DeauthEvent]:
        """Analyze device JSON blobs for deauth frame indicators.

        Kismet tracks dot11.device fields that indicate deauth activity
        even when specific alerts aren't generated.
        """
        events = []
        cursor = conn.cursor()

        scan_start = self._scan_start(time.time() if now is None else float(now))

        try:
            cursor.execute(
                """SELECT devmac, type, device, last_time
                   FROM devices
                   WHERE last_time >= ? AND device IS NOT NULL""",
                (scan_start,)
            )

            for row in cursor:
                try:
                    device_data = json.loads(row['device'])
                    mac = row['devmac'].upper()
                    last_time = float(row['last_time'])

                    dot11 = device_data.get('dot11.device', {})
                    if not isinstance(dot11, dict):
                        continue

                    client_map = dot11.get('dot11.device.client_map', {})
                    if isinstance(client_map, dict):
                        for bssid, client_data in client_map.items():
                            if not isinstance(client_data, dict):
                                continue

                            retries = client_data.get('dot11.client.retries', 0)
                            tx_packets = client_data.get('dot11.client.tx_packets', 0)

                            if tx_packets > 0 and retries > 0:
                                retry_rate = retries / tx_packets
                                if retry_rate > 0.5 and retries > 50:
                                    event = DeauthEvent(
                                        timestamp=last_time,
                                        target_mac=mac,
                                        source_mac=bssid.upper() if bssid else 'UNKNOWN',
                                        event_type="interference",
                                        alert_text=(
                                            f"High retry rate ({retry_rate:.0%}) - "
                                            f"{retries} retries / {tx_packets} packets. "
                                            f"Possible deauth interference on {bssid}"
                                        )
                                    )
                                    events.append(event)

                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logger.debug(f"Error parsing device data for {row['devmac']}: {e}")
                    continue

        except sqlite3.Error as e:
            logger.debug(f"Error scanning devices for deauth data: {e}")

        return events

    def analyze_attacks(self) -> List[DeauthAttack]:
        """Correlate deauth events into attack patterns"""
        self.attacks = []

        if not self.events:
            return self.attacks

        # Group events by target MAC
        events_by_target = defaultdict(list)
        for event in self.events:
            events_by_target[event.target_mac].append(event)

        for target_mac, target_events in events_by_target.items():
            # Sort by timestamp
            target_events.sort(key=lambda e: e.timestamp)

            # Group by source MAC (attacker)
            events_by_source = defaultdict(list)
            for event in target_events:
                events_by_source[event.source_mac].append(event)

            for source_mac, source_events in events_by_source.items():
                if len(source_events) < self.min_events_for_attack:
                    continue

                attack = self._build_attack(target_mac, source_mac, source_events)
                if attack:
                    self.attacks.append(attack)

        # Also detect broadcast floods (FF:FF:FF:FF:FF:FF target)
        broadcast_events = events_by_target.get('FF:FF:FF:FF:FF:FF', [])
        if len(broadcast_events) >= self.min_events_for_attack:
            by_source = defaultdict(list)
            for event in broadcast_events:
                by_source[event.source_mac].append(event)

            for source_mac, source_events in by_source.items():
                if len(source_events) >= self.min_events_for_attack:
                    attack = self._build_attack(
                        'FF:FF:FF:FF:FF:FF', source_mac, source_events
                    )
                    if attack:
                        attack.attack_type = "broadcast"
                        self.attacks.append(attack)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.attacks.sort(key=lambda a: severity_order.get(a.severity, 4))

        return self.attacks

    def _build_attack(
        self, target_mac: str, source_mac: str, events: List[DeauthEvent]
    ) -> Optional[DeauthAttack]:
        """Build an attack record from correlated events"""
        if not events:
            return None

        timestamps = [e.timestamp for e in events]
        channels = [e.channel for e in events if e.channel is not None]

        # Calculate peak rate (events per minute in sliding window)
        peak_rate = self._calculate_peak_rate(timestamps)

        # Determine severity
        severity = self._classify_severity(len(events), peak_rate, target_mac)

        attack = DeauthAttack(
            target_mac=target_mac,
            attacker_mac=source_mac,
            events=events,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            total_frames=len(events),
            peak_rate_per_min=peak_rate,
            channels_used=sorted(set(channels)),
            severity=severity,
            attack_type="flood" if peak_rate > self.burst_threshold else "targeted"
        )

        return attack

    def _calculate_peak_rate(self, timestamps: List[float]) -> float:
        """Calculate peak event rate per minute using two-pointer sliding window (O(n))"""
        if len(timestamps) < 2:
            return float(len(timestamps))

        sorted_ts = sorted(timestamps)
        window = self.burst_window_seconds
        max_count = 0
        left = 0

        for right in range(len(sorted_ts)):
            while sorted_ts[right] - sorted_ts[left] > window:
                left += 1
            max_count = max(max_count, right - left + 1)

        return max_count * (60.0 / window)

    def _classify_severity(
        self, event_count: int, peak_rate: float, target_mac: str
    ) -> str:
        """Classify attack severity"""
        is_protected = target_mac.upper() in self.protected_macs

        if peak_rate > self.burst_threshold * 5 or (is_protected and event_count > 20):
            return "CRITICAL"
        elif peak_rate > self.burst_threshold * 2 or (is_protected and event_count > 10):
            return "HIGH"
        elif peak_rate > self.burst_threshold or event_count > 20:
            return "MEDIUM"
        else:
            return "LOW"

    def get_protected_device_attacks(self) -> List[DeauthAttack]:
        """Get attacks specifically targeting your protected devices"""
        if not self.protected_macs:
            return self.attacks

        return [
            a for a in self.attacks
            if a.target_mac.upper() in self.protected_macs
            or a.target_mac == 'FF:FF:FF:FF:FF:FF'
        ]

    def generate_report(self, output_dir: str = './surveillance_reports') -> str:
        """Generate a markdown report of deauth attack findings"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = Path(output_dir) / f"deauth_report_{timestamp}.md"

        lines = []
        lines.append("# Deauthentication Attack Detection Report")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Total Events:** {len(self.events)}")
        lines.append(f"**Confirmed Attacks:** {len(self.attacks)}")
        lines.append(f"**Protected Devices:** {len(self.protected_macs)}")
        lines.append("")

        if not self.attacks:
            lines.append("## No Deauth Attacks Detected")
            lines.append("")
            lines.append("No deauthentication or disassociation attack patterns were found")
            lines.append("in the analyzed Kismet data. This is normal for environments")
            lines.append("without active wireless attacks.")
            lines.append("")
            if self.events:
                lines.append(f"*Note: {len(self.events)} individual deauth frames were observed,")
                lines.append("but none met the threshold for a confirmed attack pattern.*")
        else:
            # Summary table
            lines.append("## Attack Summary")
            lines.append("")
            lines.append("| Severity | Target | Attacker | Frames | Peak Rate/min | Duration | Type |")
            lines.append("|----------|--------|----------|--------|---------------|----------|------|")

            for attack in self.attacks:
                duration = attack.duration_seconds
                if duration > 3600:
                    dur_str = f"{duration/3600:.1f}h"
                elif duration > 60:
                    dur_str = f"{duration/60:.0f}m"
                else:
                    dur_str = f"{duration:.0f}s"

                is_yours = " (YOUR DEVICE)" if attack.target_mac in self.protected_macs else ""
                lines.append(
                    f"| **{attack.severity}** "
                    f"| `{attack.target_mac}`{is_yours} "
                    f"| `{attack.attacker_mac}` "
                    f"| {attack.total_frames} "
                    f"| {attack.peak_rate_per_min:.0f} "
                    f"| {dur_str} "
                    f"| {attack.attack_type} |"
                )

            lines.append("")

            # Detailed attack analysis
            lines.append("## Detailed Attack Analysis")
            lines.append("")

            for i, attack in enumerate(self.attacks, 1):
                severity_emoji = {
                    "CRITICAL": "🚨", "HIGH": "⚠️",
                    "MEDIUM": "🟡", "LOW": "🔵"
                }
                emoji = severity_emoji.get(attack.severity, "⚪")

                lines.append(f"### {emoji} Attack #{i}: {attack.severity}")
                lines.append("")
                lines.append(f"- **Target:** `{attack.target_mac}`")
                lines.append(f"- **Attacker:** `{attack.attacker_mac}`")
                lines.append(f"- **First Seen:** {datetime.fromtimestamp(attack.first_seen).strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"- **Last Seen:** {datetime.fromtimestamp(attack.last_seen).strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"- **Total Frames:** {attack.total_frames}")
                lines.append(f"- **Peak Rate:** {attack.peak_rate_per_min:.0f} frames/minute")
                if attack.channels_used:
                    lines.append(f"- **Channels:** {', '.join(str(c) for c in attack.channels_used)}")
                lines.append(f"- **Attack Type:** {attack.attack_type}")
                lines.append("")

                # Show reason codes if present
                reason_codes = set()
                for event in attack.events:
                    if event.reason_code is not None:
                        reason_codes.add(event.reason_code)
                if reason_codes:
                    lines.append("**Reason Codes Used:**")
                    for code in sorted(reason_codes):
                        desc = REASON_CODES.get(code, "Unknown")
                        lines.append(f"  - Code {code}: {desc}")
                    lines.append("")

            # Countermeasures
            lines.append("## Recommended Countermeasures")
            lines.append("")
            lines.append("1. **Enable 802.11w (PMF)** - Protected Management Frames prevent deauth attacks")
            lines.append("2. **Use WPA3** - Includes mandatory PMF support")
            lines.append("3. **Monitor the attacker MAC** - Track the source device for identification")
            lines.append("4. **Change channels** - If attack is on specific channel, consider band steering")
            lines.append("5. **Physical investigation** - Deauth attacks require proximity (<100m typically)")
            lines.append("")

        report_text = '\n'.join(lines)

        with open(report_path, 'w') as f:
            f.write(report_text)

        logger.info(f"Deauth report saved to {report_path}")
        return str(report_path)


def run_deauth_scan(config: Dict, db_path: str) -> Tuple[List[DeauthEvent], List[DeauthAttack], str]:
    """Convenience function to run a full deauth scan and generate report.

    Returns: (events, attacks, report_path)
    """
    detector = DeauthDetector(config)
    events = detector.scan_kismet_db(db_path)
    attacks = detector.analyze_attacks()
    report_path = detector.generate_report()
    return events, attacks, report_path
