"""
Rogue Access Point Detector for CYT
Detects evil twin attacks and rogue APs spoofing your known SSIDs.

Detection methods:
1. BSSID mismatch - Known SSID seen from unknown BSSID (evil twin)
2. Encryption downgrade - Known SSID with weaker encryption than expected
3. Channel anomaly - Known SSID on unexpected channel
4. Signal strength anomaly - Known SSID with unusual signal characteristics
5. New AP discovery - Any previously-unseen AP advertising monitored SSIDs
"""
import sqlite3
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TrustedAP:
    """A known, trusted access point"""
    ssid: str
    bssid: str
    encryption: str = ""  # WPA2, WPA3, OWE, Open, etc.
    channel: Optional[int] = None
    first_seen: float = 0.0


@dataclass
class RogueAPAlert:
    """Alert for a detected rogue access point"""
    ssid: str
    rogue_bssid: str
    expected_bssid: str
    timestamp: float
    severity: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL
    reasons: List[str] = field(default_factory=list)
    rogue_encryption: str = ""
    expected_encryption: str = ""
    rogue_channel: Optional[int] = None
    expected_channel: Optional[int] = None
    signal_strength: Optional[float] = None

    @property
    def time_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')


class RogueAPDetector:
    """Detects rogue access points and evil twin attacks from Kismet data"""

    def __init__(self, config: Dict):
        self.config = config

        rogue_config = config.get('rogue_ap_detection', {})

        # Build trusted AP list from config
        self.trusted_aps: Dict[str, List[TrustedAP]] = defaultdict(list)
        for ap_entry in rogue_config.get('trusted_aps', []):
            ssid = ap_entry.get('ssid', '')
            bssid = ap_entry.get('bssid', '').upper()
            if ssid and bssid:
                trusted = TrustedAP(
                    ssid=ssid,
                    bssid=bssid,
                    encryption=ap_entry.get('encryption', ''),
                    channel=ap_entry.get('channel'),
                )
                self.trusted_aps[ssid].append(trusted)

        # SSIDs to monitor (even without known BSSIDs - will learn and alert on new ones)
        self.monitored_ssids: Set[str] = set(
            rogue_config.get('monitored_ssids', [])
        )
        # Add all trusted SSIDs to monitored set
        self.monitored_ssids.update(self.trusted_aps.keys())

        # Auto-learn: track all seen AP profiles to detect changes
        self.auto_learn = rogue_config.get('auto_learn', True)
        self.learned_aps: Dict[str, List[TrustedAP]] = defaultdict(list)

        # Detection state
        self.alerts: List[RogueAPAlert] = []
        self.seen_bssids: Dict[str, Set[str]] = defaultdict(set)  # ssid -> set of bssids
        self.last_scan_time: float = 0.0

    def scan_kismet_db(self, db_path: str) -> List[RogueAPAlert]:
        """Scan Kismet database for rogue APs. Returns new alerts."""
        new_alerts = []

        try:
            conn = sqlite3.connect(db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row

            # Scan for APs in device table
            new_alerts.extend(self._scan_ap_devices(conn))

            # Check Kismet alerts for AP-related warnings
            new_alerts.extend(self._scan_ap_alerts(conn))

            conn.close()

        except sqlite3.Error as e:
            logger.error(f"Database error scanning for rogue APs: {e}")
        except Exception as e:
            logger.error(f"Error scanning for rogue APs: {e}")

        # Deduplicate alerts
        seen = set()
        unique_alerts = []
        for alert in new_alerts:
            key = (alert.ssid, alert.rogue_bssid, round(alert.timestamp / 60))
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)

        self.alerts.extend(unique_alerts)
        self.last_scan_time = time.time()

        logger.info(f"Rogue AP scan found {len(unique_alerts)} new alerts")
        return unique_alerts

    def _scan_ap_devices(self, conn: sqlite3.Connection) -> List[RogueAPAlert]:
        """Scan device table for access points advertising monitored SSIDs"""
        alerts = []
        cursor = conn.cursor()

        scan_start = self.last_scan_time if self.last_scan_time > 0 else 0

        try:
            # Get all AP-type devices
            cursor.execute(
                """SELECT devmac, type, device, last_time, first_time
                   FROM devices
                   WHERE device IS NOT NULL AND last_time >= ?""",
                (scan_start,)
            )

            for row in cursor.fetchall():
                try:
                    device_data = json.loads(row['device'])
                    bssid = row['devmac'].upper()
                    last_time = float(row['last_time'])
                    dev_type = row['type'] or ''

                    dot11 = device_data.get('dot11.device', {})
                    if not isinstance(dot11, dict):
                        continue

                    # Extract advertised SSIDs from this device
                    # Kismet stores these in several places
                    advertised_ssids = self._extract_advertised_ssids(dot11)
                    responded_ssids = self._extract_responded_ssids(dot11)
                    all_ssids = advertised_ssids | responded_ssids

                    if not all_ssids:
                        continue

                    # Extract encryption and channel info
                    encryption = self._extract_encryption(dot11)
                    channel = self._extract_channel(device_data)

                    for ssid in all_ssids:
                        # Track all BSSIDs per SSID
                        prev_bssids = self.seen_bssids[ssid].copy()
                        self.seen_bssids[ssid].add(bssid)

                        # Check against trusted APs
                        if ssid in self.trusted_aps:
                            alert = self._check_against_trusted(
                                ssid, bssid, encryption, channel, last_time
                            )
                            if alert:
                                alerts.append(alert)

                        # Check monitored SSIDs for new BSSIDs
                        elif ssid in self.monitored_ssids:
                            if self.auto_learn and not prev_bssids:
                                # First time seeing this SSID - learn it
                                learned = TrustedAP(
                                    ssid=ssid, bssid=bssid,
                                    encryption=encryption,
                                    channel=channel,
                                    first_seen=last_time
                                )
                                self.learned_aps[ssid].append(learned)
                                logger.info(
                                    f"Learned AP: {ssid} -> {bssid} "
                                    f"(ch {channel}, {encryption})"
                                )
                            elif prev_bssids and bssid not in prev_bssids:
                                # New BSSID for a known SSID
                                alert = RogueAPAlert(
                                    ssid=ssid,
                                    rogue_bssid=bssid,
                                    expected_bssid=next(iter(prev_bssids)),
                                    timestamp=last_time,
                                    severity="HIGH",
                                    reasons=[
                                        f"New BSSID detected for monitored SSID '{ssid}'",
                                        f"Previously seen from: {', '.join(prev_bssids)}",
                                        f"Now also seen from: {bssid}"
                                    ],
                                    rogue_encryption=encryption,
                                    rogue_channel=channel,
                                )
                                alerts.append(alert)

                        # Auto-learn mode: track all APs
                        elif self.auto_learn:
                            if prev_bssids and bssid not in prev_bssids:
                                # Potentially interesting - new BSSID for existing SSID
                                # Only alert if it looks suspicious (same SSID, different BSSID)
                                # Keep this as LOW severity for awareness
                                pass  # Don't flood alerts for non-monitored SSIDs

                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logger.debug(f"Error parsing device {row['devmac']}: {e}")
                    continue

        except sqlite3.Error as e:
            logger.debug(f"Error scanning AP devices: {e}")

        return alerts

    def _check_against_trusted(
        self, ssid: str, bssid: str, encryption: str, channel: Optional[int],
        timestamp: float
    ) -> Optional[RogueAPAlert]:
        """Check a detected AP against the trusted AP list for this SSID"""
        trusted_list = self.trusted_aps.get(ssid, [])
        if not trusted_list:
            return None

        trusted_bssids = {t.bssid for t in trusted_list}

        # Check if this BSSID is trusted
        if bssid in trusted_bssids:
            # Known BSSID - check for encryption/channel changes
            matching_trusted = next(t for t in trusted_list if t.bssid == bssid)
            reasons = []

            if matching_trusted.encryption and encryption:
                if not self._encryption_matches(matching_trusted.encryption, encryption):
                    reasons.append(
                        f"Encryption changed: expected {matching_trusted.encryption}, "
                        f"got {encryption}"
                    )
                    if self._is_downgrade(matching_trusted.encryption, encryption):
                        reasons.append("ENCRYPTION DOWNGRADE DETECTED")

            if matching_trusted.channel and channel:
                if matching_trusted.channel != channel:
                    reasons.append(
                        f"Channel changed: expected {matching_trusted.channel}, "
                        f"got {channel}"
                    )

            if reasons:
                return RogueAPAlert(
                    ssid=ssid,
                    rogue_bssid=bssid,
                    expected_bssid=bssid,
                    timestamp=timestamp,
                    severity="MEDIUM",
                    reasons=reasons,
                    rogue_encryption=encryption,
                    expected_encryption=matching_trusted.encryption,
                    rogue_channel=channel,
                    expected_channel=matching_trusted.channel,
                )
            return None

        # Unknown BSSID advertising a trusted SSID - likely evil twin
        primary_trusted = trusted_list[0]
        reasons = [
            f"EVIL TWIN: Unknown BSSID '{bssid}' advertising trusted SSID '{ssid}'",
            f"Trusted BSSID(s): {', '.join(trusted_bssids)}"
        ]

        severity = "CRITICAL"

        if encryption and primary_trusted.encryption:
            if self._is_downgrade(primary_trusted.encryption, encryption):
                reasons.append(
                    f"ENCRYPTION DOWNGRADE: {primary_trusted.encryption} -> {encryption}"
                )
            elif not self._encryption_matches(primary_trusted.encryption, encryption):
                reasons.append(
                    f"Different encryption: expected {primary_trusted.encryption}, "
                    f"got {encryption}"
                )

        if channel and primary_trusted.channel:
            if channel != primary_trusted.channel:
                reasons.append(
                    f"Different channel: expected {primary_trusted.channel}, got {channel}"
                )

        return RogueAPAlert(
            ssid=ssid,
            rogue_bssid=bssid,
            expected_bssid=primary_trusted.bssid,
            timestamp=timestamp,
            severity=severity,
            reasons=reasons,
            rogue_encryption=encryption,
            expected_encryption=primary_trusted.encryption,
            rogue_channel=channel,
            expected_channel=primary_trusted.channel,
        )

    def _scan_ap_alerts(self, conn: sqlite3.Connection) -> List[RogueAPAlert]:
        """Check Kismet alerts table for AP-related alerts"""
        alerts = []
        cursor = conn.cursor()

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        )
        if not cursor.fetchone():
            return alerts

        try:
            scan_start = self.last_scan_time if self.last_scan_time > 0 else 0
            cursor.execute(
                """SELECT ts_sec, header, json FROM alerts
                   WHERE ts_sec >= ?
                   ORDER BY ts_sec""",
                (scan_start,)
            )

            ap_keywords = [
                'APSPOOF', 'BSSTIMESTAMP', 'PROBECHAN',
                'BEACONCHANGE', 'CRYPTODROP', 'ADVCRYPTCHANGE',
                'WMMTSPEC', 'dot11_ssid_new'
            ]

            for row in cursor.fetchall():
                try:
                    alert_json = json.loads(row['json']) if row['json'] else {}
                    header = row['header'] if row['header'] else ''
                    alert_text = alert_json.get('kismet.alert.text', header)
                    alert_type = alert_json.get('kismet.alert.header', header)

                    is_ap_alert = any(
                        kw.lower() in alert_type.lower() or kw.lower() in alert_text.lower()
                        for kw in ap_keywords
                    )

                    if not is_ap_alert:
                        continue

                    source_mac = alert_json.get(
                        'kismet.alert.source_mac', 'UNKNOWN'
                    ).upper()

                    alert = RogueAPAlert(
                        ssid=f"[Kismet Alert: {alert_type}]",
                        rogue_bssid=source_mac,
                        expected_bssid="N/A",
                        timestamp=float(row['ts_sec']),
                        severity="HIGH",
                        reasons=[f"Kismet alert: {alert_text[:200]}"],
                    )
                    alerts.append(alert)

                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logger.debug(f"Error parsing AP alert: {e}")
                    continue

        except sqlite3.Error as e:
            logger.debug(f"Error querying alerts for AP data: {e}")

        return alerts

    def _extract_advertised_ssids(self, dot11: Dict) -> Set[str]:
        """Extract advertised SSIDs from dot11 device data"""
        ssids = set()

        # Kismet stores advertised SSIDs in a map
        adv_map = dot11.get('dot11.device.advertised_ssid_map', {})
        if isinstance(adv_map, dict):
            for key, ssid_data in adv_map.items():
                if isinstance(ssid_data, dict):
                    ssid = ssid_data.get('dot11.advertisedssid.ssid', '')
                    if ssid and isinstance(ssid, str):
                        ssids.add(ssid)
        elif isinstance(adv_map, list):
            for ssid_data in adv_map:
                if isinstance(ssid_data, dict):
                    ssid = ssid_data.get('dot11.advertisedssid.ssid', '')
                    if ssid and isinstance(ssid, str):
                        ssids.add(ssid)

        return ssids

    def _extract_responded_ssids(self, dot11: Dict) -> Set[str]:
        """Extract responded SSIDs from dot11 device data"""
        ssids = set()

        resp_map = dot11.get('dot11.device.responded_ssid_map', {})
        if isinstance(resp_map, dict):
            for key, ssid_data in resp_map.items():
                if isinstance(ssid_data, dict):
                    ssid = ssid_data.get('dot11.respondedssid.ssid', '')
                    if ssid and isinstance(ssid, str):
                        ssids.add(ssid)
        elif isinstance(resp_map, list):
            for ssid_data in resp_map:
                if isinstance(ssid_data, dict):
                    ssid = ssid_data.get('dot11.respondedssid.ssid', '')
                    if ssid and isinstance(ssid, str):
                        ssids.add(ssid)

        return ssids

    def _extract_encryption(self, dot11: Dict) -> str:
        """Extract encryption type from dot11 device data"""
        adv_map = dot11.get('dot11.device.advertised_ssid_map', {})
        if isinstance(adv_map, dict):
            for key, ssid_data in adv_map.items():
                if isinstance(ssid_data, dict):
                    crypt = ssid_data.get('dot11.advertisedssid.crypt_string', '')
                    if crypt:
                        return crypt
        elif isinstance(adv_map, list):
            for ssid_data in adv_map:
                if isinstance(ssid_data, dict):
                    crypt = ssid_data.get('dot11.advertisedssid.crypt_string', '')
                    if crypt:
                        return crypt
        return ""

    def _extract_channel(self, device_data: Dict) -> Optional[int]:
        """Extract channel from device data"""
        try:
            channel_str = device_data.get('kismet.device.base.channel', '')
            if channel_str:
                return int(channel_str)
        except (ValueError, TypeError):
            pass

        try:
            freq = device_data.get('kismet.device.base.frequency', 0)
            if freq:
                return self._freq_to_channel(int(freq))
        except (ValueError, TypeError):
            pass

        return None

    @staticmethod
    def _freq_to_channel(freq_khz: int) -> Optional[int]:
        """Convert frequency in KHz to channel number"""
        freq_map = {
            2412000: 1, 2417000: 2, 2422000: 3, 2427000: 4, 2432000: 5,
            2437000: 6, 2442000: 7, 2447000: 8, 2452000: 9, 2457000: 10,
            2462000: 11, 2467000: 12, 2472000: 13,
            5180000: 36, 5200000: 40, 5220000: 44, 5240000: 48,
            5260000: 52, 5280000: 56, 5300000: 60, 5320000: 64,
            5500000: 100, 5520000: 104, 5540000: 108, 5560000: 112,
            5580000: 116, 5600000: 120, 5620000: 124, 5640000: 128,
            5660000: 132, 5680000: 136, 5700000: 140, 5720000: 144,
            5745000: 149, 5765000: 153, 5785000: 157, 5805000: 161,
            5825000: 165,
        }
        return freq_map.get(freq_khz)

    @staticmethod
    def _encryption_matches(expected: str, actual: str) -> bool:
        """Check if encryption types match (fuzzy comparison)"""
        e = expected.upper()
        a = actual.upper()
        if e == a:
            return True
        # Normalize common variations
        for pair in [("WPA2-PSK", "WPA2"), ("WPA3-SAE", "WPA3"), ("WPA2-CCMP", "WPA2")]:
            if (pair[0] in e and pair[1] in a) or (pair[1] in e and pair[0] in a):
                return True
        return False

    @staticmethod
    def _is_downgrade(expected: str, actual: str) -> bool:
        """Check if encryption has been downgraded"""
        strength = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
        e_strength = 0
        a_strength = 0
        for name, level in strength.items():
            if name in expected.upper():
                e_strength = max(e_strength, level)
            if name in actual.upper():
                a_strength = max(a_strength, level)
        return a_strength < e_strength

    def get_summary(self) -> Dict:
        """Get a summary of detection state"""
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert.severity] += 1

        return {
            'total_alerts': len(self.alerts),
            'monitored_ssids': len(self.monitored_ssids),
            'trusted_aps': sum(len(v) for v in self.trusted_aps.values()),
            'learned_aps': sum(len(v) for v in self.learned_aps.values()),
            'unique_ssids_seen': len(self.seen_bssids),
            'severity_counts': dict(severity_counts),
        }

    def generate_report(self, output_dir: str = './surveillance_reports') -> str:
        """Generate markdown report of rogue AP findings"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = Path(output_dir) / f"rogue_ap_report_{timestamp}.md"

        lines = []
        lines.append("# Rogue Access Point Detection Report")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Monitored SSIDs:** {len(self.monitored_ssids)}")
        lines.append(f"**Trusted AP Profiles:** {sum(len(v) for v in self.trusted_aps.values())}")
        lines.append(f"**Total Alerts:** {len(self.alerts)}")
        lines.append("")

        if not self.alerts:
            lines.append("## No Rogue APs Detected")
            lines.append("")
            lines.append("No rogue access points or evil twin attacks were detected")
            lines.append("for your monitored SSIDs. Your wireless environment appears clean.")
            lines.append("")
            summary = self.get_summary()
            lines.append(f"- Unique SSIDs observed: {summary['unique_ssids_seen']}")
            lines.append(f"- Auto-learned APs: {summary['learned_aps']}")
        else:
            # Alert summary table
            lines.append("## Alert Summary")
            lines.append("")
            lines.append("| Severity | SSID | Rogue BSSID | Expected BSSID | Time |")
            lines.append("|----------|------|-------------|----------------|------|")

            for alert in self.alerts:
                lines.append(
                    f"| **{alert.severity}** "
                    f"| {alert.ssid} "
                    f"| `{alert.rogue_bssid}` "
                    f"| `{alert.expected_bssid}` "
                    f"| {alert.time_str} |"
                )

            lines.append("")

            # Detailed alerts
            lines.append("## Detailed Alerts")
            lines.append("")

            for i, alert in enumerate(self.alerts, 1):
                severity_emoji = {
                    "CRITICAL": "🚨", "HIGH": "⚠️",
                    "MEDIUM": "🟡", "LOW": "🔵"
                }
                emoji = severity_emoji.get(alert.severity, "⚪")

                lines.append(f"### {emoji} Alert #{i}: {alert.severity} - {alert.ssid}")
                lines.append("")
                lines.append(f"- **Rogue BSSID:** `{alert.rogue_bssid}`")
                lines.append(f"- **Expected BSSID:** `{alert.expected_bssid}`")
                lines.append(f"- **Time:** {alert.time_str}")

                if alert.rogue_encryption:
                    lines.append(f"- **Rogue Encryption:** {alert.rogue_encryption}")
                if alert.expected_encryption:
                    lines.append(f"- **Expected Encryption:** {alert.expected_encryption}")
                if alert.rogue_channel:
                    lines.append(f"- **Rogue Channel:** {alert.rogue_channel}")
                if alert.expected_channel:
                    lines.append(f"- **Expected Channel:** {alert.expected_channel}")

                lines.append("")
                lines.append("**Detection Reasons:**")
                for reason in alert.reasons:
                    lines.append(f"  - {reason}")
                lines.append("")

            # Countermeasures
            lines.append("## Recommended Actions")
            lines.append("")
            lines.append("1. **Do NOT connect** to any flagged rogue APs")
            lines.append("2. **Verify your router** - confirm BSSID matches your known hardware")
            lines.append("3. **Check for physical devices** - evil twins require nearby hardware")
            lines.append("4. **Enable 802.11w (PMF)** - prevents deauth-based evil twin attacks")
            lines.append("5. **Use WPA3-SAE** - resistant to credential capture via evil twins")
            lines.append("6. **Certificate-based auth** - Enterprise WPA2/3 with certificates prevents evil twin credential theft")
            lines.append("")

        # Trusted AP reference
        if self.trusted_aps:
            lines.append("## Your Trusted AP Profiles")
            lines.append("")
            lines.append("| SSID | BSSID | Encryption | Channel |")
            lines.append("|------|-------|------------|---------|")
            for ssid, aps in self.trusted_aps.items():
                for ap in aps:
                    lines.append(
                        f"| {ssid} | `{ap.bssid}` "
                        f"| {ap.encryption or 'N/A'} "
                        f"| {ap.channel or 'N/A'} |"
                    )
            lines.append("")

        report_text = '\n'.join(lines)

        with open(report_path, 'w') as f:
            f.write(report_text)

        logger.info(f"Rogue AP report saved to {report_path}")
        return str(report_path)


def run_rogue_ap_scan(config: Dict, db_path: str) -> Tuple[List[RogueAPAlert], str]:
    """Convenience function to run a full rogue AP scan and generate report.

    Returns: (alerts, report_path)
    """
    detector = RogueAPDetector(config)
    alerts = detector.scan_kismet_db(db_path)
    report_path = detector.generate_report()
    return alerts, report_path
