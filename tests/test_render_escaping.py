"""Render-sink escaping tests: RF-sourced text must render inert at every sink.

SSIDs, MACs, probe strings, and alert text are read off the air and are fully
attacker-controlled. These tests push adversarial fixtures through the KML,
markdown, and pandoc-bound HTML render paths and assert nothing executable or
markup-bearing survives.

Acceptance fixtures (task AC-1): `<script>` tags, `]]>` sequences, `[link](x)`
markdown links.
"""
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from gps_tracker import GPSTracker, KMLExporter
from cyt_platform.input_validation import InputValidator
from surveillance_detector import (
    DeviceAppearance,
    SurveillanceDetector,
    SuspiciousDevice,
)

EVIL_SCRIPT = "<script>alert(1)</script>"
EVIL_CDATA = "never]]>gone"
EVIL_LINK = "[link](https://evil.example)"

HOSTILE_SESSION = EVIL_CDATA  # location/session names reach KML <name> + CDATA


def _appearance(mac: str, ts: float, location_id: str) -> DeviceAppearance:
    return DeviceAppearance(
        mac=mac,
        timestamp=ts,
        location_id=location_id,
        ssids_probed=[EVIL_SCRIPT, EVIL_LINK],
    )


def _work_hour_timestamps(count: int, start_hour: int = 10) -> list:
    base = datetime(2025, 9, 24, start_hour, 0, 0).timestamp()
    return [base + i * 3600 for i in range(count)]


def _hostile_devices(session_ids: list) -> list:
    """Two suspicious devices whose MACs, reasons, and probes are all hostile."""
    ts = _work_hour_timestamps(4)
    d1 = SuspiciousDevice(
        mac=EVIL_SCRIPT,
        persistence_score=0.95,
        appearances=[_appearance(EVIL_SCRIPT, ts[i], session_ids[i % len(session_ids)])
                     for i in range(len(ts))],
        reasons=[EVIL_CDATA, EVIL_LINK, EVIL_SCRIPT],
        first_seen=datetime.fromtimestamp(ts[0]),
        last_seen=datetime.fromtimestamp(ts[-1]),
        total_appearances=len(ts),
        locations_seen=list(session_ids),
    )
    d2 = SuspiciousDevice(
        mac=EVIL_LINK,
        persistence_score=0.85,
        appearances=[_appearance(EVIL_LINK, ts[i], session_ids[i % len(session_ids)])
                     for i in range(len(ts))],
        reasons=[EVIL_LINK],
        first_seen=datetime.fromtimestamp(ts[0]),
        last_seen=datetime.fromtimestamp(ts[-1]),
        total_appearances=len(ts),
        locations_seen=list(session_ids),
    )
    return [d1, d2]


def _tracker_with_hostile_sessions() -> GPSTracker:
    tracker = GPSTracker({})
    tracker.add_gps_reading(33.4484, -112.0740, location_name=EVIL_SCRIPT + EVIL_CDATA)
    tracker.add_device_at_current_location(EVIL_SCRIPT)
    tracker.add_gps_reading(33.5076, -112.0726, location_name=EVIL_CDATA)
    tracker.add_device_at_current_location(EVIL_LINK)
    return tracker


class TestEscapeHelpers:
    @pytest.mark.parametrize("evil", [EVIL_SCRIPT, EVIL_CDATA, EVIL_LINK])
    def test_xml_text_escaping_is_markup_inert(self, evil):
        out = InputValidator.escape_xml_text(evil)
        assert "<" not in out and ">" not in out

    @pytest.mark.parametrize("evil", [EVIL_SCRIPT, EVIL_CDATA, EVIL_LINK])
    def test_cdata_escaping_is_markup_inert(self, evil):
        out = InputValidator.escape_cdata_html(evil)
        assert "<" not in out and ">" not in out
        # A hostile ']]>' must never survive literally (CDATA breakout).
        assert "]]>" not in out

    @pytest.mark.parametrize("evil", [EVIL_SCRIPT, EVIL_CDATA, EVIL_LINK])
    def test_markdown_escaping_is_markup_inert(self, evil):
        out = InputValidator.escape_markdown_text(evil)
        assert EVIL_SCRIPT not in out
        assert "[link](" not in out
        assert "]]>" not in out


class TestKmlSink:
    def test_hostile_rf_text_renders_inert(self, tmp_path):
        tracker = _tracker_with_hostile_sessions()
        devices = _hostile_devices([s.session_id for s in tracker.location_sessions])
        out_file = tmp_path / "hostile.kml"

        kml = KMLExporter().generate_kml(tracker, devices, str(out_file))

        # Document must still be well-formed XML — no CDATA breakout, no
        # injected elements. (Compare exact local tag names: 'description'
        # contains 'script' as a substring.)
        root = ET.fromstring(kml)
        assert not any(elem.tag.rsplit("}", 1)[-1].lower() == "script" for elem in root.iter())
        for evil in (EVIL_SCRIPT, EVIL_CDATA):
            assert evil not in kml
        # EVIL_LINK renders as inert literal text inside CDATA (markdown link
        # syntax is not HTML), so its literal presence there is harmless.
        assert InputValidator.escape_xml_text(EVIL_SCRIPT) in kml
        assert out_file.exists() and EVIL_SCRIPT not in out_file.read_text()


class TestMarkdownReportSink:
    def test_hostile_rf_text_renders_inert(self, tmp_path):
        detector = SurveillanceDetector({})
        report = tmp_path / "report.md"

        with patch.object(detector, "analyze_surveillance_patterns",
                          return_value=_hostile_devices([HOSTILE_SESSION, "Location_1"])):
            detector.generate_surveillance_report(str(report))

        text = report.read_text()
        for evil in (EVIL_SCRIPT, EVIL_CDATA, EVIL_LINK):
            assert evil not in text
        # Escaped forms render literally instead of executing.
        assert "\\[link\\]" in text
        assert "\\<script\\>" in text


class TestHtmlReportSink:
    def test_pandoc_input_and_output_render_hostile_rf_text_inert(self, tmp_path):
        detector = SurveillanceDetector({})
        report = tmp_path / "report.md"
        html = tmp_path / "report.html"

        with patch.object(detector, "analyze_surveillance_patterns",
                          return_value=_hostile_devices([HOSTILE_SESSION, "Location_1"])):
            detector.generate_surveillance_report(str(report))

        # The markdown file is the exact input pandoc converts to HTML: no raw
        # HTML-bearing or link-bearing fixture may reach it.
        md_text = report.read_text()
        assert "<script>alert" not in md_text
        assert "[link](" not in md_text

        # When pandoc is available, the produced HTML must be equally inert.
        if html.exists():
            html_text = html.read_text()
            assert "<script" not in html_text.lower()
            assert EVIL_SCRIPT not in html_text
            assert 'href="https://evil.example"' not in html_text


class TestRenderSourcesGuard:
    """Grep-style guard: no unwrapped RF-attribute interpolation may return to
    the render templates."""

    RAW_INTERPOLATIONS = (
        "{device.mac}",
        "{device1.mac}",
        "{device2.mac}",
        "{session.session_id}",
        "{appearance.location_id}",
        "{location}",
        "{loc}</li>",
        "f\"• {mac}\"",
        "f\"• {reason}\"",
        "f\"<li>{reason}</li>\"",
        "join(device.locations_seen)",
        "join(hotspot_locations)",
        "join(common_locations)",
        "join(app.ssids_probed)",
    )

    def test_no_unescaped_rf_interpolation_on_render_paths(self):
        repo_root = Path(__file__).resolve().parents[1]
        # gps_tracker.py / surveillance_detector.py are quarantined under
        # legacy/ — the escaping invariant follows the files there.
        for name in ("legacy/gps_tracker.py", "legacy/surveillance_detector.py"):
            source = (repo_root / name).read_text()
            for pattern in self.RAW_INTERPOLATIONS:
                assert pattern not in source, f"{name}: unescaped RF interpolation {pattern!r}"
