"""MatchEvent hooks + MAC case normalization."""

from __future__ import annotations

from secure_main_logic import MatchEvent, SecureCYTMonitor


class _Sink:
    def write(self, t: str) -> None:
        pass


def test_mac_case_normalized_match():
    events = []
    mon = SecureCYTMonitor(
        {"timing": {"time_windows": {"recent": 5, "medium": 10, "old": 15, "oldest": 20}}},
        ignore_list=[],
        ssid_ignore_list=[],
        log_file=_Sink(),
        on_match=events.append,
    )
    mon.five_ten_min_ago_macs = {"AA:BB:CC:DD:EE:FF"}
    mon.current_kismet_db = "test.kismet"
    mon._process_mac_tracking("aa:bb:cc:dd:ee:ff")
    assert len(events) == 1
    assert events[0].kind == "mac_reappear"
    assert events[0].subject == "AA:BB:CC:DD:EE:FF"
    assert events[0].window == "5-10"
    assert events[0].kismet_db == "test.kismet"


def test_ssid_hook():
    events = []
    mon = SecureCYTMonitor(
        {"timing": {"time_windows": {"recent": 5, "medium": 10, "old": 15, "oldest": 20}}},
        ignore_list=[],
        ssid_ignore_list=[],
        log_file=_Sink(),
        on_match=events.append,
    )
    mon.ten_fifteen_min_ago_ssids = {"CoffeeShop"}
    mon._check_ssid_history("CoffeeShop", source_mac="11:22:33:44:55:66")
    assert len(events) == 1
    assert events[0].kind == "ssid_probe_repeat"
    assert events[0].source_mac == "11:22:33:44:55:66"


def test_no_hook_legacy_safe():
    mon = SecureCYTMonitor(
        {"timing": {"time_windows": {"recent": 5, "medium": 10, "old": 15, "oldest": 20}}},
        ignore_list=[],
        ssid_ignore_list=[],
        log_file=_Sink(),
    )
    mon.five_ten_min_ago_macs = {"AA:BB:CC:DD:EE:FF"}
    mon._process_mac_tracking("AA:BB:CC:DD:EE:FF")  # should not raise
