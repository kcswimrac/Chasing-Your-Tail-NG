"""Wire SecureCYTMonitor.on_match → IncidentDeduper (+ baseline)."""

from __future__ import annotations

from typing import Optional, TextIO, Union

from secure_ignore_loader import SecureIgnoreLoader
from secure_main_logic import SecureCYTMonitor

from cyt_platform.baseline import BaselineEngine, resolve_place
from cyt_platform.config import ignore_list_paths
from cyt_platform.incidents import IncidentDeduper
from cyt_platform.sinks.log_file import LogFileSink, NullSink
from cyt_platform.store import CytStore


def build_monitor(
    config: dict,
    store: CytStore,
    session_id: str,
    log_sink: Optional[Union[LogFileSink, NullSink, TextIO]] = None,
    baseline: Optional[BaselineEngine] = None,
    place_id: Optional[str] = None,
) -> tuple[SecureCYTMonitor, IncidentDeduper]:
    mac_path, ssid_path = ignore_list_paths(config)
    loader = SecureIgnoreLoader()
    macs = loader.load_mac_list(mac_path)
    ssids = loader.load_ssid_list(ssid_path)

    status_cfg = config.get("status") or {}
    window_map = status_cfg.get("window_to_severity") or {
        "5-10": "watch",
        "10-15": "watch",
        "15-20": "alert",
    }
    if baseline is None and (config.get("baseline") or {}).get("enabled"):
        baseline = BaselineEngine(store, config)
    if place_id is None:
        place_id = resolve_place(config)

    deduper = IncidentDeduper(
        store,
        config.get("incidents") or {},
        session_id=session_id,
        window_to_severity=window_map,
        baseline=baseline,
        place_id=place_id,
    )
    sink = log_sink if log_sink is not None else NullSink()
    monitor = SecureCYTMonitor(
        config,
        macs,
        ssids,
        sink,
        on_match=deduper.handle_match,
    )
    return monitor, deduper
