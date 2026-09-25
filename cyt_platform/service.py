"""Headless analyzer service loop."""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from typing import Optional

from secure_database import SecureKismetDB

from cyt_platform import notify
from cyt_platform.baseline import BaselineEngine, resolve_place
from cyt_platform.config import ensure_runtime_dirs, load_json
from cyt_platform.health import ComponentFailureRegistry
from cyt_platform.kismet_resolve import KismetDbResolver
from cyt_platform.logging_setup import setup_logging
from cyt_platform.monitor_adapter import build_monitor
from cyt_platform.privacy import (
    apply_umask,
    log_fde_notice_if_needed,
    sanitize_error,
)
from cyt_platform.push import PushQueue
from cyt_platform.rf_plugins import RFPluginRunner
from cyt_platform.sinks.log_file import LogFileSink, NullSink
from cyt_platform.status import StatusEngine
from cyt_platform.store import CytStore
from cyt_platform.windows import (
    collect_window_sets,
    load_window_sets,
    merge_into_monitor,
    save_window_sets,
)

logger = logging.getLogger(__name__)

EX_CONFIG = 1
EX_STORE = 2
EX_TEMPFAIL = 75

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True
    logger.info("Shutdown signal %s received", signum)


def _kismet_proc_ok() -> bool:
    """Cheap process presence check (optional)."""
    try:
        # pgrep-like via /proc
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
                    if "kismet" in f.read().lower():
                        return True
            except OSError:
                continue
        return False
    except OSError:
        return False


def _sleep_remaining(interval: float, t0: float) -> None:
    elapsed = time.monotonic() - t0
    remaining = interval - elapsed
    # mid-cycle watchdog already handled; sleep in chunks for responsive SIGTERM
    end = time.monotonic() + max(0.0, remaining)
    while time.monotonic() < end and not _shutdown:
        time.sleep(min(1.0, end - time.monotonic()))
        notify.watchdog()


def run(
    config_path: Optional[str] = None,
    *,
    repair_empty_store: bool = False,
    max_cycles: Optional[int] = None,
) -> int:
    """
    Run the headless analyzer loop.
    Returns process exit code.
    """
    global _shutdown
    _shutdown = False

    try:
        config = load_json(config_path)
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        return EX_CONFIG

    apply_umask(config)
    ensure_runtime_dirs(config)
    log = setup_logging(config)
    log_fde_notice_if_needed(config, log)

    store_cfg = config.get("store") or {}
    enc = store_cfg.get("encryption") or {}
    if enc.get("enabled"):
        log.info("Store encryption enabled (sealed=%s field=%s)", enc.get("sealed", True), enc.get("field_encrypt", True))
    try:
        store = CytStore.open(store_cfg, repair=repair_empty_store)
    except Exception as e:
        log.error("Store open failed: %s", sanitize_error(e))
        return EX_STORE

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    session_id = store.begin_session()
    close_after = float((config.get("incidents") or {}).get("close_after_seconds") or 600)
    now = time.time()
    with store.transaction():
        closed = store.close_stale_incidents(now, close_after)
        if closed:
            log.info("Closed %s stale incidents at startup", closed)

    service_cfg = config.get("service") or {}
    if service_cfg.get("legacy_log_file"):
        log_sink = LogFileSink.create(config)
    else:
        log_sink = NullSink()

    baseline = BaselineEngine(store, config) if (config.get("baseline") or {}).get("enabled") else None
    place_id = resolve_place(config)
    if place_id:
        log.info("Current place: %s", place_id)
        store.set_runtime("current_place", place_id)

    monitor, deduper = build_monitor(
        config,
        store,
        session_id,
        log_sink=log_sink,
        baseline=baseline,
        place_id=place_id,
    )
    resolver = KismetDbResolver((config.get("paths") or {}).get("kismet_logs", "*.kismet"))
    status = StatusEngine(store, config)
    seal_every = int(store_cfg.get("seal_every_cycles") or 10)
    # D6: one failure registry per session — every detector and sensing
    # component reports into it, and status composition renders it.
    health_registry = ComponentFailureRegistry()
    rf = RFPluginRunner(store, config, registry=health_registry)
    push = PushQueue(store, config)
    prev_state = "fail"
    last_gps_place = place_id

    check_interval = float((config.get("timing") or {}).get("check_interval") or 60)
    list_update_interval = int(
        (config.get("timing") or {}).get("list_update_interval") or 5
    )
    basename_only = bool(
        (config.get("privacy") or {}).get("status_path_basename_only", True)
    )
    exit_on_fail = bool(service_cfg.get("exit_on_consecutive_fail", False))
    fail_threshold = int(service_cfg.get("consecutive_fail_threshold") or 5)
    check_proc = bool(service_cfg.get("kismet_proc_check", True))

    consecutive_fails = 0
    ready_sent = False
    cycle = 0

    log.info(
        "CYT analyzer starting session=%s check_interval=%s store=%s",
        session_id[:12],
        check_interval,
        store.path,
    )

    try:
        while not _shutdown:
            if max_cycles is not None and cycle >= max_cycles:
                break
            cycle += 1
            t0 = time.monotonic()
            try:
                db_path = resolver.resolve()
                kismet_label = os.path.basename(db_path) if basename_only else db_path
                monitor.current_kismet_db = kismet_label

                with SecureKismetDB(db_path, read_only=True) as kdb:
                    if not kdb.validate_connection():
                        raise RuntimeError("kismet_db_validation_failed")
                    freshness = kdb.capture_freshness(
                        recent_window_s=check_interval
                    )
                    if cycle == 1 or resolver.just_rolled:
                        log.info(
                            "Initializing tracking lists (cycle=%s just_rolled=%s)",
                            cycle,
                            resolver.just_rolled,
                        )
                        monitor.initialize_tracking_lists(kdb)
                        # D8: rehydrate window state persisted by a previous
                        # session — the capture DB may have rolled during the
                        # outage, and a follower must not get a 20-minute
                        # grace period on every restart.
                        try:
                            rehydrated = load_window_sets(store, now=time.time())
                            if rehydrated is not None:
                                merged = merge_into_monitor(monitor, rehydrated)
                                if merged:
                                    log.info(
                                        "Window rehydration: %s subjects carried "
                                        "over from previous session",
                                        merged,
                                    )
                        except Exception as we:
                            log.warning(
                                "Window rehydration skipped: %s",
                                sanitize_error(we),
                            )
                    monitor.process_current_activity(kdb)
                    if cycle % list_update_interval == 0:
                        monitor.rotate_tracking_lists(kdb)

                    # P2/P3 RF + GPS plugins (inside Kismet open)
                    rf_stats = {}
                    try:
                        with store.transaction():
                            rf_stats = rf.run_cycle(
                                kdb, db_path, recent_window_s=max(check_interval, 120)
                            )
                    except Exception as rfe:
                        # Total RF-plugin failure must be visible in status:
                        # never read clear while detectors are failing.
                        log.warning("RF plugins: %s", sanitize_error(rfe))
                        rf_stats = {
                            "detector_failures": {
                                "rf_runner": sanitize_error(rfe)
                            }
                        }

                now = time.time()
                # Place: config override, else GPS cluster as soft place id
                place_id = resolve_place(config)
                if not place_id and rf_stats.get("gps"):
                    g = rf_stats["gps"]
                    place_id = resolve_place(
                        config, lat=g.get("lat"), lon=g.get("lon"), now=now
                    )
                deduper.set_place(place_id)
                if place_id:
                    store.set_runtime("current_place", place_id)
                    # Write-only today: seeds the sticky last-known-place
                    # fallback (GPS dropout) arriving with the trust build.
                    last_gps_place = place_id  # noqa: F841

                with store.transaction():
                    deduper.flush()
                    store.close_stale_incidents(now, close_after)
                    store.write_heartbeat("analyzer", ok=True, cycle=cycle, detail="ok")
                    store.set_runtime("last_ok_ts", str(now))
                    store.set_runtime("last_kismet_db", kismet_label)
                    if rf_stats:
                        store.set_runtime("last_rf_stats", str(rf_stats))
                    if cycle % 10 == 0:
                        store.purge_retention(now)
                    if cycle % list_update_interval == 0:
                        # D8: snapshot window state on every rotation cadence
                        # so a crash loses at most one rotation of history.
                        save_window_sets(store, collect_window_sets(monitor), now)

                if cycle % 10 == 0:
                    try:
                        # D8: outside the transaction — incremental vacuum
                        # actually shrinks the file after purge.
                        store.vacuum_incremental()
                    except Exception as ve:
                        log.warning("Incremental vacuum skipped: %s", sanitize_error(ve))

                if seal_every > 0 and cycle % seal_every == 0:
                    try:
                        store.seal_now()
                    except Exception as se:
                        log.warning("Periodic seal failed: %s", sanitize_error(se))

                proc_ok = _kismet_proc_ok() if check_proc else None
                snapshot = status.publish(
                    cycle=cycle,
                    db_label=kismet_label,
                    freshness=freshness,
                    consecutive_fails=0,
                    analyzer_ok=True,
                    kismet_db_ok=True,
                    kismet_proc_ok=proc_ok,
                    detector_failures=rf_stats.get("detector_failures"),
                    component_registry=health_registry,
                )
                # P2 push on escalation transitions
                try:
                    cur_state = snapshot.get("state")
                    if cur_state in ("alert", "fail") and cur_state != prev_state:
                        with store.transaction():
                            push.enqueue_from_status(snapshot)
                    with store.transaction():
                        flush_stats = push.flush()
                    if flush_stats.get("sent"):
                        log.info("Push sent: %s", flush_stats)
                    prev_state = cur_state or prev_state
                except Exception as pe:
                    log.warning("Push path: %s", sanitize_error(pe))

                consecutive_fails = 0
                if not ready_sent:
                    notify.ready(status="first_cycle_ok")
                    ready_sent = True
                notify.watchdog()
                log.debug(
                    "Cycle %s ok in %.0fms rf=%s",
                    cycle,
                    (time.monotonic() - t0) * 1000,
                    rf_stats,
                )

            except Exception as e:
                consecutive_fails += 1
                now = time.time()
                detail = sanitize_error(e)
                log.error("Cycle %s error: %s", cycle, detail)
                try:
                    with store.transaction():
                        store.close_stale_incidents(now, close_after)
                        store.write_heartbeat(
                            "analyzer", ok=False, cycle=cycle, detail=detail
                        )
                except Exception as fe:
                    # D8: a failure-path store write (e.g. ENOSPC) must not
                    # escape the handler and kill the loop.
                    log.error(
                        "Cycle %s failure-path store write failed: %s",
                        cycle,
                        sanitize_error(fe),
                    )
                try:
                    status.publish_fail(
                        reason="analyzer_error",
                        consecutive_fails=consecutive_fails,
                        cycle=cycle,
                        db_label=getattr(resolver, "current", None)
                        and os.path.basename(resolver.current or "")
                        or "",
                    )
                except Exception as pe:
                    # D8 audit P0: publish_fail itself must never be the
                    # exception that parks the unit.
                    log.error(
                        "Cycle %s status publish failed: %s",
                        cycle,
                        sanitize_error(pe),
                    )
                notify.watchdog()
                if exit_on_fail and consecutive_fails >= fail_threshold:
                    log.error("Too many consecutive failures; exiting %s", EX_TEMPFAIL)
                    return EX_TEMPFAIL

            _sleep_remaining(check_interval, t0)

    finally:
        try:
            # D8: persist window state so the next boot rehydrates instead
            # of giving a follower a fresh 20-minute grace period.
            save_window_sets(store, collect_window_sets(monitor), time.time())
        except Exception:
            pass
        try:
            with store.transaction():
                store.write_heartbeat(
                    "analyzer", ok=True, cycle=cycle, detail="shutting_down"
                )
        except Exception:
            pass
        try:
            log_sink.close()
        except Exception:
            pass
        notify.stopping()
        store.close()
        log.info("CYT analyzer stopped cleanly")

    return 0


def self_check(config_path: Optional[str] = None) -> int:
    """Validate config, store open, optional kismet glob — no long loop."""
    try:
        config = load_json(config_path)
    except Exception as e:
        print(f"FAIL config: {e}")
        return EX_CONFIG
    apply_umask(config)
    ensure_runtime_dirs(config)
    try:
        store = CytStore.open(config.get("store") or {})
        sid = store.begin_session()
        inputs = store.get_status_inputs(300)
        store.close()
        print(f"OK store session={sid[:8]}... watch_open={inputs.watch_open}")
    except Exception as e:
        print(f"FAIL store: {sanitize_error(e)}")
        return EX_STORE

    pattern = (config.get("paths") or {}).get("kismet_logs")
    try:
        path = KismetDbResolver(pattern).resolve()
        print(f"OK kismet_db={os.path.basename(path)}")
    except FileNotFoundError:
        print(f"WARN kismet_db: no files matching {pattern}")
    except Exception as e:
        print(f"WARN kismet_db: {sanitize_error(e)}")

    print("OK self-check complete")
    return 0
