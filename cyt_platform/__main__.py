"""CLI entry: python -m cyt_platform | cyt-analyzer"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    """The CLI parser, exposed for tests (docs-claim flag verification)."""
    parser = argparse.ArgumentParser(
        prog="cyt-analyzer",
        description="CYT EDC platform (P0–P3: service, trust, debrief, RF)",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help="Path to config.json (default: CYT_CONFIG or ./config.json)",
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="Validate config/store/kismet glob and exit",
    )
    parser.add_argument(
        "--repair-empty-store",
        action="store_true",
        help="If cyt.db is corrupt, rename and recreate empty schema",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Stop after N cycles (testing)",
    )
    parser.add_argument(
        "--legacy-loop",
        action="store_true",
        help="Run legacy chasing_your_tail loop without CytStore",
    )
    parser.add_argument(
        "--panic-wipe",
        action="store_true",
        help="Secure-erase store, seals, logs, status (requires --confirm YES)",
    )
    parser.add_argument(
        "--confirm",
        default="",
        help="Confirmation token for destructive ops (YES or WIPE)",
    )
    parser.add_argument(
        "--init-store-key",
        metavar="PATH",
        help="Generate a new 32-byte store key file (base64) at PATH",
    )
    parser.add_argument(
        "--led",
        action="store_true",
        help="Run LED/status glance consumer (polls status.json)",
    )
    parser.add_argument(
        "--led-once",
        action="store_true",
        help="Single LED update then exit",
    )
    parser.add_argument(
        "--debrief",
        nargs="?",
        const="TODAY",
        default=None,
        metavar="YYYY-MM-DD",
        help="Generate end-of-day debrief (default: today)",
    )
    parser.add_argument(
        "--push-flush",
        action="store_true",
        help="Attempt to deliver pending push queue items",
    )

    sub = parser.add_subparsers(dest="cmd")

    bl = sub.add_parser("baseline", help="Baseline list / mark / forget")
    bl_sub = bl.add_subparsers(dest="baseline_cmd")
    bl_sub.add_parser("list", help="List baseline entries")
    mk = bl_sub.add_parser("mark", help="Mark entity as baseline (or false positive)")
    mk.add_argument("--place", required=True)
    mk.add_argument("--type", dest="entity_type", default="wifi_mac")
    mk.add_argument("--key", required=True, help="MAC or SSID")
    mk.add_argument(
        "--false",
        action="store_true",
        help="Also set entity ignore (mark_false feedback)",
    )
    fg = bl_sub.add_parser("forget", help="Remove baseline entry")
    fg.add_argument("--place", required=True)
    fg.add_argument("--type", dest="entity_type", default="wifi_mac")
    fg.add_argument("--key", required=True)

    rp = sub.add_parser(
        "replay", help="Deterministically replay a labeled scenario session"
    )
    rp.add_argument(
        "--session", required=True, help="Path to scenario JSON document"
    )
    rp.add_argument(
        "--store-path",
        default=None,
        help="Directory for the replay store (default: temp dir, removed on exit)",
    )
    rp.add_argument(
        "--json-out",
        default=None,
        help="Write the replay report JSON to this path (default: stdout)",
    )

    ev = sub.add_parser(
        "eval",
        help="Run the labeled replay corpus and enforce the calibrated gates",
    )
    ev.add_argument(
        "--scenarios",
        default="scenarios/replay",
        help="Directory of labeled scenario JSON files (default: scenarios/replay)",
    )
    ev.add_argument(
        "--gates",
        default="eval/gates.json",
        help="Path to the calibrated gates document (default: eval/gates.json)",
    )
    ev.add_argument(
        "--json-out",
        default=None,
        help="Write the evaluation summary JSON to this path (default: stdout)",
    )

    def _config_flag(sp):
        # Accept -c on either side of the subcommand. SUPPRESS keeps the
        # parent's value when the subcommand form is absent.
        sp.add_argument(
            "-c",
            "--config",
            default=argparse.SUPPRESS,
            help="Path to config.json (same as the top-level flag)",
        )

    ex = sub.add_parser(
        "export",
        help="Export persisted observations as a replayable scenario (B6)",
    )
    ex.add_argument(
        "--out",
        default=None,
        help="Write the scenario JSON to this path (default: stdout)",
    )
    ex.add_argument(
        "--since",
        default=None,
        metavar="EPOCH_S",
        help="Only observations at/after this epoch second",
    )
    ex.add_argument(
        "--until",
        default=None,
        metavar="EPOCH_S",
        help="Only observations at/before this epoch second",
    )
    ex.add_argument(
        "--scenario-id",
        default=None,
        help="scenario_id for the exported document (default: export-<session>)",
    )
    _config_flag(ex)

    st = sub.add_parser(
        "status", help="One-glance system status (status.json + store counts)"
    )
    st.add_argument("--json", action="store_true", help="Machine-readable output")
    _config_flag(st)

    _doctor = sub.add_parser(
        "doctor", help="Per-check environment report (PASS/WARN/FAIL with detail)"
    )
    _config_flag(_doctor)

    cf = sub.add_parser("config", help="Configuration utilities")
    cf_sub = cf.add_subparsers(dest="config_cmd", required=True)
    cf_sub.add_parser("check", help="Validate the config file (key+reason+range errors)")

    inc = sub.add_parser("incident", help="Inspect and disposition incidents")
    inc_sub = inc.add_subparsers(dest="incident_cmd", required=True)
    inc_show = inc_sub.add_parser("show", help="Show one incident with its timeline")
    inc_show.add_argument("key", help="Incident key (see: cyt status)")
    inc_show.add_argument(
        "--json", action="store_true", help="Machine-readable output"
    )
    _config_flag(inc_show)
    for _verb, _verb_help in (
        ("dismiss", "Disposition as FALSE_POSITIVE (feeds baseline learning)"),
        ("confirm", "Disposition as KNOWN_DEVICE (your own device)"),
        ("resolve", "Disposition as RESOLVED (staleness close)"),
        ("reopen", "Re-open a terminal incident as NEW"),
    ):
        _inc = inc_sub.add_parser(_verb, help=_verb_help)
        _inc.add_argument("key", help="Incident key")
        _inc.add_argument(
            "--reason", default="", help="Why (recorded in the audit timeline)"
        )
        _inc.add_argument(
            "--json", action="store_true", help="Machine-readable output"
        )
        _config_flag(_inc)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.init_store_key:
        from pathlib import Path

        from cyt_platform.crypto import generate_key_file

        p = generate_key_file(Path(args.init_store_key))
        print(f"Wrote store key: {p} (mode 0600)")
        print("Set store.encryption.key_file or CYT_STORE_KEY_FILE to this path")
        print("Enable store.encryption.enabled=true in config")
        return 0

    if args.panic_wipe:
        from cyt_platform.config import load_json
        from cyt_platform.wipe import panic_wipe

        try:
            config = load_json(args.config)
        except Exception as e:
            print(f"Config error: {e}", file=sys.stderr)
            return 1
        try:
            result = panic_wipe(config, confirm=args.confirm)
        except ValueError as e:
            print(f"Refused: {e}", file=sys.stderr)
            return 1
        print(f"Panic wipe complete: {result}")
        return 0 if result.get("errors", 0) == 0 else 2

    if args.led or args.led_once:
        from cyt_platform.config import load_json
        from cyt_platform.led import run_led_loop

        config = load_json(args.config)
        return run_led_loop(config, once=bool(args.led_once))

    if args.debrief is not None:
        from cyt_platform.config import ensure_runtime_dirs, load_json
        from cyt_platform.debrief import generate_debrief
        from cyt_platform.privacy import apply_umask
        from cyt_platform.store import CytStore

        config = load_json(args.config)
        apply_umask(config)
        ensure_runtime_dirs(config)
        store = CytStore.open(config.get("store") or {})
        try:
            day = None if args.debrief == "TODAY" else args.debrief
            result = generate_debrief(store, config, day=day)
            print(result["markdown"])
            print(f"\n# wrote {result['path']}", file=sys.stderr)
            return 0
        finally:
            store.close()

    if args.push_flush:
        from cyt_platform.config import ensure_runtime_dirs, load_json
        from cyt_platform.privacy import apply_umask
        from cyt_platform.push import PushQueue
        from cyt_platform.store import CytStore

        config = load_json(args.config)
        apply_umask(config)
        ensure_runtime_dirs(config)
        store = CytStore.open(config.get("store") or {})
        try:
            q = PushQueue(store, config)
            with store.transaction():
                stats = q.flush()
            print(f"Push flush: {stats}")
            return 0
        finally:
            store.close()

    if args.cmd in ("status", "doctor", "config", "incident"):
        return _operator_cmd(args)

    if args.cmd == "replay":
        return _replay_cmd(args)

    if args.cmd == "export":
        return _export_cmd(args)

    if args.cmd == "eval":
        return _eval_cmd(args)

    if args.cmd == "baseline":
        return _baseline_cmd(args)

    if args.legacy_loop:
        from cyt_platform.legacy_loop import run_legacy_loop

        return run_legacy_loop()

    if args.self_check:
        from cyt_platform.service import self_check

        return self_check(args.config)

    from cyt_platform.service import run

    return run(
        args.config,
        repair_empty_store=args.repair_empty_store,
        max_cycles=args.max_cycles,
    )


def _eval_cmd(args) -> int:
    import json
    from pathlib import Path

    from cyt_platform.replay.evaluation import run_eval

    summary, code = run_eval(args.scenarios, args.gates)
    data = json.dumps(summary, indent=2, sort_keys=True).encode("utf-8")
    if args.json_out:
        Path(args.json_out).write_bytes(data)
        print(
            f"eval: {'GREEN' if code == 0 else 'RED'} "
            f"({summary.get('scenarios', 0)} scenarios) -> {args.json_out}",
            file=sys.stderr,
        )
    else:
        sys.stdout.buffer.write(data + b"\n")
    return code


def _export_cmd(args) -> int:
    """B6: persist observations -> v1 scenario document a replay can run."""
    import json
    from pathlib import Path

    from cyt_platform.privacy import apply_umask
    from cyt_platform.replay.scenario import scenario_from_observations
    from cyt_platform.store import CytStore

    config, err = _load_config_or_exit(args.config)
    if err:
        return err
    apply_umask(config)
    try:
        since = float(args.since) if args.since else None
        until = float(args.until) if args.until else None
    except ValueError:
        print("export: --since/--until must be epoch seconds", file=sys.stderr)
        return 2
    store = CytStore.open(config.get("store") or {})
    try:
        doc = scenario_from_observations(
            store,
            since_ts=since,
            until_ts=until,
            scenario_id=args.scenario_id,
        )
    finally:
        store.close()
    if not doc["cycles"]:
        print(
            "export: no observations in range — nothing to export",
            file=sys.stderr,
        )
        return 1
    data = json.dumps(doc, indent=2).encode("utf-8")
    if args.out:
        Path(args.out).write_bytes(data)
        print(f"export: wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(data + b"\n")
    return 0


def _replay_cmd(args) -> int:
    from pathlib import Path

    from cyt_platform.replay.engine import ReplayEngine
    from cyt_platform.replay.report import report_bytes
    from cyt_platform.replay.scenario import ScenarioError, load_scenario

    try:
        scenario = load_scenario(args.session)
    except ScenarioError as e:
        print(f"Scenario error: {e}", file=sys.stderr)
        return 2
    engine = ReplayEngine(
        scenario, store_path=Path(args.store_path) if args.store_path else None
    )
    data = report_bytes(engine.run())
    if args.json_out:
        Path(args.json_out).write_bytes(data)
    else:
        sys.stdout.buffer.write(data)
    return 0


def _baseline_cmd(args) -> int:
    from cyt_platform.baseline import BaselineEngine
    from cyt_platform.config import ensure_runtime_dirs, load_json
    from cyt_platform.privacy import apply_umask
    from cyt_platform.store import CytStore

    config = load_json(args.config)
    apply_umask(config)
    ensure_runtime_dirs(config)
    store = CytStore.open(config.get("store") or {})
    try:
        eng = BaselineEngine(store, config)
        if args.baseline_cmd == "list":
            rows = store.list_baselines()
            if not rows:
                print("(no baselines)")
                return 0
            for r in rows:
                print(
                    f"{r['place_id']:12} {r['entity_type']:10} "
                    f"src={r['source']:10} n={r['sighting_count']} key={r['entity_key']}"
                )
            return 0
        if args.baseline_cmd == "mark":
            source = "mark_false" if args.false else "manual"
            with store.transaction():
                eng.mark_manual(
                    args.place, args.entity_type, args.key, source=source
                )
            print(f"Marked {args.entity_type} for place={args.place} source={source}")
            return 0
        if args.baseline_cmd == "forget":
            with store.transaction():
                n = eng.forget(args.place, args.entity_type, args.key)
            print(f"Removed {n} baseline row(s)")
            return 0
        print("Usage: baseline list|mark|forget", file=sys.stderr)
        return 1
    finally:
        store.close()


# --- D10 operator surface: status / doctor / config check / incident ---------


def _load_config_or_exit(config_path):
    """Config errors are operator-facing: message + exit 1, no traceback."""
    from cyt_platform.config import ConfigError, load_json

    try:
        return load_json(config_path), None
    except ConfigError as e:
        print(f"Config error:\n{e}", file=sys.stderr)
        return None, 1
    except FileNotFoundError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return None, 1


def _operator_cmd(args) -> int:
    from cyt_platform.doctor import doctor as run_doctor

    if args.cmd == "status":
        return _status_cmd(args)
    if args.cmd == "doctor":
        return run_doctor(args.config)
    if args.cmd == "config":
        return _config_check_cmd(args)
    if args.cmd == "incident":
        return _incident_cmd(args)
    raise AssertionError(f"unhandled operator subcommand: {args.cmd}")


def _status_cmd(args) -> int:
    from pathlib import Path

    from cyt_platform.cli import load_json_result, print_status, status_report
    from cyt_platform.crypto import sealed_path_for
    from cyt_platform.privacy import apply_umask
    from cyt_platform.store import CytStore

    config, err = _load_config_or_exit(args.config)
    if config is None:
        return err
    apply_umask(config)
    logical = Path((config.get("store") or {}).get("path") or "data/cyt.db")
    if not logical.exists() and not sealed_path_for(logical).exists():
        print(f"no store yet at {logical} — the first service run creates it")
        return 0
    store = CytStore.open(config.get("store") or {})
    try:
        report = status_report(config, store)
    finally:
        store.close()
    if args.json:
        load_json_result(report)
    else:
        print_status(report)
    return 0


def _config_check_cmd(args) -> int:
    from cyt_platform.config import load_json

    try:
        load_json(args.config)
    except FileNotFoundError as e:
        print(f"config check: FAIL {e}")
        return 1
    except ValueError as e:  # ConfigError rides ValueError: key+reason+range
        print(f"config check: FAIL\n{e}")
        return 1
    print("config check: OK")
    return 0


def _incident_cmd(args) -> int:
    from cyt_platform.cli import (
        IncidentCliError,
        dispose,
        incident_detail,
        load_json_result,
        print_transition,
        reopen,
    )
    from cyt_platform.privacy import apply_umask, sanitize_error
    from cyt_platform.store import CytStore

    config, err = _load_config_or_exit(args.config)
    if config is None:
        return err
    apply_umask(config)
    try:
        store = CytStore.open(config.get("store") or {})
    except Exception as e:  # noqa: BLE001 - operator-facing
        print(f"error: cannot open store: {sanitize_error(e)}", file=sys.stderr)
        return 2
    try:
        if args.incident_cmd == "show":
            detail = incident_detail(store, args.key)
            if args.json:
                load_json_result(detail)
            else:
                print(f"incident {detail['incident_key']}")
                print(
                    f"  state: {detail['lifecycle_state']}  "
                    f"confidence: {detail['confidence']}  "
                    f"severity: {detail['severity']}"
                )
                print(f"  last_seen: {detail['last_seen']}")
                if detail.get("disposition"):
                    print(f"  disposition: {detail['disposition']}")
                for entry in detail["timeline"]:
                    print(
                        f"  [{entry['ts']:.0f}] {entry['from_state']} -> "
                        f"{entry['to_state']}: {entry['reason']}"
                    )
            return 0
        if args.incident_cmd == "reopen":
            result = reopen(store, args.key, args.reason)
        else:
            result = dispose(store, config, args.key, args.incident_cmd, args.reason)
        if args.json:
            load_json_result(result)
        else:
            print_transition(result)
        return 0
    except IncidentCliError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        # Illegal lifecycle moves raise InvalidTransition (a ValueError):
        # the operator sees the rule, not a traceback.
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
