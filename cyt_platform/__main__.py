"""CLI entry: python -m cyt_platform | cyt-analyzer"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
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

    if args.cmd == "baseline":
        return _baseline_cmd(args)

    if args.legacy_loop:
        from chasing_your_tail import run_legacy_loop

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


if __name__ == "__main__":
    sys.exit(main())
