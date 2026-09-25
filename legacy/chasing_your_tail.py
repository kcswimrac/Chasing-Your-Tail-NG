#!/usr/bin/env python3
### Chasing Your Tail — historical entry point (quarantined)
###
### Legacy quarantine (locked decision 2): the actual loop lives in
### ``cyt_platform/legacy_loop.py``; this shim keeps the historical command
### working from a source checkout. Default dispatch is the headless EDC
### platform; ``--legacy-loop`` runs the original in-memory loop.

import sys
from pathlib import Path

# Source-checkout bootstrap: make the repo-root cyt_platform package
# importable when this script is run directly (a `pip install -e .` checkout
# does not need this, but the historical command must not require one).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyt_platform.legacy_loop import run_legacy_loop


def main() -> int:
    if "--legacy-loop" in sys.argv:
        return run_legacy_loop()
    # Prefer headless EDC platform
    from cyt_platform.__main__ import main as platform_main

    # Strip our own re-entry flag if present; platform argparse handles the rest
    argv = [a for a in sys.argv[1:] if a != "--legacy-loop"]
    return platform_main(argv)


if __name__ == "__main__":
    sys.exit(main() or 0)
