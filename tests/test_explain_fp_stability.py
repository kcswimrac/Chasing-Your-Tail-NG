"""S5: window-match subject fingerprints must be restart-stable.

``explain._fp`` once used CPython's salted ``hash()``, so the same MAC
produced a different ``subject_fp`` after every process restart. The
fingerprint is the cross-restart correlation reference — it must come from
``detectors.subject_fingerprint`` and be identical across hash seeds.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

SCRIPT = "from cyt_platform.explain import _fp; print(_fp('AA:BB:CC:DD:EE:01'))"


def _fp_under_seed(seed: str) -> str:
    env = dict(os.environ, PYTHONHASHSEED=seed)
    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        check=True,
    )
    return proc.stdout.strip()


def test_fingerprint_stable_across_hash_seeds():
    first = _fp_under_seed("11")
    second = _fp_under_seed("22")
    assert first == second
    assert first != ""


def test_fingerprint_is_a_stable_hex_reference():
    value = _fp_under_seed("0")
    int(value, 16)  # parses as hex
