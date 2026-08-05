"""KismetDbResolver rollover flag tests."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cyt_platform.kismet_resolve import KismetDbResolver


def test_empty_glob_raises(tmp_path: Path):
    r = KismetDbResolver(str(tmp_path / "none" / "*.kismet"))
    with pytest.raises(FileNotFoundError):
        r.resolve()
    assert r.just_rolled is False


def test_just_rolled_one_cycle(tmp_path: Path):
    a = tmp_path / "a.kismet"
    b = tmp_path / "b.kismet"
    a.write_text("x")
    time.sleep(0.02)
    b.write_text("y")
    pattern = str(tmp_path / "*.kismet")
    r = KismetDbResolver(pattern)
    p1 = r.resolve()
    assert p1.endswith("b.kismet")
    assert r.just_rolled is True
    p2 = r.resolve()
    assert p2 == p1
    assert r.just_rolled is False

    # rollover: newer file
    time.sleep(0.02)
    c = tmp_path / "c.kismet"
    c.write_text("z")
    p3 = r.resolve()
    assert p3.endswith("c.kismet")
    assert r.just_rolled is True
