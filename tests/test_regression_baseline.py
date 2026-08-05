"""Regression baseline from design Issue 16 — structural claims."""

from __future__ import annotations

import inspect
from pathlib import Path

import chasing_your_tail
import secure_database
import secure_main_logic
from secure_main_logic import MatchEvent, SecureCYTMonitor


def test_match_event_lives_in_secure_main_logic():
    assert MatchEvent.__module__ == "secure_main_logic"


def test_secure_kismet_supports_read_only():
    sig = inspect.signature(secure_database.SecureKismetDB.__init__)
    assert "read_only" in sig.parameters


def test_capture_freshness_exists():
    assert hasattr(secure_database.SecureKismetDB, "capture_freshness")


def test_on_match_optional():
    sig = inspect.signature(SecureCYTMonitor.__init__)
    assert "on_match" in sig.parameters


def test_platform_package_present():
    root = Path(__file__).resolve().parent.parent
    assert (root / "cyt_platform" / "service.py").is_file()
    assert (root / "pyproject.toml").is_file()


def test_chasing_entry_prefers_platform():
    src = inspect.getsource(chasing_your_tail.main)
    assert "platform_main" in src or "cyt_platform" in src
