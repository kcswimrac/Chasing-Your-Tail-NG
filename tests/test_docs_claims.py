"""D10 docs re-trace: every flag, path, and command the README claims
must exist and respond.

The credibility claim starts at the README. This suite:
- extracts shell commands from README bash blocks and parses every
  `python -m cyt_platform` / `cyt` invocation against the REAL argparse
  parser (parse-only — no handler execution);
- runs `--help` on legacy scripts and asserts each README-claimed flag
  appears (surveillance_analyzer, probe_analyzer);
- asserts every repo file the README references exists;
- pins regression guards over the claims that used to lie
  (--min-persistence, legacy/create_ignore_list.py, archive dirs,
  Python 3.6+).
"""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from cyt_platform.__main__ import build_parser

REPO = Path(__file__).resolve().parent.parent
README = (REPO / "README.md").read_text(encoding="utf-8")

# Repo files the README references as paths (post-quarantine locations:
# runtime-role modules live in cyt_platform/, archived tools under legacy/).
# Runtime outputs (status.json, cyt.db, debrief logs, ignore_lists/*.json)
# are created on first run and deliberately not listed here.
README_PATHS = [
    "requirements.txt",
    "legacy/migrate_credentials.py",
    "legacy/chasing_your_tail.py",
    "legacy/cyt_gui.py",
    "config.json",
    "config.edc.json",
    "legacy/create_ignore_list.py",
    "deploy/FIELD_DEPLOY.md",
    "docs/EDC_PLATFORM_DESIGN.md",
    "eval/gates.json",
    "legacy/gps_tracker.py",
    "cyt_platform/input_validation.py",
    "legacy/probe_analyzer.py",
    "scenarios/replay/commute-quiet.json",
    "cyt_platform/secure_credentials.py",
    "cyt_platform/secure_database.py",
    "cyt_platform/secure_ignore_loader.py",
    "cyt_platform/secure_main_logic.py",
    "legacy/start_kismet_clean.sh",
    "legacy/surveillance_analyzer.py",
    "legacy/surveillance_detector.py",
]

# Legacy scripts with real argparse: README flags are verified against
# --help output (safe: argparse exits before any analysis runs).
HELP_VERIFIED_SCRIPTS = {
    "legacy/surveillance_analyzer.py",
}
# probe_analyzer.py builds its parser only AFTER config/log discovery
# (with no logs it exits before argparse), so --help cannot list flags.
# Its README claims are verified against the declared add_argument set.
SOURCE_VERIFIED_SCRIPTS = {
    "legacy/probe_analyzer.py",
}


def readme_bash_commands() -> list[str]:
    """Shell commands inside README fenced bash blocks (continuation-joined)."""
    commands: list[str] = []
    for block in re.findall(r"```bash\n(.*?)```", README, re.DOTALL):
        joined: list[str] = []
        for raw in block.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith("\\"):
                joined.append(line[:-1].strip())
                continue
            joined.append(line)
            # Strip trailing inline comments the way bash would (# after
            # whitespace); quoted values in this README never contain ' #'.
            commands.append(re.sub(r"\s#.*$", "", " ".join(joined)))
            joined.clear()
    return commands


def test_readme_parses_into_commands():
    # Guard the extractor: the README must yield a healthy command list,
    # otherwise the tests below would silently verify nothing.
    cmds = readme_bash_commands()
    assert len(cmds) >= 15, cmds


def cyt_platform_tokens(cmd: str) -> list[str] | None:
    """Tokens after the entry point for cyt_platform/cyt invocations."""
    tokens = shlex.split(cmd)
    if tokens[:3] in (["python", "-m", "cyt_platform"], ["python3", "-m", "cyt_platform"]):
        return tokens[3:]
    if tokens and tokens[0] == "cyt":
        return tokens[1:]
    return None


@pytest.mark.parametrize("cmd", readme_bash_commands(), ids=lambda cmd: cmd[:60])
def test_readme_cyt_commands_parse_against_real_parser(cmd: str):
    tokens = cyt_platform_tokens(cmd)
    if tokens is None:
        return  # not a cyt_platform command (pip, venv, GUI, ...)
    parser = build_parser()
    try:  # parse-only: handlers never run
        parser.parse_args(tokens)
    except SystemExit as exc:  # argparse rejects the documented form
        pytest.fail(f"README documents a command the CLI rejects: {cmd!r} ({exc})")


@pytest.mark.parametrize(
    "script",
    sorted(HELP_VERIFIED_SCRIPTS),
)
def test_readme_flags_exist_in_script_help(script: str):
    claimed: set[str] = set()
    for cmd in readme_bash_commands():
        tokens = shlex.split(cmd)
        if len(tokens) >= 2 and tokens[0] == "python3" and tokens[1] == script:
            claimed.update(t for t in tokens[2:] if t.startswith("--"))
    assert claimed, f"no flags claimed for {script} in README"
    out = subprocess.run(
        [sys.executable, str(REPO / script), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    missing = [f for f in sorted(claimed) if f not in out.stdout]
    assert not missing, f"README claims flags that --help does not list: {missing}"


@pytest.mark.parametrize(
    "script",
    sorted(SOURCE_VERIFIED_SCRIPTS),
)
def test_readme_flags_declared_in_script_source(script: str):
    claimed: set[str] = set()
    for cmd in readme_bash_commands():
        tokens = shlex.split(cmd)
        if len(tokens) >= 2 and tokens[0] == "python3" and tokens[1] == script:
            claimed.update(t for t in tokens[2:] if t.startswith("--"))
    assert claimed, f"no flags claimed for {script} in README"
    source = (REPO / script).read_text(encoding="utf-8")
    declared = set(re.findall(r"add_argument\('(--[a-z-]+)'", source))
    missing = sorted(claimed - declared)
    assert not missing, f"README claims flags the script does not declare: {missing}"


def test_readme_legacy_loop_sentinel_exists():
    # Quarantined chasing_your_tail.py dispatches --legacy-loop via sys.argv
    # membership (no argparse), so help-text verification does not apply.
    source = (REPO / "legacy" / "chasing_your_tail.py").read_text(encoding="utf-8")
    assert '"--legacy-loop" in sys.argv' in source


@pytest.mark.parametrize("path", README_PATHS)
def test_readme_referenced_paths_exist(path: str):
    assert (REPO / path).exists(), f"README references a missing path: {path}"


# --- regression guards over claims that used to lie -------------------------


@pytest.mark.parametrize(
    "stale",
    [
        "--min-persistence",
        "old_scripts/",
        "docs_archive/",
        "Python 3.6+",
    ],
)
def test_readme_no_longer_carries_known_stale_claims(stale: str):
    # "legacy/create_ignore_list.py" was removed from this list when the
    # quarantine PR moved the tool to exactly that path: the claim stopped
    # being stale (it used to reference a directory that did not exist).
    assert stale not in README


def test_readme_python_version_matches_pyproject():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'requires-python\s*=\s*">=(\d+\.\d+)"', pyproject)
    assert match, "pyproject must pin requires-python"
    assert f"Python {match.group(1)}+" in README


def test_readme_documents_the_operator_cli():
    # The D10 surface must be discoverable from the README.
    for fragment in ("cyt status", "cyt doctor", "cyt config check",
                     "cyt incident", "cyt replay", "cyt eval"):
        assert fragment in README
