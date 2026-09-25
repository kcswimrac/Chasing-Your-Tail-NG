"""Locked decision 2 guard: cyt_platform must never import quarantined code.

The quarantine moved the historical root-level tools under ``legacy/`` and
the shared runtime-role modules into the ``cyt_platform`` package. This suite
keeps that boundary honest:

- derives the quarantined-module set from ``legacy/`` itself, so quarantining
  a new module auto-arms the guard (no list to forget to update);
- parses every ``cyt_platform`` file as AST and rejects any ``import`` /
  ``from ... import`` (including lazy, function-level imports and dynamic
  ``import_module``-style string literals) that resolves to a quarantined
  module or the ``legacy`` package;
- pins the canonical homes of the modules the platform depends on, so a
  revert of the move fails loudly instead of silently re-creating flat
  root-level modules.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PLATFORM = REPO / "cyt_platform"
LEGACY = REPO / "legacy"

# Modules with a proven runtime role (locked decision 2): they moved INTO the
# package. The guard fails if they are ever found back at the repository root.
CANONICAL_MODULES = [
    "input_validation.py",
    "secure_database.py",
    "secure_ignore_loader.py",
    "secure_main_logic.py",
    "secure_credentials.py",
    "deauth_detector.py",
    "rogue_ap_detector.py",
    "legacy_loop.py",
]


def quarantined_stems() -> set[str]:
    """Every module name quarantined under legacy/, plus the package itself."""
    stems = {p.stem for p in LEGACY.glob("*.py") if p.stem != "__init__"}
    stems.add("legacy")
    return stems


def _import_roots(tree: ast.AST, package_parts: list[str]) -> set[str]:
    """Root names of every module an import statement could resolve to."""
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            level = node.level
            module = node.module or ""
            if level == 0:
                roots.add(module.split(".")[0])
            else:
                # Relative import: resolve the anchor from the file's package.
                base = package_parts[: len(package_parts) - (level - 1)]
                if module:
                    if base:
                        roots.add((base + module.split("."))[0])
                    else:
                        roots.add(module.split(".")[0])
                else:
                    # `from .. import x` — the imported names are the modules.
                    roots.update(alias.name.split(".")[0] for alias in node.names)
                    if base:
                        roots.add(base[0])
        elif isinstance(node, ast.Call):
            # Dynamic imports: import_module("x"), importlib.import_module("x"),
            # __import__("x"). Deliberately NOT any string literal — plain
            # strings like "ignore_list" are filenames/keys, not imports.
            func = node.func
            dynamic = (
                isinstance(func, ast.Name) and func.id == "__import__"
            ) or (
                isinstance(func, ast.Attribute) and func.attr in {"import_module", "__import__"}
            )
            if dynamic and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    roots.add(first.value.split(".")[0])
    return roots


def platform_files() -> list[tuple[Path, list[str]]]:
    files = []
    for path in sorted(PLATFORM.rglob("*.py")):
        rel = path.relative_to(REPO).with_suffix("")
        package_parts = list(rel.parts[:-1])
        files.append((path, package_parts))
    return files


def test_quarantine_directory_exists_with_readme():
    assert LEGACY.is_dir()
    assert (LEGACY / "README.md").is_file()


def test_quarantined_stem_set_is_populated():
    # Guards the guard: if legacy/ were ever emptied (or renamed), the
    # name-based checks below would silently verify nothing.
    stems = quarantined_stems() - {"legacy"}
    assert {"cyt_gui", "surveillance_analyzer", "gps_tracker", "probe_analyzer"} <= stems


@pytest.mark.parametrize("path,package_parts", platform_files(), ids=lambda p: str(p))
def test_platform_never_imports_quarantined_code(path: Path, package_parts: list[str]):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots = _import_roots(tree, package_parts)
    bad = sorted(roots & quarantined_stems())
    assert not bad, (
        f"{path.relative_to(REPO)} imports quarantined code {bad} — the "
        "platform must depend only on its own package (locked decision 2)"
    )


@pytest.mark.parametrize("name", CANONICAL_MODULES)
def test_runtime_modules_live_in_the_package(name: str):
    assert (PLATFORM / name).is_file(), f"canonical module missing: cyt_platform/{name}"
    assert not (REPO / name).is_file(), (
        f"{name} re-appeared at the repository root — flat root modules are "
        f"quarantined; the canonical home is cyt_platform/{name}"
    )


def test_legacy_entry_is_the_shim():
    shim = LEGACY / "chasing_your_tail.py"
    assert shim.is_file()
    source = shim.read_text(encoding="utf-8")
    # The shim must dispatch to the platform and keep the sentinel that
    # docs-claim tests verify.
    assert "cyt_platform.legacy_loop" in source
    assert '"--legacy-loop" in sys.argv' in source
    assert not (REPO / "chasing_your_tail.py").is_file()


def test_no_module_name_collides_between_platform_and_legacy():
    platform_stems = {p.stem for p in PLATFORM.glob("*.py")}
    legacy_stems = {p.stem for p in LEGACY.glob("*.py") if p.stem != "__init__"}
    colliding = sorted(platform_stems & legacy_stems)
    assert not colliding, f"module defined in both cyt_platform/ and legacy/: {colliding}"
