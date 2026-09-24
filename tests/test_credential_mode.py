"""Credential test-mode guards.

The committed ``test_password_123`` must be reachable ONLY through an explicit
operator-set ``CYT_TEST_MODE=true`` environment variable. Nothing in the
codebase may enable it on the operator's behalf: neither at import time
(``cyt_gui`` used to force it before any import) nor when constructing tooling
(``SurveillanceAnalyzer`` used to force it in ``__init__``).
"""
import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secure_credentials import SecureCredentialManager

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_MODE_KEY = "CYT_TEST_MODE"


def _test_mode_env_writes(source: str) -> list:
    """Return line numbers that write the CYT_TEST_MODE environment key.

    Covers the regression shapes: ``anything['CYT_TEST_MODE'] = ...``,
    ``environ.setdefault('CYT_TEST_MODE', ...)``, ``environ.update(...)``,
    and ``os.putenv('CYT_TEST_MODE', ...)``. Comments/docstrings are ignored.
    """

    def is_test_mode_key(node):
        return isinstance(node, ast.Constant) and node.value == TEST_MODE_KEY

    def receiver_is_environ(func):
        recv = func.value
        return (isinstance(recv, ast.Name) and recv.id == "environ") or (
            isinstance(recv, ast.Attribute) and recv.attr == "environ")

    writes = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) and is_test_mode_key(target.slice):
                    writes.append(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (node.func.attr in ("setdefault", "update", "putenv")
                    and receiver_is_environ(node.func) and node.args
                    and is_test_mode_key(node.args[0])):
                writes.append(node.lineno)
    return writes


class TestDefaultPathNeverEnablesTestMode:
    def test_no_code_path_writes_test_mode_env(self):
        # These two modules historically wrote os.environ['CYT_TEST_MODE']
        # at import/init time; the AST guard blocks any such write returning.
        for name in ("cyt_gui.py", "surveillance_analyzer.py"):
            source = (REPO_ROOT / name).read_text()
            writes = _test_mode_env_writes(source)
            assert not writes, (
                f"{name} writes the {TEST_MODE_KEY} env var at lines {writes} "
                "— forced test mode regression"
            )

    def test_import_and_analyzer_init_leave_default_env_clean(self, tmp_path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("CYT_")}
        env["PYTHONPATH"] = str(REPO_ROOT)
        probe = (
            "import os\n"
            "import surveillance_analyzer\n"
            f"surveillance_analyzer.SurveillanceAnalyzer(config_path={str(REPO_ROOT / 'config.json')!r})\n"
            "print('CYT_TEST_MODE_SET=' + str(os.environ.get('CYT_TEST_MODE')))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True, text=True, cwd=str(tmp_path), env=env, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert "CYT_TEST_MODE_SET=None" in proc.stdout


class TestExplicitOptIn:
    def test_clean_env_fails_closed_without_test_password(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CYT_TEST_MODE", raising=False)
        monkeypatch.delenv("CYT_MASTER_PASSWORD", raising=False)
        monkeypatch.delenv("CYT_MASTER_PASSWORD_FILE", raising=False)
        monkeypatch.setattr("getpass.getpass", lambda *a, **k: (_ for _ in ()).throw(EOFError()))
        manager = SecureCredentialManager(credentials_dir=str(tmp_path / "creds"))

        with pytest.raises(RuntimeError):
            manager._get_master_password()

    def test_explicit_opt_in_still_works_with_loud_warning(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("CYT_TEST_MODE", "true")
        manager = SecureCredentialManager(credentials_dir=str(tmp_path / "creds"))

        assert manager._get_master_password() == "test_password_123"

        output = capsys.readouterr().out.upper()
        assert "WARNING" in output and "PUBLIC" in output
