"""Credential migration guards.

Migration must secure credentials without first exposing them: it used to
write a plaintext ``config_backup.json`` containing every secret it had just
encrypted — a copy that survived panic wipe.
"""
import json
from pathlib import Path

import migrate_credentials
from secure_credentials import SecureCredentialManager

SECRET_TOKEN = "SECRET_WIGLE_TOKEN_AAA111"


def _write_config_with_secret(directory: Path) -> None:
    (directory / "config.json").write_text(json.dumps({
        "api_keys": {"wigle": {"encoded_token": SECRET_TOKEN}},
        "paths": {"log_dir": "logs"},
    }))


def test_migration_secures_without_plaintext_backup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CYT_MASTER_PASSWORD", "ci-master-password")
    monkeypatch.delenv("CYT_TEST_MODE", raising=False)
    _write_config_with_secret(tmp_path)

    migrate_credentials.main()

    # The plaintext backup must not be written — not now, not by any mode.
    assert not (tmp_path / "config_backup.json").exists()

    # The sanitized config carries no secrets.
    secure_config = json.loads((tmp_path / "config_secure.json").read_text())
    assert "api_keys" not in secure_config
    assert SECRET_TOKEN not in (tmp_path / "config_secure.json").read_text()


def test_migration_writes_secret_only_into_encrypted_store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CYT_MASTER_PASSWORD", "ci-master-password")
    monkeypatch.delenv("CYT_TEST_MODE", raising=False)
    _write_config_with_secret(tmp_path)

    migrate_credentials.main()

    # No file written BY the migration contains the plaintext secret; the
    # only plaintext copy left is the operator's own original config.json.
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.name != "config.json":
            assert SECRET_TOKEN not in path.read_text(errors="ignore"), (
                f"plaintext secret leaked into {path.name}"
            )

    # And the migration actually secured it: round-trip through the store.
    manager = SecureCredentialManager(credentials_dir=str(tmp_path / "secure_credentials"))
    assert manager.get_wigle_token() == SECRET_TOKEN
