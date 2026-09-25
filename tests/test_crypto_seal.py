"""Sealed store encryption + field crypto tests."""

from __future__ import annotations

import base64
import secrets
import time
from pathlib import Path

import pytest


from conftest import escalate_lifecycle
from cyt_platform.crypto import (
    CryptoError,
    StoreKey,
    generate_key_file,
    load_key_from_file,
    seal_file,
    unseal_file,
)
from cyt_platform.store import CytStore


def test_seal_unseal_roundtrip(tmp_path: Path):
    key_path = tmp_path / "k.bin"
    generate_key_file(key_path)
    from cyt_platform.crypto import load_key_from_file

    key = StoreKey(load_key_from_file(key_path))
    plain = tmp_path / "f.db"
    plain.write_bytes(b"sqlite-bytes-hello")
    sealed = tmp_path / "f.db.sealed"
    seal_file(plain, sealed, key)
    out = tmp_path / "out.db"
    unseal_file(sealed, out, key)
    assert out.read_bytes() == b"sqlite-bytes-hello"


def test_encrypted_store_open_close(tmp_path: Path):
    key_path = tmp_path / "store.key"
    generate_key_file(key_path)
    # use runtime next to data (no /dev/shm dependency in CI)
    cfg = {
        "path": str(tmp_path / "cyt.db"),
        "mode": "durable",
        "encryption": {
            "enabled": True,
            "sealed": True,
            "field_encrypt": True,
            "key_file": str(key_path),
            "runtime_dir": str(tmp_path / "rt"),
        },
    }
    store = CytStore.open(cfg)
    sid = store.begin_session()
    with store.transaction():
        escalate_lifecycle(
            store,
            "AA:BB:CC:DD:EE:FF",
            time.time(),
            "alert",
            session_id=sid,
        )
    store.close()

    sealed = Path(str(tmp_path / "cyt.db") + ".sealed")
    assert sealed.is_file()
    # plaintext runtime should be shredded
    assert not (tmp_path / "rt" / "cyt.db").exists()

    # reopen
    store2 = CytStore.open(cfg)
    inputs = store2.get_status_inputs(300)
    assert inputs.alert_open == 1
    store2.close()


def test_field_encrypt_hides_plaintext_mac(tmp_path: Path):
    key_path = tmp_path / "store.key"
    generate_key_file(key_path)
    cfg = {
        "path": str(tmp_path / "cyt.db"),
        "mode": "durable",
        "encryption": {
            "enabled": True,
            "sealed": False,  # keep open file for inspection
            "field_encrypt": True,
            "key_file": str(key_path),
        },
    }
    store = CytStore.open(cfg)
    with store.transaction():
        store.upsert_entity("wifi_mac", "AA:BB:CC:DD:EE:01", time.time())
    row = store.conn.execute("SELECT key FROM entities").fetchone()
    assert row["key"].startswith("enc:v1:")
    assert "AA:BB" not in row["key"]
    store.close()


class TestKeyFileModeFailsClosed:
    """S4: a group/world-readable key file must refuse to load.

    A weak mode undoes the encryption the key unlocks, so the refusal is
    the feature. CYT_ALLOW_WEAK_KEY_MODE=1 is the explicit dev-only escape
    hatch — it loads with a loud warning, never silently.
    """

    @staticmethod
    def _key(path: Path, mode: int) -> Path:
        path.write_bytes(base64.b64encode(secrets.token_bytes(32)))
        path.chmod(mode)
        return path

    def test_group_readable_refuses(self, tmp_path: Path):
        key = self._key(tmp_path / "store.key", 0o640)
        with pytest.raises(CryptoError, match="group/world-readable"):
            load_key_from_file(key)

    def test_world_writable_refuses(self, tmp_path: Path):
        key = self._key(tmp_path / "store.key", 0o602)
        with pytest.raises(CryptoError):
            load_key_from_file(key)

    def test_owner_only_loads(self, tmp_path: Path):
        key = self._key(tmp_path / "store.key", 0o600)
        assert len(load_key_from_file(key)) == 32

    def test_dev_escape_hatch_loads_with_warning(self, tmp_path, monkeypatch):
        key = self._key(tmp_path / "store.key", 0o644)
        monkeypatch.setenv("CYT_ALLOW_WEAK_KEY_MODE", "1")
        assert len(load_key_from_file(key)) == 32

    def test_escape_hatch_off_by_default(self, tmp_path, monkeypatch):
        key = self._key(tmp_path / "store.key", 0o644)
        monkeypatch.delenv("CYT_ALLOW_WEAK_KEY_MODE", raising=False)
        with pytest.raises(CryptoError):
            load_key_from_file(key)
