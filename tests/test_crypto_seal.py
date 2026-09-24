"""Sealed store encryption + field crypto tests."""

from __future__ import annotations

import time
from pathlib import Path


from cyt_platform.crypto import StoreKey, generate_key_file, seal_file, unseal_file
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
        store.observe_incident(
            event_type="mac_reappear",
            subject="AA:BB:CC:DD:EE:FF",
            window_label="15-20",
            severity="alert",
            session_id=sid,
            observed_at=time.time(),
            summary="t",
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
