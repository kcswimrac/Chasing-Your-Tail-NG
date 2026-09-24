"""
Store encryption for CYT EDC (P1).

Modes:
  - sealed: AES-GCM envelope of the entire SQLite file at rest
            (cyt.db.sealed); plaintext only while the analyzer runs.
  - field:  encrypt entity keys / incident subjects in-place (defense in depth).

Key unlock (first match wins):
  1. CYT_STORE_KEY_FILE  — 32 raw bytes or base64
  2. store.encryption.key_file in config
  3. CYT_STORE_PASSWORD / CYT_STORE_PASSWORD_FILE + salt file
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from cyt_platform.privacy import chmod_private_file, ensure_dir

logger = logging.getLogger(__name__)

MAGIC = b"CYT1"  # sealed file magic
SEALED_VERSION = 1
FIELD_PREFIX = "enc:v1:"
KDF_ITERATIONS = 200_000


class CryptoError(Exception):
    pass


@dataclass
class StoreKey:
    key: bytes  # 32 bytes AES-256

    def field_encrypt(self, plaintext: str) -> str:
        if not plaintext or plaintext.startswith(FIELD_PREFIX):
            return plaintext
        aes = AESGCM(self.key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plaintext.encode("utf-8"), b"field")
        blob = base64.urlsafe_b64encode(nonce + ct).decode("ascii")
        return FIELD_PREFIX + blob

    def field_decrypt(self, value: str) -> str:
        if not value or not value.startswith(FIELD_PREFIX):
            return value
        raw = base64.urlsafe_b64decode(value[len(FIELD_PREFIX) :].encode("ascii"))
        nonce, ct = raw[:12], raw[12:]
        aes = AESGCM(self.key)
        return aes.decrypt(nonce, ct, b"field").decode("utf-8")


def _kdf(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password)


def load_key_from_file(path: Path) -> bytes:
    data = path.read_bytes().strip()
    if len(data) == 32:
        return data
    # try base64
    try:
        decoded = base64.b64decode(data)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    try:
        decoded = base64.urlsafe_b64decode(data)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    raise CryptoError(f"Key file must be 32 raw bytes or base64: {path}")


def resolve_store_key(enc_cfg: dict) -> Optional[StoreKey]:
    """Return StoreKey if encryption enabled and unlock material present."""
    if not enc_cfg or not enc_cfg.get("enabled"):
        return None

    # Raw key file
    for env_name in ("CYT_STORE_KEY_FILE",):
        p = os.environ.get(env_name)
        if p:
            return StoreKey(load_key_from_file(Path(p)))

    key_file = enc_cfg.get("key_file")
    if key_file:
        return StoreKey(load_key_from_file(Path(key_file)))

    # Password path
    password = os.environ.get("CYT_STORE_PASSWORD")
    pw_file = os.environ.get("CYT_STORE_PASSWORD_FILE") or enc_cfg.get("password_file")
    if not password and pw_file:
        password = Path(pw_file).read_text(encoding="utf-8").strip()
    if not password:
        raise CryptoError(
            "store.encryption.enabled but no key: set CYT_STORE_KEY_FILE, "
            "encryption.key_file, CYT_STORE_PASSWORD, or CYT_STORE_PASSWORD_FILE"
        )

    salt_path = Path(enc_cfg.get("salt_file") or "data/store_salt.bin")
    if salt_path.is_file():
        salt = salt_path.read_bytes()
    else:
        ensure_dir(salt_path.parent, 0o700)
        salt = os.urandom(16)
        salt_path.write_bytes(salt)
        chmod_private_file(salt_path, 0o600)

    return StoreKey(_kdf(password.encode("utf-8"), salt))


def generate_key_file(path: Path) -> Path:
    ensure_dir(path.parent, 0o700)
    key = secrets.token_bytes(32)
    path.write_bytes(base64.b64encode(key))
    chmod_private_file(path, 0o600)
    return path


def sealed_path_for(db_path: Path) -> Path:
    return Path(str(db_path) + ".sealed")


def seal_file(plaintext_path: Path, sealed_path: Path, key: StoreKey) -> None:
    """AES-GCM seal of entire file. Atomic replace."""
    data = plaintext_path.read_bytes()
    aes = AESGCM(key.key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data, b"cyt-db")
    # magic | ver(u8) | nonce(12) | ciphertext
    blob = MAGIC + bytes([SEALED_VERSION]) + nonce + ct
    tmp = sealed_path.with_suffix(sealed_path.suffix + ".tmp")
    ensure_dir(sealed_path.parent, 0o700)
    tmp.write_bytes(blob)
    chmod_private_file(tmp, 0o600)
    os.replace(tmp, sealed_path)
    chmod_private_file(sealed_path, 0o600)


def unseal_file(sealed_path: Path, plaintext_path: Path, key: StoreKey) -> None:
    blob = sealed_path.read_bytes()
    if len(blob) < 4 + 1 + 12 + 16:
        raise CryptoError("Sealed file too short")
    if blob[:4] != MAGIC:
        raise CryptoError("Bad sealed magic")
    ver = blob[4]
    if ver != SEALED_VERSION:
        raise CryptoError(f"Unsupported sealed version {ver}")
    nonce = blob[5:17]
    ct = blob[17:]
    aes = AESGCM(key.key)
    try:
        data = aes.decrypt(nonce, ct, b"cyt-db")
    except Exception as e:
        raise CryptoError("Unseal failed — wrong key or corrupt file") from e
    ensure_dir(plaintext_path.parent, 0o700)
    tmp = plaintext_path.with_suffix(plaintext_path.suffix + ".tmp")
    tmp.write_bytes(data)
    chmod_private_file(tmp, 0o600)
    os.replace(tmp, plaintext_path)
    chmod_private_file(plaintext_path, 0o600)


def secure_delete(path: Path, passes: int = 1) -> None:
    """Best-effort overwrite then unlink (not guaranteed on flash/SSD)."""
    path = Path(path)
    if not path.is_file():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as f:
            for _ in range(max(1, passes)):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    chunk = min(65536, remaining)
                    f.write(os.urandom(chunk))
                    remaining -= chunk
                f.flush()
                os.fsync(f.fileno())
        path.unlink(missing_ok=True)
    except OSError as e:
        logger.warning("secure_delete failed for %s: %s", path, e)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def runtime_db_path(store_cfg: dict, logical_path: Path) -> Path:
    """
    Prefer tmpfs for plaintext while running when encryption is on.
    Config: store.encryption.runtime_dir (default /dev/shm/cyt-$UID)
    """
    enc = store_cfg.get("encryption") or {}
    if not enc.get("enabled"):
        return logical_path
    if not enc.get("sealed", True):
        return logical_path
    rt = enc.get("runtime_dir")
    if rt:
        base = Path(rt)
    else:
        base = Path(f"/dev/shm/cyt-{os.getuid()}")
    try:
        ensure_dir(base, 0o700)
        # probe writable
        probe = base / ".w"
        probe.write_text("1")
        probe.unlink()
        return base / logical_path.name
    except OSError:
        # fall back next to sealed file
        open_dir = logical_path.parent / ".open"
        ensure_dir(open_dir, 0o700)
        logger.warning("tmpfs unavailable; using %s for plaintext DB", open_dir)
        return open_dir / logical_path.name
