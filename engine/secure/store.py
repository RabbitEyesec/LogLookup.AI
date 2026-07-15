"""Encrypted local secret store — AES-256-GCM, owner-only files.

Credentials (SIEM API key, cloud AI keys) never live in ``config.yaml``,
environment variables, or any file a user hand-edits. They are written to
``<app home>/secrets.enc``, encrypted with a machine-local random key in
``<app home>/secrets.key``. Both files are created ``0600`` and replaced
atomically. The API accepts secrets write-only and never echoes them.

The key file protects secrets at rest against casual reads, backups of the
config directory, and accidental commits — it is on the same host by
design (the engine must decrypt without prompting a headless service for a
passphrase), so file permissions are the trust boundary for a local
attacker with the same UID.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

KEY_FILE = "secrets.key"
STORE_FILE = "secrets.enc"
_MAGIC = b"LLSEC1\n"
_NONCE_BYTES = 12

#: Well-known secret names (single vocabulary across wizard, API, engine).
SIEM_API_KEY = "siem_api_key"


def ai_key_name(provider: str) -> str:
    """Per-provider cloud key slot, so switching providers keeps keys."""
    return f"ai_key_{provider}"


class SecretStoreError(Exception):
    """Raised when the store cannot be read, decrypted, or written."""


def _write_private(path: Path, data: bytes) -> None:
    """Atomic replace with 0600 permissions from the first byte."""
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


class SecretStore:
    """Named secrets, encrypted at rest under one directory."""

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._key_path = self._dir / KEY_FILE
        self._store_path = self._dir / STORE_FILE

    # -- key management ----------------------------------------------------

    def _key(self) -> bytes:
        if self._key_path.exists():
            try:
                raw = base64.b64decode(self._key_path.read_bytes())
            except (OSError, ValueError) as exc:
                raise SecretStoreError(
                    f"cannot read secret key {self._key_path}: {exc}"
                ) from exc
            if len(raw) != 32:
                raise SecretStoreError(
                    f"secret key {self._key_path} is corrupt "
                    f"(expected 32 bytes, got {len(raw)})"
                )
            return raw
        key = AESGCM.generate_key(bit_length=256)
        _write_private(self._key_path, base64.b64encode(key))
        logger.info("generated new secret store key at %s", self._key_path)
        return key

    # -- store I/O -----------------------------------------------------------

    def _load(self) -> dict[str, str]:
        if not self._store_path.exists():
            return {}
        blob = self._store_path.read_bytes()
        if not blob.startswith(_MAGIC):
            raise SecretStoreError(
                f"secret store {self._store_path} has an unknown format"
            )
        body = blob[len(_MAGIC):]
        if len(body) <= _NONCE_BYTES:
            raise SecretStoreError(f"secret store {self._store_path} is truncated")
        nonce, ciphertext = body[:_NONCE_BYTES], body[_NONCE_BYTES:]
        try:
            plaintext = AESGCM(self._key()).decrypt(nonce, ciphertext, _MAGIC)
        except InvalidTag as exc:
            raise SecretStoreError(
                f"cannot decrypt {self._store_path}: wrong key or tampered file"
            ) from exc
        try:
            data = json.loads(plaintext)
        except ValueError as exc:
            raise SecretStoreError(
                f"secret store {self._store_path} decrypted to invalid data"
            ) from exc
        if not isinstance(data, dict):
            raise SecretStoreError(
                f"secret store {self._store_path} decrypted to invalid data"
            )
        return {str(k): str(v) for k, v in data.items()}

    def _save(self, data: dict[str, str]) -> None:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(self._key()).encrypt(
            nonce, json.dumps(data).encode("utf-8"), _MAGIC
        )
        _write_private(self._store_path, _MAGIC + nonce + ciphertext)

    # -- public API -----------------------------------------------------------

    def get(self, name: str, default: str = "") -> str:
        return self._load().get(name, default)

    def set(self, name: str, value: str) -> None:
        if not name:
            raise SecretStoreError("secret name must not be empty")
        data = self._load()
        data[name] = value
        self._save(data)

    def set_many(self, values: dict[str, str]) -> None:
        data = self._load()
        data.update({k: v for k, v in values.items() if k})
        self._save(data)

    def delete(self, name: str) -> None:
        data = self._load()
        if data.pop(name, None) is not None:
            self._save(data)

    def names(self) -> list[str]:
        """Secret names only — values are never enumerated."""
        return sorted(self._load())
