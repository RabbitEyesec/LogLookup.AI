"""Encrypted raw-evidence vault.

Vendor payloads are stored AES-256-GCM encrypted in the ledger. The
envelope's ``raw_sha256`` is the hash of the *plaintext* canonical payload,
so integrity can be re-verified after decryption.
"""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from engine.envelope import canonical_json, sha256_hex
from engine.store.database import StoreError

_NONCE_BYTES = 12


class EvidenceVault:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise StoreError("evidence key must be 32 bytes")
        self._aead = AESGCM(key)

    def seal(self, payload: Any, aad: str) -> tuple[bytes, str]:
        """Return ``(ciphertext_blob, sha256_of_plaintext)``."""
        plaintext = canonical_json(payload)
        nonce = os.urandom(_NONCE_BYTES)
        blob = nonce + self._aead.encrypt(nonce, plaintext, aad.encode("utf-8"))
        return blob, sha256_hex(plaintext)

    def open(self, blob: bytes, aad: str, expected_sha256: str | None = None) -> Any:
        nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        try:
            plaintext = self._aead.decrypt(nonce, ciphertext, aad.encode("utf-8"))
        except InvalidTag as exc:
            raise StoreError("evidence failed authentication (tampered or wrong key)") from exc
        if expected_sha256 and sha256_hex(plaintext) != expected_sha256:
            raise StoreError("evidence hash mismatch")
        return json.loads(plaintext)
