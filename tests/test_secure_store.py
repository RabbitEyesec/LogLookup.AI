"""Secure configuration acceptance: encrypted secret store.

Prompt 3 requirements: API keys / provider credentials / secrets are
encrypted at rest, files are owner-only, and nothing is stored in
plaintext anywhere a user would edit or back up casually.
"""

from __future__ import annotations

import stat

import pytest

from engine.secure.store import (
    SIEM_API_KEY,
    SecretStore,
    SecretStoreError,
    ai_key_name,
)


def test_roundtrip_and_persistence(tmp_path):
    store = SecretStore(tmp_path)
    store.set(SIEM_API_KEY, "elastic-key-123")
    store.set(ai_key_name("anthropic"), "sk-ant-xyz")
    assert store.get(SIEM_API_KEY) == "elastic-key-123"
    # A fresh instance (fresh process, restart) reads the same values.
    again = SecretStore(tmp_path)
    assert again.get(ai_key_name("anthropic")) == "sk-ant-xyz"
    assert again.names() == [ai_key_name("anthropic"), SIEM_API_KEY]


def test_values_are_encrypted_on_disk(tmp_path):
    store = SecretStore(tmp_path)
    store.set(SIEM_API_KEY, "super-secret-value")
    blob = (tmp_path / "secrets.enc").read_bytes()
    assert b"super-secret-value" not in blob
    assert b"siem_api_key" not in blob  # names are encrypted too


def test_files_are_owner_only(tmp_path):
    store = SecretStore(tmp_path)
    store.set("x", "y")
    for name in ("secrets.key", "secrets.enc"):
        mode = stat.S_IMODE((tmp_path / name).stat().st_mode)
        assert mode == 0o600, f"{name} has mode {oct(mode)}"


def test_delete_and_default(tmp_path):
    store = SecretStore(tmp_path)
    assert store.get("missing", "fallback") == "fallback"
    store.set("a", "1")
    store.delete("a")
    assert store.get("a") == ""
    store.delete("never-existed")  # no error


def test_tampered_store_raises(tmp_path):
    store = SecretStore(tmp_path)
    store.set("a", "1")
    path = tmp_path / "secrets.enc"
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))
    with pytest.raises(SecretStoreError, match="tampered|decrypt"):
        SecretStore(tmp_path).get("a")


def test_wrong_key_raises(tmp_path):
    store = SecretStore(tmp_path)
    store.set("a", "1")
    (tmp_path / "secrets.key").unlink()
    with pytest.raises(SecretStoreError):
        SecretStore(tmp_path).get("a")  # new random key cannot decrypt


def test_empty_name_rejected(tmp_path):
    with pytest.raises(SecretStoreError):
        SecretStore(tmp_path).set("", "v")
