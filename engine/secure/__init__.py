"""Secure local storage: encrypted secret store for credentials."""

from engine.secure.store import SecretStore, SecretStoreError

__all__ = ["SecretStore", "SecretStoreError"]
