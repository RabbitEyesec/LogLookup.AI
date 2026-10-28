"""Splunk token-based authentication."""

from __future__ import annotations

from engine.connectors.base import ConfigurationError


def splunk_headers(token: str) -> dict[str, str]:
    if not token:
        raise ConfigurationError("Splunk authentication token is not set")
    return {"Authorization": f"Bearer {token}"}
