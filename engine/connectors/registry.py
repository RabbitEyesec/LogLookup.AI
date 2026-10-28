"""Provider registry: factory + advertised capabilities per provider."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from engine.connectors.auth.microsoft import MicrosoftCredentialProvider, parse_profile
from engine.connectors.base import (
    PROVIDERS, ConfigurationError, SourceConnection,
)
from engine.secure.store import SecretStore, auth_profile_name


@dataclass(frozen=True)
class ProviderSpec:
    provider: str
    label: str
    capabilities: tuple[str, ...]
    #: ``alert`` kinds produce OCSF findings; ``context`` kinds do not.
    emits: tuple[str, ...]
    credential_kinds: tuple[str, ...]
    prerequisites: str


REGISTRY: dict[str, ProviderSpec] = {
    "elastic": ProviderSpec(
        "elastic", "Elastic Security",
        ("alerts", "writeback"), ("alert",), ("api_key",),
        "API key with read on the alert index; write on the results index "
        "only if write-back is enabled."),
    "sentinel": ProviderSpec(
        "sentinel", "Microsoft Sentinel",
        ("alerts", "query_language"), ("alert",),
        ("client_secret", "certificate", "managed_identity"),
        "Entra app/identity with Log Analytics Reader on the workspace "
        "(Azure RBAC; separate from any Graph grant)."),
    "splunk": ProviderSpec(
        "splunk", "Splunk Enterprise / ES",
        ("alerts", "query_language"), ("alert",), ("token",),
        "Splunk authentication token whose role may search the allowlisted "
        "indexes; REST management port reachable."),
    "defender_xdr": ProviderSpec(
        "defender_xdr", "Microsoft Defender XDR",
        ("alerts", "incidents"), ("alert", "incident"),
        ("client_secret", "certificate", "managed_identity"),
        "Graph application permissions SecurityAlert.Read.All and "
        "SecurityIncident.Read.All with admin consent."),
    "entra_id": ProviderSpec(
        "entra_id", "Microsoft Entra ID",
        ("identity_context",), ("signin", "directory_audit"),
        ("client_secret", "certificate", "managed_identity"),
        "Graph application permission AuditLog.Read.All; sign-in logs need "
        "Entra ID P1/P2 licensing."),
}
assert set(REGISTRY) == set(PROVIDERS)


def load_profile(secrets: SecretStore, conn: SourceConnection) -> str:
    """Encrypted store first; then ``LOGLOOKUP_AUTH_<PROFILE_ID>`` so
    config-file deployments can inject a credential without a file."""
    if not conn.auth_profile_id:
        return ""
    stored = secrets.get(auth_profile_name(conn.auth_profile_id))
    if stored:
        return stored
    env = "LOGLOOKUP_AUTH_" + re.sub(r"[^A-Za-z0-9]", "_", conn.auth_profile_id).upper()
    return os.environ.get(env, "")


def build_connector(
    conn: SourceConnection,
    secrets: SecretStore,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    token_getter_factory: Callable[[SourceConnection], Any] | None = None,
):
    """Instantiate the connector for ``conn``; raises ConfigurationError."""
    raw = load_profile(secrets, conn)
    provider = conn.provider
    if provider == "elastic":
        from engine.connectors.elastic import ElasticSourceConnector

        return ElasticSourceConnector(conn, _plain_secret(raw, "api_key"))
    if provider == "splunk":
        from engine.connectors.splunk import SplunkConnector

        token = _plain_secret(raw, "token")
        if not token:
            raise ConfigurationError("Splunk auth profile has no token")
        return SplunkConnector(conn, token, transport=transport)

    tenant = str(conn.options.get("tenant_id", ""))
    broker = None
    if token_getter_factory is not None:
        getter = token_getter_factory(conn)
    else:
        broker = MicrosoftCredentialProvider(
            tenant, parse_profile(raw), profile_id=conn.auth_profile_id)
        getter = broker.token
    if provider == "sentinel":
        from engine.connectors.sentinel import SentinelConnector

        connector = SentinelConnector(conn, getter, transport=transport)
    elif provider == "defender_xdr":
        from engine.connectors.defender_xdr import DefenderXdrConnector

        connector = DefenderXdrConnector(conn, getter, transport=transport)
    else:
        from engine.connectors.entra_id import EntraIdConnector

        connector = EntraIdConnector(conn, getter, transport=transport)
    if broker is not None:  # release the credential's HTTP session on close
        inner_close = connector.close

        async def close() -> None:
            await inner_close()
            await broker.close()

        connector.close = close  # type: ignore[method-assign]
    return connector


def _plain_secret(raw: str, field: str) -> str:
    """Accept either a bare secret or a JSON profile holding ``field``."""
    raw = (raw or "").strip()
    if raw.startswith("{"):
        try:
            return str(json.loads(raw).get(field, ""))
        except ValueError:
            return ""
    return raw
