"""Microsoft Entra token broker (azure-identity).

Tokens are cached per ``(tenant, resource, auth_profile)`` and refreshed
before expiry. Graph and Azure Monitor Logs use *different* audiences and
are never interchanged. Credential kinds:

* ``client_secret``  - app registration secret
* ``certificate``    - PEM certificate + private key (unattended, preferred)
* ``managed_identity`` - Azure-hosted deployments, no stored secret
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from engine.connectors.base import (
    STATUS_PERMISSION_DENIED,
    ConfigurationError,
    ConnectorError,
)

logger = logging.getLogger(__name__)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.azure.com/.default"
LOGIC_APPS_SCOPE = "https://logic.azure.com/.default"

REFRESH_SKEW_SECONDS = 300


@dataclass
class _Token:
    value: str
    expires_on: float


class MicrosoftCredentialProvider:
    """Async token source for one auth profile."""

    def __init__(
        self,
        tenant_id: str,
        profile: dict[str, Any],
        *,
        profile_id: str = "",
        credential_factory: Callable[[str, dict[str, Any]], Any] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._tenant = tenant_id
        self._profile = profile
        self._profile_id = profile_id
        self._factory = credential_factory or _default_credential
        self._clock = clock
        self._credential: Any = None
        self._cache: dict[tuple[str, str, str], _Token] = {}
        self._lock = asyncio.Lock()

    async def token(self, scope: str) -> str:
        key = (self._tenant, scope, self._profile_id)
        async with self._lock:
            cached = self._cache.get(key)
            if cached and cached.expires_on - REFRESH_SKEW_SECONDS > self._clock():
                return cached.value
            if self._credential is None:
                self._credential = self._factory(self._tenant, self._profile)
            try:
                got = await self._credential.get_token(scope)
            except ConnectorError:
                raise
            except Exception as exc:  # azure-identity raises many types
                # Class name only: messages can echo request detail.
                raise ConnectorError(
                    f"Microsoft token acquisition failed ({type(exc).__name__}); "
                    "verify tenant, client id, credential and consent",
                    status=STATUS_PERMISSION_DENIED, code="token_failed",
                ) from None
            token = _Token(got.token, float(got.expires_on))
            self._cache[key] = token
            return token.value

    async def close(self) -> None:
        if self._credential is not None and hasattr(self._credential, "close"):
            await self._credential.close()
            self._credential = None


def parse_profile(raw: str) -> dict[str, Any]:
    """Secret-store value -> credential profile dict."""
    if not raw:
        raise ConfigurationError("auth profile has no stored credentials")
    try:
        data = json.loads(raw)
    except ValueError:
        raise ConfigurationError("auth profile is not valid JSON") from None
    if not isinstance(data, dict) or "kind" not in data:
        raise ConfigurationError("auth profile must be an object with a 'kind'")
    return data


def _default_credential(tenant_id: str, profile: dict[str, Any]) -> Any:
    from azure.identity import aio

    kind = profile.get("kind")
    if kind == "client_secret":
        for field in ("client_id", "client_secret"):
            if not profile.get(field):
                raise ConfigurationError(f"auth profile is missing {field}")
        return aio.ClientSecretCredential(
            tenant_id, profile["client_id"], profile["client_secret"])
    if kind == "certificate":
        if not profile.get("client_id") or not (
            profile.get("certificate_pem") or profile.get("certificate_path")
        ):
            raise ConfigurationError(
                "certificate auth needs client_id and certificate_pem/path")
        kwargs: dict[str, Any] = {}
        if profile.get("certificate_pem"):
            kwargs["certificate_data"] = profile["certificate_pem"].encode()
        else:
            kwargs["certificate_path"] = profile["certificate_path"]
        return aio.CertificateCredential(tenant_id, profile["client_id"], **kwargs)
    if kind == "managed_identity":
        return aio.ManagedIdentityCredential(client_id=profile.get("client_id"))
    raise ConfigurationError(f"unsupported Microsoft credential kind {kind!r}")


TokenGetter = Callable[[str], Awaitable[str]]
