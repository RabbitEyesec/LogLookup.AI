"""Azure Logic Apps outbound transport (HTTP Request trigger).

Delivery classification is deliberately conservative:

* connection never established / 4xx / 429  -> ``rejected`` (no effect)
* 2xx                                       -> ``accepted`` (run reference kept)
* timeout after send, 5xx, protocol errors  -> ``unknown`` (never auto-retried)

A 202 only proves the workflow *accepted* the request. It does not prove an
endpoint was isolated or an account changed.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from engine.connectors.base import ConfigurationError, ConnectorError
from engine.connectors.http import build_tls, scrub, validate_target
from engine.response.models import DispatchResult

logger = logging.getLogger(__name__)

ALLOWED_HOST_SUFFIXES = (".logic.azure.com", ".logic.azure.us",
                         ".logic.azure.cn", ".azurewebsites.net")
DEFAULT_AUDIENCE = "https://management.core.windows.net/.default"


class LogicAppsTransport:
    """``profile`` is the decrypted auth profile:

    ``{"kind": "logic_app", "url": "https://....logic.azure.com/...",
       "auth": "entra" | "sas", "scope": "...optional audience scope",
       "credential": {...Microsoft credential profile...}, "tenant_id": "..."}``
    """

    def __init__(self, profile: dict[str, Any], *,
                 token_getter: Callable[[str], Awaitable[str]] | None = None,
                 transport: httpx.AsyncBaseTransport | None = None,
                 timeout: float = 30.0) -> None:
        if profile.get("kind") != "logic_app":
            raise ConfigurationError("auth profile kind must be 'logic_app'")
        url = profile.get("url")
        if not isinstance(url, str):
            raise ConfigurationError("Logic App profile has no url")
        validate_target(url)
        host = (urlsplit(url).hostname or "").lower()
        if not host.endswith(ALLOWED_HOST_SUFFIXES):
            raise ConfigurationError(
                "Logic App endpoint host is not an Azure Logic Apps host")
        self._url = url
        self._auth = profile.get("auth", "entra")
        if self._auth not in ("entra", "sas"):
            raise ConfigurationError("Logic App auth must be 'entra' or 'sas'")
        self._scope = profile.get("scope") or DEFAULT_AUDIENCE
        self._token = token_getter
        if self._auth == "entra" and token_getter is None:
            raise ConfigurationError("Entra-protected Logic App needs a token source")
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport,
                                         verify=build_tls(True, None),
                                         follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def send(self, contract: dict[str, Any]) -> DispatchResult:
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": contract["idempotency_key"],
            "X-LogLookup-Action-Id": contract["action_id"],
            # Logic Apps stores this on the run, which is how a run is found
            # again later without guessing from time or workflow name.
            "x-ms-client-tracking-id": contract["action_id"],
        }
        if self._auth == "entra":
            try:
                headers["Authorization"] = f"Bearer {await self._token(self._scope)}"
            except ConnectorError as exc:
                # No request was made: definitely no effect.
                return DispatchResult("rejected", detail=f"token: {exc.code}")
        try:
            response = await self._client.post(
                self._url, headers=headers, content=json.dumps(contract))
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            return DispatchResult("rejected",
                                  detail=f"not delivered: {type(exc).__name__}")
        except httpx.HTTPError as exc:
            return DispatchResult("unknown",
                                  detail=f"delivery unknown: {type(exc).__name__}")
        run_id = response.headers.get("x-ms-workflow-run-id")
        code = response.status_code
        if 200 <= code < 300:
            return DispatchResult("accepted", run_id=run_id,
                                  detail="accepted by workflow", http_status=code)
        if code >= 500:
            return DispatchResult("unknown", run_id=run_id,
                                  detail=f"server error {code}", http_status=code)
        return DispatchResult("rejected", detail=scrub(f"HTTP {code}"),
                              http_status=code)
