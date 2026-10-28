"""Shared HTTP layer: pooled client, TLS, retry/backoff, host allowlisting.

Every v2 connector goes through :class:`ConnectorHttp`. It never puts a
credential or token into an exception message, honours ``Retry-After``,
classifies vendor failures into operator-visible states, and refuses
metadata/link-local targets so a hostile config or a hostile ``nextLink``
cannot turn the server into a request proxy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import re
import ssl
from typing import Any
from urllib.parse import urlsplit

import httpx

from engine.connectors.base import (
    STATUS_LIMITED_BY_LICENSE,
    STATUS_PERMISSION_DENIED,
    STATUS_THROTTLED,
    STATUS_UNAVAILABLE,
    ConfigurationError,
    ConnectorError,
)

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 4
BASE_BACKOFF = 1.0
MAX_BACKOFF = 30.0
_BLOCKED_NETS = (
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("fe80::/10"),
)
_SECRET_PATTERNS = (
    (re.compile(r"(?i)\b(bearer|apikey|basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1 [redacted]"),
    (re.compile(r"(?i)\b(sig|client_secret|access_token|refresh_token|password)=[^&\s\"']+"),
     r"\1=[redacted]"),
)


def scrub(text: str) -> str:
    """Remove token-shaped substrings from text bound for logs or errors."""
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def validate_target(url: str, *, allow_loopback: bool = False,
                    allowed_hosts: tuple[str, ...] = (),
                    require_https: bool = True) -> str:
    """Reject unsafe connector targets before any request is made."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        raise ConfigurationError(f"invalid URL scheme/host for {url!r}")
    if require_https and parts.scheme != "https" and not (
        allow_loopback and host in ("localhost", "127.0.0.1", "::1")
    ):
        raise ConfigurationError("HTTPS is required for this source")
    if allowed_hosts and host not in allowed_hosts:
        raise ConfigurationError(f"host {host!r} is not an allowed endpoint")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if any(ip in net for net in _BLOCKED_NETS):
            raise ConfigurationError("link-local/metadata addresses are blocked")
        if ip.is_loopback and not allow_loopback:
            raise ConfigurationError("loopback targets are not allowed here")
    elif host == "metadata.google.internal":
        raise ConfigurationError("metadata hosts are blocked")
    return url


def build_tls(verify: bool, ca_bundle_path: str | None) -> bool | ssl.SSLContext:
    if not verify:
        return False
    if ca_bundle_path:
        try:
            return ssl.create_default_context(cafile=ca_bundle_path)
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(f"cannot load CA bundle: {exc}") from exc
    return True


def classify_status(status_code: int, body: str = "") -> ConnectorError:
    text = scrub(body[:300])
    if status_code == 429:
        return ConnectorError("rate limited by source", status=STATUS_THROTTLED,
                              code="throttled")
    if status_code in (401, 403):
        lowered = body.lower()
        if any(w in lowered for w in ("license", "premium", "p1", "p2",
                                      "subscription", "not licensed")):
            return ConnectorError(
                f"source feature unavailable for this licence (HTTP {status_code})",
                status=STATUS_LIMITED_BY_LICENSE, code="limited_by_license")
        return ConnectorError(
            f"source denied access (HTTP {status_code}); check granted permissions",
            status=STATUS_PERMISSION_DENIED, code="permission_denied")
    if status_code == 404:
        return ConnectorError("source resource not found (HTTP 404)",
                              status=STATUS_UNAVAILABLE, code="not_found")
    return ConnectorError(f"source returned HTTP {status_code}: {text}",
                          status=STATUS_UNAVAILABLE, code=f"http_{status_code}")


class ConnectorHttp:
    """Retrying async client bound to one connection."""

    def __init__(
        self,
        *,
        base_url: str = "",
        verify: bool | ssl.SSLContext = True,
        timeout: float = 30.0,
        max_connections: int = 8,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep=asyncio.sleep,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            verify=verify,
            timeout=timeout,
            limits=httpx.Limits(max_connections=max_connections,
                                max_keepalive_connections=max_connections),
            transport=transport,
            follow_redirects=False,
        )
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        retry: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        attempts = MAX_ATTEMPTS if retry else 1
        last: ConnectorError | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = await self._client.request(
                    method, url, headers=headers, **kwargs
                )
            except httpx.TransportError as exc:
                last = ConnectorError(
                    f"network error talking to source: {type(exc).__name__}",
                    status=STATUS_UNAVAILABLE, code="network")
            else:
                if response.status_code < 400:
                    return response
                last = classify_status(response.status_code, response.text)
                if response.status_code not in (429, 500, 502, 503, 504):
                    raise last
                retry_after = _retry_after(response)
                if retry_after is not None:
                    last.retry_after = retry_after
            if attempt >= attempts:
                break
            delay = last.retry_after if last.retry_after is not None else min(
                MAX_BACKOFF, BASE_BACKOFF * 2 ** (attempt - 1)
            ) * (0.5 + random.random() / 2)
            logger.info("retrying source request in %.1fs (attempt %d/%d, %s)",
                        delay, attempt, attempts, last.code)
            await self._sleep(min(delay, MAX_BACKOFF * 2))
        assert last is not None
        raise last


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
