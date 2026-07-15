"""Elastic SIEM connector: read alerts (batch + poll) and write results back.

The SIEM sits on both ends of the pipeline: alerts are pulled from the
alert index, and triaged attack chains are written back to the results
index (``index_doc``) keyed by ``cluster_id`` idempotent, so re-running a
window updates the same document instead of duplicating it.

Responses are decoded with msgspec on the hot path. Pagination advances on
the ``@timestamp`` sort key and excludes already seen document ids at the
boundary timestamp, so pages never skip or duplicate alerts that share a
timestamp without requiring a point-in-time context.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from typing import Any, AsyncIterator, Callable

import httpx
import msgspec

from engine.config import SiemConfig

logger = logging.getLogger(__name__)

TIMESTAMP_FIELD = "@timestamp"


class ConnectorError(Exception):
    """Raised when the SIEM cannot be reached or returns an error."""


def _tls_verification(
    siem: SiemConfig, ca_cert_pem: str = ""
) -> bool | ssl.SSLContext:
    """Build httpx TLS verification without mutating global trust settings."""
    if not siem.verify_tls:
        return False
    try:
        if ca_cert_pem:
            return ssl.create_default_context(cadata=ca_cert_pem)
        if siem.ca_cert_path:
            return ssl.create_default_context(cafile=siem.ca_cert_path)
    except (OSError, ssl.SSLError) as exc:
        raise ConnectorError(f"cannot load Elastic CA certificate: {exc}") from exc
    return True


class ElasticConnector:
    """Pulls alert documents from an Elasticsearch alert index."""

    def __init__(
        self,
        siem: SiemConfig,
        *,
        client: httpx.AsyncClient | None = None,
        page_size: int = 1000,
        ca_cert_pem: str = "",
    ) -> None:
        self._siem = siem
        self._page_size = page_size
        headers = {"Content-Type": "application/json"}
        if siem.api_key:
            headers["Authorization"] = f"ApiKey {siem.api_key}"
        self._client = client or httpx.AsyncClient(
            base_url=siem.host,
            headers=headers,
            timeout=30.0,
            verify=_tls_verification(siem, ca_cert_pem),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def ping(self) -> bool:
        """True if the cluster root endpoint answers."""
        try:
            response = await self._client.get("/")
        except httpx.HTTPError as exc:
            raise ConnectorError(f"cannot reach SIEM at {self._siem.host}: {exc}") from exc
        return response.status_code == 200

    async def info(self) -> dict[str, Any]:
        """Cluster identity from the root endpoint (name, version)."""
        try:
            response = await self._client.get("/")
        except httpx.HTTPError as exc:
            raise ConnectorError(
                f"cannot reach SIEM at {self._siem.host}: {exc}"
            ) from exc
        if response.status_code in (401, 403):
            raise ConnectorError(
                f"SIEM rejected the credentials (HTTP {response.status_code})"
            )
        if response.status_code != 200:
            raise ConnectorError(
                f"SIEM returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )
        body = msgspec.json.decode(response.content)
        return {
            "cluster_name": body.get("cluster_name", ""),
            "name": body.get("name", ""),
            "version": (body.get("version") or {}).get("number", ""),
        }

    async def list_indices(self) -> list[dict[str, Any]]:
        """Index names + doc counts (for the wizard's index detection)."""
        try:
            response = await self._client.get(
                "/_cat/indices",
                params={
                    "format": "json",
                    "h": "index,docs.count,store.size",
                    "s": "index",
                    "expand_wildcards": "open,hidden",
                },
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"index listing failed: {exc}") from exc
        if response.status_code != 200:
            raise ConnectorError(
                f"index listing returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )
        rows = msgspec.json.decode(response.content)
        indices = []
        for row in rows if isinstance(rows, list) else []:
            name = row.get("index", "")
            if not name:
                continue
            try:
                docs = int(row.get("docs.count") or 0)
            except (TypeError, ValueError):
                docs = 0
            indices.append(
                {"index": name, "docs": docs, "size": row.get("store.size", "")}
            )
        return indices

    async def count(self, index: str) -> int:
        """Document count for one index/pattern (0 if it doesn't resolve)."""
        try:
            response = await self._client.get(f"/{index}/_count")
        except httpx.HTTPError as exc:
            raise ConnectorError(f"count failed for {index!r}: {exc}") from exc
        if response.status_code == 404:
            return 0
        if response.status_code != 200:
            raise ConnectorError(
                f"count for {index!r} returned HTTP {response.status_code}"
            )
        return int(msgspec.json.decode(response.content).get("count", 0))

    async def _search(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"/{self._siem.alert_index}/_search"
        try:
            response = await self._client.post(url, content=msgspec.json.encode(body))
        except httpx.HTTPError as exc:
            raise ConnectorError(f"search request failed: {exc}") from exc
        if response.status_code != 200:
            raise ConnectorError(
                f"search returned HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )
        return msgspec.json.decode(response.content)

    async def index_doc(
        self,
        index: str,
        doc_id: str,
        doc: dict[str, Any],
    ) -> dict[str, Any]:
        """Write one document (PUT /<index>/_doc/<id>); create or update."""
        url = f"/{index}/_doc/{doc_id}"
        try:
            response = await self._client.put(
                url, content=msgspec.json.encode(doc)
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"write-back request failed: {exc}") from exc
        if response.status_code not in (200, 201):
            raise ConnectorError(
                f"write-back returned HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )
        return msgspec.json.decode(response.content)

    async def get_doc(
        self,
        index: str,
        doc_id: str,
    ) -> dict[str, Any] | None:
        """Fetch one document's ``_source``, or None if it does not exist."""
        url = f"/{index}/_doc/{doc_id}"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"result lookup failed: {exc}") from exc
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ConnectorError(
                f"result lookup returned HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )
        body = msgspec.json.decode(response.content)
        return body.get("_source")
    async def fetch_batch(
        self,
        since_ms: int,
        until_ms: int,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield raw alert hits with ``since_ms <= @timestamp < until_ms``.

        Hits are yielded in event-time order. Each hit is the full Elastic
        hit dict (``_id``, ``_index``, ``_source``).
        """
        cursor_ms = since_ms
        boundary_ids: list[str] = []
        while True:
            filters: list[dict[str, Any]] = [
                {
                    "range": {
                        TIMESTAMP_FIELD: {
                            "gte": cursor_ms,
                            "lt": until_ms,
                            "format": "epoch_millis",
                        }
                    }
                }
            ]
            query: dict[str, Any] = {"bool": {"filter": filters}}
            if boundary_ids:
                query["bool"]["must_not"] = [{"ids": {"values": boundary_ids}}]
            body = {
                "query": query,
                "sort": [{TIMESTAMP_FIELD: {"order": "asc"}}],
                "size": self._page_size,
            }
            result = await self._search(body)
            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                return
            for hit in hits:
                yield hit
            last_sort = hits[-1].get("sort") or [cursor_ms]
            last_ts = int(last_sort[0])
            ids_at_last_ts = [
                h["_id"] for h in hits if int((h.get("sort") or [last_ts])[0]) == last_ts
            ]
            if last_ts == cursor_ms:
                boundary_ids.extend(ids_at_last_ts)
            else:
                cursor_ms = last_ts
                boundary_ids = ids_at_last_ts
            if len(hits) < self._page_size:
                return

    async def poll(
        self,
        since_ms: int | None = None,
        *,
        stop: asyncio.Event | None = None,
        on_cursor: Callable[[int], None] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield new alert hits forever, checking every ``poll_seconds``.

        The cursor starts at ``since_ms`` (default: now) and advances past
        everything yielded. Transient SIEM errors are logged and retried on
        the next cycle — polling never dies on a hiccup.

        ``on_cursor`` is invoked with the advanced cursor after each cycle
        that fetched alerts, so callers can persist it and resume from the
        same point after a restart (alerts that arrived during downtime are
        then re-read; downstream dedup by uid makes that safe).
        """
        cursor = since_ms if since_ms is not None else int(time.time() * 1000)
        while stop is None or not stop.is_set():
            until = int(time.time() * 1000)
            fetched = 0
            try:
                async for hit in self.fetch_batch(cursor, until):
                    ts = hit.get("sort", [None])[0]
                    if ts is not None:
                        cursor = max(cursor, int(ts) + 1)
                    fetched += 1
                    yield hit
            except ConnectorError as exc:
                logger.warning("poll cycle failed, retrying next cycle: %s", exc)
            if fetched:
                logger.info("poll cycle fetched %d alert(s)", fetched)
                if on_cursor is not None:
                    try:
                        on_cursor(cursor)
                    except Exception:  # persistence must never kill polling
                        logger.exception("poll cursor persistence failed")
            try:
                if stop is not None:
                    await asyncio.wait_for(
                        stop.wait(), timeout=self._siem.poll_seconds
                    )
                else:
                    await asyncio.sleep(self._siem.poll_seconds)
            except asyncio.TimeoutError:
                pass
