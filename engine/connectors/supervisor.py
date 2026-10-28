"""Connector supervisor: one independent async worker per connection.

A worker pages its source, wraps each record in a :class:`SourceEnvelope`,
commits page + cursor atomically through the ledger, and hands accepted
records to the pipeline callback. A failing source only pauses itself:
other sources and existing investigations keep working.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from engine.connectors.base import (
    STATUS_HEALTHY, STATUS_NOT_CONFIGURED, STATUS_PAUSED, STATUS_STARTING,
    STATUS_THROTTLED, STATUS_UNAVAILABLE, ConfigurationError, ConnectorError,
    SourceConnection,
)
from engine.envelope import (
    SCHEMA_VERSION, SourceEnvelope, canonical_event_id, canonical_json, sha256_hex,
)
from engine.normalize.adapters import get_context_adapter
from engine.store.cursors import CursorStore
from engine.store.database import Database, utcnow
from engine.store.ledger import AcceptedRecord, Ledger, PageItem

logger = logging.getLogger(__name__)

OnAccepted = Callable[[SourceConnection, list[AcceptedRecord]], Awaitable[None]]
ConnectorFactory = Callable[[SourceConnection], Any]

#: pause between pages while a window is still being drained
DRAIN_DELAY = 0.2
MAX_BACKOFF_SECONDS = 300


@dataclass
class SourceHealth:
    connection_id: str
    status: str = STATUS_STARTING
    last_attempt: str | None = None
    last_success: str | None = None
    last_receipt: str | None = None
    last_error_code: str | None = None
    last_error: str | None = None
    records_committed: int = 0
    quarantined: int = 0
    consecutive_failures: int = 0
    lag_seconds: float | None = None
    warnings: list[str] = field(default_factory=list)

    def view(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class ConnectionWorker:
    def __init__(self, conn: SourceConnection, factory: ConnectorFactory,
                 ledger: Ledger, cursors: CursorStore, on_accepted: OnAccepted,
                 *, sleep=asyncio.sleep) -> None:
        self.conn = conn
        self.health = SourceHealth(conn.connection_id)
        self._factory, self._ledger, self._cursors = factory, ledger, cursors
        self._on_accepted = on_accepted
        self._sleep = sleep
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self.paused = False

    async def start(self) -> None:
        self._stop.clear()
        self._task = asyncio.create_task(
            self._run(), name=f"source-{self.conn.connection_id}")

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    def pause(self) -> None:
        self.paused = True
        self.health.status = STATUS_PAUSED

    def resume(self) -> None:
        self.paused = False
        self.health.status = STATUS_STARTING
        self._wake.set()

    async def _run(self) -> None:
        connector = None
        backoff = 0.0
        while not self._stop.is_set():
            if self.paused:
                await self._idle(self.conn.poll_seconds)
                continue
            try:
                if connector is None:
                    connector = self._factory(self.conn)
                    await connector.open()
                drained = await self._poll_once(connector)
                backoff = 0.0
                await self._idle(DRAIN_DELAY if not drained
                                 else self.conn.poll_seconds)
            except asyncio.CancelledError:
                raise
            except ConfigurationError as exc:
                self._fail(exc)
                connector = await self._discard(connector)
                await self._idle(max(self.conn.poll_seconds, 60))
            except ConnectorError as exc:
                self._fail(exc)
                await self._ledger.record_error(
                    self.conn.connection_id, None, exc.code, str(exc))
                connector = await self._discard(connector)
                backoff = min(MAX_BACKOFF_SECONDS,
                              max(exc.retry_after or 0, backoff * 2 or 5))
                await self._idle(backoff)
            except Exception as exc:  # isolate: one source must never kill the app
                logger.exception("source %s crashed", self.conn.connection_id)
                self._fail(ConnectorError(type(exc).__name__, code="internal"))
                connector = await self._discard(connector)
                backoff = min(MAX_BACKOFF_SECONDS, backoff * 2 or 10)
                await self._idle(backoff)
        if connector is not None:
            await self._discard(connector)

    async def _discard(self, connector) -> None:
        if connector is not None:
            with contextlib.suppress(Exception):
                await connector.close()
        return None

    async def _idle(self, seconds: float) -> None:
        self._wake.clear()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._wake.wait(), timeout=seconds)

    def _fail(self, exc: ConnectorError) -> None:
        h = self.health
        h.status = exc.status
        h.last_attempt = utcnow()
        h.last_error_code = exc.code
        h.last_error = str(exc)[:300]
        h.consecutive_failures += 1
        logger.warning("source %s: %s (%s)", self.conn.connection_id, exc.code,
                       exc.status)

    async def _poll_once(self, connector) -> bool:
        """Fetch every stream's current window; True once all are drained."""
        all_drained = True
        for stream in connector.streams:
            cursor = await self._cursors.get(self.conn.connection_id, stream)
            page = await connector.fetch_page(cursor, stream)
            items = await self._to_items(connector, stream, page.records)
            accepted = await self._ledger.commit_page(
                self.conn.connection_id, stream, items, page.next_cursor,
                page.window_complete)
            if accepted:
                await self._on_accepted(self.conn, accepted)
                self.health.last_receipt = utcnow()
            self.health.records_committed += len(accepted)
            self.health.warnings = list(page.source_warnings)
            if not page.window_complete:
                all_drained = False
        h = self.health
        h.status, h.last_success, h.last_attempt = STATUS_HEALTHY, utcnow(), utcnow()
        h.consecutive_failures, h.last_error, h.last_error_code = 0, None, None
        h.lag_seconds = 0.0
        return all_drained

    async def _to_items(self, connector, stream: str,
                        records: list[dict[str, Any]]) -> list[PageItem]:
        items: list[PageItem] = []
        observed = utcnow()
        for record in records:
            try:
                ident = connector.identify(record, stream)
                payload_bytes = canonical_json(record)
                envelope = SourceEnvelope(
                    schema_version=SCHEMA_VERSION,
                    scope_id=self.conn.scope_id,
                    connection_id=self.conn.connection_id,
                    provider=self.conn.provider,
                    record_kind=ident.record_kind,
                    source_event_id=ident.source_event_id,
                    canonical_event_id=canonical_event_id(
                        self.conn.scope_id, self.conn.provider, ident.namespace,
                        ident.source_event_id, ident.record_kind,
                        self.conn.connection_id),
                    event_time=ident.event_time,
                    observed_at=observed,
                    raw_sha256=sha256_hex(payload_bytes),
                    source_incident_id=ident.source_incident_id,
                    source_url=ident.source_url,
                    source_updated_at=ident.source_updated_at,
                    provenance=ident.provenance,
                    aliases=ident.aliases,
                )
                item = PageItem(envelope=envelope, payload=record, links=ident.links)
                if envelope.is_context:
                    adapter = get_context_adapter(self.conn.provider)
                    item.contexts = [c.row() for c in
                                     adapter.parse_context(record, envelope)]
                items.append(item)
            except Exception as exc:
                # Quarantine: keep a bounded, redacted reference; do not halt.
                self.health.quarantined += 1
                await self._ledger.record_error(
                    self.conn.connection_id, stream, "malformed_record",
                    f"{type(exc).__name__}: {str(exc)[:200]}",
                    ref=sha256_hex(canonical_json(record))[:32])
        return items


class Supervisor:
    def __init__(self, db: Database, ledger: Ledger, cursors: CursorStore,
                 factory: ConnectorFactory, on_accepted: OnAccepted) -> None:
        self._db, self._ledger, self._cursors = db, ledger, cursors
        self._factory, self._on_accepted = factory, on_accepted
        self.workers: dict[str, ConnectionWorker] = {}

    async def add(self, conn: SourceConnection, *, start: bool = True) -> None:
        if conn.connection_id in self.workers:
            await self.workers[conn.connection_id].stop()
        worker = ConnectionWorker(conn, self._factory, self._ledger,
                                  self._cursors, self._on_accepted)
        if not conn.active:
            worker.health.status = STATUS_NOT_CONFIGURED
        self.workers[conn.connection_id] = worker
        if start and conn.active and conn.origin != "legacy":
            await worker.start()

    async def remove(self, connection_id: str) -> None:
        worker = self.workers.pop(connection_id, None)
        if worker is not None:
            await worker.stop()

    async def stop(self) -> None:
        await asyncio.gather(*(w.stop() for w in self.workers.values()),
                             return_exceptions=True)

    def health(self) -> dict[str, dict[str, Any]]:
        return {cid: w.health.view() for cid, w in self.workers.items()}
