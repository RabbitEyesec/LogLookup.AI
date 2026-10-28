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

from engine.connectors._common import backfill_cursor, parse_iso
from engine.connectors.base import (
    COMPLETENESS_ERRORS, DEGRADING_WARNINGS, SNAPSHOT_EXPIRED_REPLAYING,
    STATUS_DEGRADED, STATUS_HEALTHY, STATUS_NOT_CONFIGURED, STATUS_PAUSED,
    STATUS_STARTING, ConfigurationError, ConnectorError, SourceConnection,
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
    # acquisition counters since this process started
    records_received: int = 0
    records_new: int = 0
    records_updated: int = 0
    records_duplicate: int = 0
    records_unchanged: int = 0
    records_committed: int = 0  # new + updated + duplicate (stored)
    records_quarantined: int = 0
    pages_drained: int = 0
    provider_partial_errors: int = 0
    consecutive_failures: int = 0
    #: worst per-stream lag from the committed watermark; None = no watermark
    lag_seconds: float | None = None
    warnings: list[str] = field(default_factory=list)
    #: stream -> window / watermark / continuation progress
    streams: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def quarantined(self) -> int:  # v2.0.0 field name, kept for API compat
        return self.records_quarantined

    def view(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["quarantined"] = self.records_quarantined
        return data


def _stream_progress(next_cursor: dict[str, Any] | None,
                     prior: dict[str, Any] | None, complete: bool,
                     committed: int) -> dict[str, Any]:
    """Operator-facing progress of one stream, from the COMMITTED cursor."""
    cur = next_cursor or {}
    watermark = cur.get("watermark") or (prior or {}).get("watermark")
    lag = None
    if watermark:
        try:
            lag = max(0.0, (datetime.now(timezone.utc)
                            - parse_iso(str(watermark))).total_seconds())
        except ValueError:
            watermark = None
    if cur.get("job_sid"):
        mode = "snapshot_job"
    elif cur.get("last_time"):
        mode = "composite_seek"
    elif cur.get("next_link"):
        mode = "next_link"
    elif cur.get("continue") or not complete:
        mode = "continuation"
    else:
        mode = None
    return {
        "window_start": cur.get("window_start") or cur.get("page_start"),
        "window_end": cur.get("window_end"),
        "watermark": watermark,
        "window_complete": complete,
        "continuation_mode": mode,
        "snapshot_active": bool(cur.get("job_sid")),
        "snapshot_offset": cur.get("offset"),
        "ingest_lag_seconds": lag,
        "last_page_records": committed,
    }


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
        #: administrator decisions for a source stuck on a bad row
        self.tolerate_bad_rows = False
        self._retry_requested = False
        self._stream = None

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

    def retry_now(self) -> None:
        """Administrator: stop waiting out the backoff and replay the same
        cursor immediately."""
        self._retry_requested = True
        self._wake.set()

    def allow_bad_rows_once(self) -> None:
        """Administrator: for the NEXT drained window only, set unidentifiable
        rows aside (hashed, recorded) instead of stopping the page."""
        self.tolerate_bad_rows = True
        self._retry_requested = True
        self._wake.set()

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
                    self.conn.connection_id, self._stream, exc.code, str(exc),
                    ref=exc.ref)
                connector = await self._discard(connector)
                backoff = min(MAX_BACKOFF_SECONDS,
                              max(exc.retry_after or 0, backoff * 2 or 5))
                await self._idle(backoff)
                if self._retry_requested:  # an administrator asked: go now
                    backoff = 0.0
                self._retry_requested = False
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
        # Do not clear the flag first: a retry, resume or stop that arrived
        # while a poll was running must still cut this wait short.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._wake.wait(), timeout=seconds)
        self._wake.clear()

    def _fail(self, exc: ConnectorError) -> None:
        h = self.health
        h.status = exc.status
        h.last_attempt = utcnow()
        h.last_error_code = exc.code
        h.last_error = str(exc)[:300]
        h.consecutive_failures += 1
        if exc.code in COMPLETENESS_ERRORS or exc.code == SNAPSHOT_EXPIRED_REPLAYING:
            h.provider_partial_errors += 1
        logger.warning("source %s: %s (%s)", self.conn.connection_id, exc.code,
                       exc.status)

    async def _poll_once(self, connector) -> bool:
        """Fetch every stream's current window; True once all are drained."""
        all_drained = True
        warnings: list[str] = []
        h = self.health
        for stream in connector.streams:
            self._stream = stream
            cursor = await self._cursors.get(self.conn.connection_id, stream)
            if hasattr(connector, "strict"):
                connector.strict = not self.tolerate_bad_rows
            page = await connector.fetch_page(cursor, stream)
            for bad in page.rejected:
                # Set aside on purpose; keep a hash so it can be investigated.
                await self._ledger.record_error(
                    self.conn.connection_id, stream, bad["reason"],
                    "row set aside by administrator decision", ref=bad["ref"])
                h.records_quarantined += 1
            items = await self._to_items(connector, stream, page.records)
            accepted = await self._ledger.commit_page(
                self.conn.connection_id, stream, items, page.next_cursor,
                page.window_complete)
            if accepted:
                await self._on_accepted(self.conn, accepted)
                h.last_receipt = utcnow()
            h.records_received += len(page.records)
            h.records_duplicate += sum(1 for a in accepted if a.duplicate_of)
            h.records_updated += sum(
                1 for a in accepted if a.is_update and not a.duplicate_of)
            h.records_new += sum(
                1 for a in accepted if not a.is_update and not a.duplicate_of)
            h.records_unchanged += max(0, len(items) - len(accepted))
            h.records_committed += len(accepted)
            if page.window_complete:
                h.pages_drained += 1
                self.tolerate_bad_rows = False  # the tolerance covered one window
            else:
                all_drained = False
            warnings.extend(page.source_warnings)
            h.streams[stream] = _stream_progress(
                page.next_cursor, cursor, page.window_complete, len(accepted))
        h.warnings = list(dict.fromkeys(warnings))
        # Healthy only when nothing known-incomplete is outstanding.
        degraded = any(w in DEGRADING_WARNINGS for w in h.warnings)
        h.status = STATUS_DEGRADED if degraded else STATUS_HEALTHY
        h.last_success = h.last_attempt = utcnow()
        h.consecutive_failures, h.last_error, h.last_error_code = 0, None, None
        lags = [v["ingest_lag_seconds"] for v in h.streams.values()
                if v.get("ingest_lag_seconds") is not None]
        h.lag_seconds = max(lags) if lags else None
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
                self.health.records_quarantined += 1
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
        self.backfills: dict[str, dict[str, Any]] = {}
        self.backfill_tasks: dict[str, asyncio.Task] = {}

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

    #: hard ceiling so a typo cannot trigger an unbounded historical read
    MAX_BACKFILL_PAGES = 2000

    def _new_backfill(self, connection_id: str, stream: str, start: datetime,
                      end: datetime) -> dict[str, Any]:
        status = self.backfills[connection_id] = {
            "state": "running", "stream": stream, "pages": 0, "records": 0,
            "stored": 0, "started_at": utcnow(), "error": None,
            "start": start.isoformat(), "end": end.isoformat()}
        return status

    def start_backfill(self, conn: SourceConnection, stream: str,
                       start: datetime, end: datetime,
                       event_time_floor: int | None = None) -> dict[str, Any]:
        """Register the job synchronously (so status is readable at once),
        then run it in the background."""
        status = self._new_backfill(conn.connection_id, stream, start, end)
        self.backfill_tasks[conn.connection_id] = asyncio.create_task(
            self.backfill(conn, stream, start, end, event_time_floor))
        return status

    async def backfill(self, conn: SourceConnection, stream: str,
                       start: datetime, end: datetime,
                       event_time_floor: int | None = None) -> dict[str, Any]:
        """Re-read one explicit UTC interval of one stream.

        Runs beside, never through, the live cursor: pages are committed with
        no cursor write, so a backfill can never move the live checkpoint
        (least of all backwards). The caller must have paused the source.
        """
        status = self.backfills.get(conn.connection_id) or self._new_backfill(
            conn.connection_id, stream, start, end)
        helper = ConnectionWorker(conn, self._factory, self._ledger,
                                  self._cursors, self._on_accepted)
        connector = None
        try:
            connector = self._factory(conn)
            await connector.open()
            if stream not in connector.streams:
                raise ConnectorError(f"stream {stream!r} is not enabled",
                                     code="bad_stream")
            cursor = backfill_cursor(start, end, event_time_floor)
            while status["pages"] < self.MAX_BACKFILL_PAGES:
                page = await connector.fetch_page(cursor, stream)
                items = await helper._to_items(connector, stream, page.records)
                accepted = await self._ledger.commit_page(
                    conn.connection_id, stream, items, None, page.window_complete)
                if accepted:
                    await self._on_accepted(conn, accepted)
                status["pages"] += 1
                status["records"] += len(page.records)
                status["stored"] += len(accepted)
                if page.window_complete:
                    break
                cursor = page.next_cursor
            else:
                raise ConnectorError("backfill page ceiling reached",
                                     code="backfill_ceiling")
            status["state"] = "complete"
        except ConnectorError as exc:
            status.update(state="failed", error=f"{exc.code}: {exc}"[:300])
        except Exception as exc:
            status.update(state="failed", error=type(exc).__name__)
        finally:
            if connector is not None:
                with contextlib.suppress(Exception):
                    await connector.close()
            status["finished_at"] = utcnow()
        return status

    async def remove(self, connection_id: str) -> None:
        worker = self.workers.pop(connection_id, None)
        if worker is not None:
            await worker.stop()

    async def stop(self) -> None:
        for task in self.backfill_tasks.values():
            task.cancel()
        await asyncio.gather(*(w.stop() for w in self.workers.values()),
                             *self.backfill_tasks.values(),
                             return_exceptions=True)

    def health(self) -> dict[str, dict[str, Any]]:
        return {cid: w.health.view() for cid, w in self.workers.items()}
