"""Ingestion: acquire raw alert records from a source, losing nothing.

Two sources ship now, matching the build plan: the file source (JSON array /
NDJSON / CSV — portable, used for tests and demos) and the Elastic connector.
Each record carries the original event payload plus its raw bytes so the
normalizer can preserve the source event byte-for-byte in ``unmapped``.

For NDJSON and CSV the raw bytes are the exact source line; for JSON-array
files and Elastic hits (already materialized by the transport) they are the
untouched event re-encoded canonically — values are never altered either way.
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Iterator

import msgspec

from engine.connectors.elastic import ElasticConnector
from engine.normalize.timeutil import now_utc_iso

logger = logging.getLogger(__name__)


class IngestError(Exception):
    """Raised when a source cannot be read at all (not per-event errors)."""


@dataclass(frozen=True)
class RawRecord:
    """One source event, exactly as received."""

    source: str  # "file" | "elastic"
    payload: dict[str, Any]  # decoded event (Elastic: the full hit)
    raw: bytes  # original event bytes, unaltered
    received_at: str  # ingestion time, UTC ISO-8601 Z


def _decode_json_line(line: bytes, source: str) -> RawRecord:
    payload = msgspec.json.decode(line)
    if not isinstance(payload, dict):
        raise msgspec.DecodeError("event is not a JSON object")
    return RawRecord(
        source=source, payload=payload, raw=line, received_at=now_utc_iso()
    )


def iter_file_records(path: str | Path) -> Iterator[RawRecord]:
    """Yield RawRecords from a JSON array, NDJSON, or CSV file.

    A single undecodable line/element must not stop ingestion: it is logged
    and skipped (there is no event to emit if the container itself cannot be
    decoded; per-FIELD failures are handled later by the normalizer).
    """
    path = Path(path)
    if not path.exists():
        raise IngestError(f"input file not found: {path}")
    data = path.read_bytes()

    if path.suffix.lower() == ".csv":
        yield from _iter_csv_records(data)
        return

    stripped = data.lstrip()
    if stripped.startswith(b"["):
        try:
            events = msgspec.json.decode(data)
        except msgspec.DecodeError as exc:
            raise IngestError(f"cannot decode JSON array file {path}: {exc}") from exc
        for event in events:
            if not isinstance(event, dict):
                logger.warning("skipping non-object element in %s", path)
                continue
            yield RawRecord(
                source="file",
                payload=event,
                raw=msgspec.json.encode(event),
                received_at=now_utc_iso(),
            )
        return

    for lineno, line in enumerate(data.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            yield _decode_json_line(line, "file")
        except msgspec.DecodeError as exc:
            logger.warning("skipping undecodable line %d in %s: %s", lineno, path, exc)


def _iter_csv_records(data: bytes) -> Iterator[RawRecord]:
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    reader = csv.DictReader(io.StringIO(text))
    # DictReader consumes the header (line 0); rows start at line 1.
    for idx, row in enumerate(reader, start=1):
        raw_line = lines[idx].encode("utf-8") if idx < len(lines) else b""
        yield RawRecord(
            source="file",
            payload={k: v for k, v in row.items() if k is not None},
            raw=raw_line,
            received_at=now_utc_iso(),
        )


def hit_to_record(hit: dict[str, Any]) -> RawRecord:
    """Wrap an Elastic hit (with ``_id``/``_source``) as a RawRecord."""
    return RawRecord(
        source="elastic",
        payload=hit,
        raw=msgspec.json.encode(hit.get("_source", hit)),
        received_at=now_utc_iso(),
    )


async def iter_elastic_batch(
    connector: ElasticConnector, since_ms: int, until_ms: int
) -> AsyncIterator[RawRecord]:
    async for hit in connector.fetch_batch(since_ms, until_ms):
        yield hit_to_record(hit)


async def iter_elastic_poll(
    connector: ElasticConnector,
    since_ms: int | None = None,
    *,
    stop=None,
    on_cursor=None,
) -> AsyncIterator[RawRecord]:
    async for hit in connector.poll(since_ms, stop=stop, on_cursor=on_cursor):
        yield hit_to_record(hit)
