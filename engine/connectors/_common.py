"""Small helpers shared by the provider connectors."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from engine.connectors.base import (
    CURSOR_CONFIG_CHANGED, CURSOR_MIGRATED_FROM_V1, STATUS_DEGRADED,
    ConfigurationError, ConnectorError,
)

CURSOR_VERSION = 2

_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    # Graph/Kusto can emit 7 fractional digits; datetime accepts 6.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def require_guid(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _GUID.match(value):
        raise ConfigurationError(f"{name} must be a GUID")
    return value


def option_list(options: dict[str, Any], key: str, default: list[str]) -> list[str]:
    value = options.get(key, default)
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(v, str) for v in value
    ):
        raise ConfigurationError(f"{key} must be a list of strings")
    return list(value)


def window_for(
    cursor: dict[str, Any] | None, now: datetime, lookback_seconds: int
) -> tuple[datetime, datetime, bool]:
    """Bounded overlapping scan window: ``(start, end, is_continuation)``.

    First run looks back ``lookback_seconds``. Later runs restart
    ``lookback_seconds`` before the last committed ``window_end`` (an
    intentional overlap: the ledger dedups, late arrivals are caught).
    A continuation resumes mid-window from ``page_start``.
    """
    overlap = timedelta(seconds=lookback_seconds)
    if cursor is None:
        return now - overlap, now, False
    if cursor.get("continue"):
        return (parse_iso(cursor["page_start"]), parse_iso(cursor["window_end"]),
                True)
    return parse_iso(cursor["window_end"]) - overlap, now, False


def fingerprint(*parts: Any) -> str:
    """Stable identity of everything a saved cursor depends on (workspace,
    indexes, template version...). A cursor whose fingerprint differs from the
    connection's current one belongs to a different query and is never
    continued."""
    return hashlib.sha256(
        "\x1f".join(str(p) for p in parts).encode("utf-8")
    ).hexdigest()[:24]


def backfill_cursor(start: datetime, end: datetime,
                    event_time_floor: int | None = None) -> dict[str, Any]:
    """Trusted in-process cursor for an explicit, bounded re-read.

    One dict carries every connector's keys, each connector reads its own:
    ``window_*`` (Sentinel, Splunk), ``page_start`` (Graph), ``since_ms`` /
    ``until_ms`` (Elastic). It is never persisted, so a backfill can never
    overwrite the live checkpoint.
    """
    cursor = {
        "cursor_version": CURSOR_VERSION, "backfill": True, "continue": True,
        "window_start": iso_z(start), "window_end": iso_z(end),
        "page_start": iso_z(start),
        "since_ms": int(start.timestamp() * 1000),
        "until_ms": int(end.timestamp() * 1000),
    }
    if event_time_floor is not None:  # Splunk: 0 = no event-time floor
        cursor["event_time_floor"] = event_time_floor
    return cursor


@dataclass
class ScanWindow:
    start: datetime
    end: datetime
    continuing: bool
    warnings: list[str] = field(default_factory=list)
    trusted_backfill: bool = False


def resolve_window(
    cursor: dict[str, Any] | None, now: datetime, lookback_seconds: int,
    fp: str,
) -> ScanWindow:
    """Decide the scan window for the next page.

    * first run                      -> look back ``lookback_seconds``
    * v2 cursor, mid-window          -> the SAME frozen window, continue
    * v2 cursor, window drained      -> restart ``lookback_seconds`` before
                                        the drained window's end (overlap)
    * v2 cursor, other fingerprint   -> different query: STOP. The saved
                                        cursor is kept and an administrator
                                        must confirm a new scan or backfill
    * legacy (v2.0.0) cursor         -> bounded overlap restart, no gap
    """
    overlap = timedelta(seconds=lookback_seconds)
    if cursor is None:
        return ScanWindow(now - overlap, now, False)
    if cursor.get("backfill"):
        return ScanWindow(parse_iso(cursor["window_start"]),
                          parse_iso(cursor["window_end"]),
                          bool(cursor.get("continue")), trusted_backfill=True)
    if cursor.get("cursor_version") == CURSOR_VERSION:
        if cursor.get("fingerprint") != fp:
            raise ConnectorError(
                "the saved cursor belongs to a different workspace, index set or "
                "query; an administrator must confirm a new scan or run a "
                "bounded backfill",
                status=STATUS_DEGRADED, code=CURSOR_CONFIG_CHANGED)
        if cursor.get("continue"):
            return ScanWindow(parse_iso(cursor["window_start"]),
                              parse_iso(cursor["window_end"]), True)
        return ScanWindow(parse_iso(cursor["window_end"]) - overlap, now, False)
    # v2.0.0 timestamp-only cursor: re-scan a bounded overlap, rely on the
    # ledger to drop what was already stored.
    if cursor.get("continue") and cursor.get("page_start"):
        return ScanWindow(parse_iso(cursor["page_start"]) - overlap,
                          parse_iso(cursor["window_end"]), False,
                          [CURSOR_MIGRATED_FROM_V1])
    return ScanWindow(parse_iso(cursor["window_end"]) - overlap, now, False,
                      [CURSOR_MIGRATED_FROM_V1])
