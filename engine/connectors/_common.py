"""Small helpers shared by the provider connectors."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from engine.connectors.base import ConfigurationError

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
