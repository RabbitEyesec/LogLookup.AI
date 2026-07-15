"""Timestamp coercion: EVERY timestamp -> UTC ISO-8601 with Z (non-negotiable).

Accepted inputs: ISO-8601 (with or without zone), epoch seconds /
milliseconds, and legacy RFC 3164 syslog ("Oct  3 10:15:32", no year, no
zone). Sources that omit a zone get the adapter-configured fixed offset for
their geographic origin.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

MS = 1000

_SYSLOG_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})$"
)
_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}


class TimestampError(ValueError):
    """Raised when a timestamp cannot be coerced to UTC."""


def _offset_tz(offset_minutes: int) -> timezone:
    return timezone(timedelta(minutes=offset_minutes))


def to_utc_datetime(
    value: object,
    *,
    default_offset_minutes: int = 0,
    assume_year: int | None = None,
) -> datetime:
    """Coerce a source timestamp to an aware UTC datetime.

    ``default_offset_minutes`` is the hardcoded offset for legacy sources
    that omit a timezone. ``assume_year`` fills RFC 3164's missing year
    (defaults to the current UTC year).
    """
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_offset_tz(default_offset_minutes))
        return dt.astimezone(timezone.utc)

    if isinstance(value, bool):
        raise TimestampError(f"not a timestamp: {value!r}")

    if isinstance(value, (int, float)):
        # Heuristic per epoch magnitude: >= 1e12 is milliseconds
        # (1e12 ms ~ 2001; 1e12 s would be year 33658).
        seconds = float(value) / MS if abs(float(value)) >= 1e12 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise TimestampError(f"epoch out of range: {value!r}") from exc

    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise TimestampError("empty timestamp")

        # Epoch encoded as string
        if re.fullmatch(r"-?\d{9,}", text):
            return to_utc_datetime(int(text),
                                   default_offset_minutes=default_offset_minutes)

        # RFC 3164 syslog: no year, no zone
        match = _SYSLOG_RE.match(text)
        if match:
            year = assume_year or datetime.now(timezone.utc).year
            hh, mm, ss = (int(p) for p in match.group("time").split(":"))
            try:
                dt = datetime(
                    year, _MONTHS[match.group("mon")], int(match.group("day")),
                    hh, mm, ss, tzinfo=_offset_tz(default_offset_minutes),
                )
            except ValueError as exc:
                raise TimestampError(f"invalid syslog timestamp: {text!r}") from exc
            return dt.astimezone(timezone.utc)

        # ISO-8601 (fromisoformat in 3.11+ accepts Z and most variants)
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise TimestampError(f"unparseable timestamp: {text!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_offset_tz(default_offset_minutes))
        return dt.astimezone(timezone.utc)

    raise TimestampError(f"unsupported timestamp type: {type(value).__name__}")


def to_iso_z(dt: datetime) -> str:
    """Aware UTC datetime -> ISO-8601 string with explicit Z."""
    dt = dt.astimezone(timezone.utc)
    text = dt.isoformat(timespec="milliseconds")
    return text.replace("+00:00", "Z")


def to_epoch_ms(dt: datetime) -> int:
    return int(dt.astimezone(timezone.utc).timestamp() * MS)


def coerce_time(
    value: object,
    *,
    default_offset_minutes: int = 0,
    assume_year: int | None = None,
) -> tuple[int, str]:
    """Coerce any source timestamp to ``(epoch_ms_utc, iso8601_z)``."""
    dt = to_utc_datetime(
        value,
        default_offset_minutes=default_offset_minutes,
        assume_year=assume_year,
    )
    return to_epoch_ms(dt), to_iso_z(dt)


def now_utc_iso() -> str:
    return to_iso_z(datetime.now(timezone.utc))


def ms_to_iso(epoch_ms: int) -> str:
    """Epoch milliseconds UTC -> ISO-8601 string with explicit Z."""
    return to_iso_z(datetime.fromtimestamp(epoch_ms / MS, tz=timezone.utc))
