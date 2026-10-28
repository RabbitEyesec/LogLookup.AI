"""Splunk adapter: search results / ES notables -> OCSF Detection Finding.

Splunk deployments differ in sourcetypes and field names, so the adapter
accepts CIM-style names by default and a connection-level ``field_aliases``
map (``{canonical_name: [splunk_field, ...]}``) for site-specific fields.
The vendor severity word is preserved in OCSF ``severity`` alongside the
normalised ``severity_id``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from engine.ingest import RawRecord
from engine.normalize.adapters.base import MappedAdapter

DEFAULT_ALIASES: dict[str, list[str]] = {}


def _epoch_to_iso(value: Any) -> Any:
    """Splunk may emit ``_time`` as epoch seconds; keep ISO strings as-is."""
    if isinstance(value, list) and value:
        value = value[0]
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return value
    if not 946684800 <= seconds <= 4102444800:  # year 2000..2100
        return value
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


class SplunkAdapter(MappedAdapter):
    name = "splunk"
    mapping_file = "splunk.yaml"

    def __init__(self, *, field_aliases: dict[str, list[str]] | None = None,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._aliases = {**DEFAULT_ALIASES, **(field_aliases or {})}

    def event_of(self, record: RawRecord) -> dict:
        event = dict(record.payload)
        event["_time"] = _epoch_to_iso(event.get("_time"))
        for canonical, candidates in self._aliases.items():
            if event.get(canonical) not in (None, "", []):
                continue
            for candidate in candidates:
                if event.get(candidate) not in (None, "", []):
                    event[canonical] = event[candidate]
                    break
        return event

    def uid_fallback(self, record: RawRecord) -> str:
        p = record.payload
        ident = p.get("event_id") or p.get("_cd") or ""
        return str(ident[0] if isinstance(ident, list) and ident else ident)
