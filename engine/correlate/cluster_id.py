"""cluster_id generation  the join key for everything downstream.

LOCKED FORMAT (Master Specification 5.2): human-readable
``CHAIN-YYYY-MM-DD-<entity>-NNN``, e.g. ``CHAIN-2026-07-11-hostA-001``.

- date: UTC date of the chain's earliest alert;
- entity: the chain's primary entity display name, sanitized;
- NNN: 3-digit sequence per (date, entity), assigned in event-time order of
  chain formation  the same input always yields the same ids.

Do not change this format without explicit approval: the SIEM write-back
tag and the dashboard deep link (later phases) both depend on it.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_PREFIX = "CHAIN"
_LABEL_MAX = 40
_SANITIZE = re.compile(r"[^A-Za-z0-9_-]+")


def sanitize_label(name: str) -> str:
    label = _SANITIZE.sub("-", name.strip()).strip("-")[:_LABEL_MAX].strip("-")
    return label or "entity"


def date_of(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%d"
    )


class ClusterIdGenerator:
    """Deterministic per-(date, entity) sequence numbers."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, str], int] = {}

    def next_id(self, first_time_ms: int, entity_name: str) -> str:
        date = date_of(first_time_ms)
        label = sanitize_label(entity_name)
        key = (date, label)
        self._counters[key] = self._counters.get(key, 0) + 1
        return f"{_PREFIX}-{date}-{label}-{self._counters[key]:03d}"
