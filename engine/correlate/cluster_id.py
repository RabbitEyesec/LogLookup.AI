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
    """Deterministic per-(date, entity) sequence numbers.

    v2 durability: ``preload`` seeds the generator from the investigation
    store. A chain is identified by its *anchor* (its earliest alert uid);
    when the same anchor forms a chain again after a restart or an
    overlapping re-read, the previously issued id is returned instead of a
    new sequence number, and new ids continue after the highest persisted
    sequence so an old id is never reissued to a different chain.
    """

    def __init__(self) -> None:
        self._counters: dict[tuple[str, str], int] = {}
        self._by_anchor: dict[str, str] = {}

    def preload(
        self,
        anchors: dict[str, str],
        counters: dict[tuple[str, str], int],
    ) -> None:
        self._by_anchor.update(anchors)
        for key, value in counters.items():
            self._counters[key] = max(self._counters.get(key, 0), value)

    @property
    def anchors(self) -> dict[str, str]:
        return dict(self._by_anchor)

    def next_id(
        self, first_time_ms: int, entity_name: str, anchor: str | None = None
    ) -> str:
        if anchor is not None and anchor in self._by_anchor:
            return self._by_anchor[anchor]
        date = date_of(first_time_ms)
        label = sanitize_label(entity_name)
        key = (date, label)
        self._counters[key] = self._counters.get(key, 0) + 1
        cluster_id = f"{_PREFIX}-{date}-{label}-{self._counters[key]:03d}"
        if anchor is not None:
            self._by_anchor[anchor] = cluster_id
        return cluster_id
