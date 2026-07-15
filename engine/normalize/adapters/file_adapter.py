"""Generic JSON/CSV file adapter — portable, used for tests and demos."""

from __future__ import annotations

import hashlib

from engine.ingest import RawRecord
from engine.normalize.adapters.base import MappedAdapter


class FileAdapter(MappedAdapter):
    name = "file"
    mapping_file = "file.yaml"

    def uid_fallback(self, record: RawRecord) -> str:
        # Deterministic id for sources without one: hash of the raw event.
        return hashlib.sha256(record.raw).hexdigest()[:16]
