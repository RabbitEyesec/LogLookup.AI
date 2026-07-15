"""Microsoft Sentinel adapter stub — documented, not built in v1.0.

The stub exists to prove the adapter pattern's extensibility (build plan
section 2.2: "Splunk / Sentinel adapters (stubs prove the pattern)").
"""

from __future__ import annotations

from engine.ingest import RawRecord
from engine.normalize.adapters.base import AdapterInterface, AdapterNotImplemented
from engine.normalize.ocsf import NormalizedAlert


class SentinelAdapter(AdapterInterface):
    name = "sentinel"

    def parse(self, record: RawRecord) -> NormalizedAlert:
        raise AdapterNotImplemented(
            "The Sentinel adapter is a documented v1.0 stub; only 'elastic' "
            "and 'file' sources are implemented."
        )
