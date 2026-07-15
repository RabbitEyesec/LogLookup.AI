"""Adapter interface: SourceAdapter.parse(raw) -> OCSF NormalizedAlert.

A new SIEM means a new adapter; the core engine stays untouched. Mapped
adapters are driven by a per-source YAML spec (declarative field rules) plus
the Python transform hooks in ``engine.normalize.mapping``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from engine.ingest import RawRecord
from engine.normalize.mapping import MappingSpec, apply_mapping
from engine.normalize.ocsf import NormalizedAlert

MAPPINGS_DIR = Path(__file__).parent / "mappings"


class AdapterNotImplemented(NotImplementedError):
    """Raised by documented stub adapters (splunk, sentinel)."""


class AdapterInterface(ABC):
    """Translate one source's raw records into validated OCSF alerts."""

    name: str = "base"

    @abstractmethod
    def parse(self, record: RawRecord) -> NormalizedAlert:
        """Map a raw record to OCSF. Per-field failures are flagged and
        routed to ``unmapped``; this only raises if the record as a whole is
        unusable (which ingestion already guards against)."""


class MappedAdapter(AdapterInterface):
    """Adapter driven by a declarative YAML mapping spec."""

    mapping_file: str = ""

    def __init__(
        self,
        *,
        default_offset_minutes: int | None = None,
        assume_year: int | None = None,
    ) -> None:
        # Adapter config: hardcoded UTC offset for legacy sources that omit
        # a timezone, per the source's geographic origin.
        self._default_offset_minutes = default_offset_minutes
        self._assume_year = assume_year
        self._spec = MappingSpec.from_yaml(MAPPINGS_DIR / self.mapping_file)

    def event_of(self, record: RawRecord) -> dict:
        return record.payload

    def uid_fallback(self, record: RawRecord) -> str:
        return ""

    def parse(self, record: RawRecord) -> NormalizedAlert:
        result = apply_mapping(
            self._spec,
            self.event_of(record),
            raw=record.raw,
            received_at=record.received_at,
            uid_fallback=self.uid_fallback(record),
            default_offset_minutes=self._default_offset_minutes,
            assume_year=self._assume_year,
        )
        return result.alert


def get_adapter(source_type: str, **kwargs) -> AdapterInterface:
    """Router: identify source -> SourceAdapter."""
    from engine.normalize.adapters.elastic_adapter import ElasticAdapter
    from engine.normalize.adapters.file_adapter import FileAdapter
    from engine.normalize.adapters.sentinel_adapter import SentinelAdapter
    from engine.normalize.adapters.splunk_adapter import SplunkAdapter

    adapters: dict[str, type[AdapterInterface]] = {
        "elastic": ElasticAdapter,
        "file": FileAdapter,
        "splunk": SplunkAdapter,
        "sentinel": SentinelAdapter,
    }
    try:
        adapter_cls = adapters[source_type.lower()]
    except KeyError:
        raise KeyError(
            f"unknown source type {source_type!r}; expected one of "
            f"{sorted(adapters)}"
        ) from None
    return adapter_cls(**kwargs)
