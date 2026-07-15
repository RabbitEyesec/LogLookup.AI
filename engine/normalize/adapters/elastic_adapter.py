"""Elastic adapter: maps ECS / Kibana alert documents to OCSF."""

from __future__ import annotations

from engine.ingest import RawRecord
from engine.normalize.adapters.base import MappedAdapter


class ElasticAdapter(MappedAdapter):
    name = "elastic"
    mapping_file = "elastic.yaml"

    def event_of(self, record: RawRecord) -> dict:
        # Connector records carry the full hit; map from _source.
        payload = record.payload
        return payload.get("_source", payload)

    def uid_fallback(self, record: RawRecord) -> str:
        return str(record.payload.get("_id", ""))
