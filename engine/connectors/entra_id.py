"""Microsoft Entra ID sign-in and directory-audit records (identity context).

These are *context*, not detections: the connector only acquires them. They
are normalised to ``ContextObservation`` and never raise the alert count.
"""

from __future__ import annotations

from typing import Any

from engine.connectors.base import ConnectorError, RecordIdentity
from engine.connectors.defender_xdr import GraphPagedConnector
from engine.envelope import KIND_DIRECTORY_AUDIT, KIND_SIGNIN

PATHS = {
    "signins": "/v1.0/auditLogs/signIns",
    "directory_audits": "/v1.0/auditLogs/directoryAudits",
}


class EntraIdConnector(GraphPagedConnector):
    provider = "entra_id"
    paths = PATHS
    streams = tuple(PATHS)
    filter_field = "createdDateTime"
    filter_fields = {"directory_audits": "activityDateTime"}

    def identify(self, record: dict[str, Any], stream: str) -> RecordIdentity:
        rid = str(record.get("id") or "")
        if not rid:
            raise ConnectorError("Graph audit record has no id",
                                 code="malformed_record")
        kind = KIND_SIGNIN if stream == "signins" else KIND_DIRECTORY_AUDIT
        return RecordIdentity(
            record_kind=kind, source_event_id=rid, namespace=self._tenant,
            event_time=record.get("createdDateTime") or record.get("activityDateTime"),
            provenance={"platform": "microsoft_graph", "stream": stream,
                        "correlation_id": record.get("correlationId")},
        )
