"""Write-back: push triaged attack chains into Elasticsearch.

Phase 5 of the Build Plan the milestone that makes LogLookup a usable
tool: every chain becomes one document in the results index, tagged with
its ``cluster_id`` (the document id, so writes are idempotent) and a
``dashboard_url`` deep link. Elasticsearch remains the single source of
truth: Kibana and the correlation dashboard both read these documents.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from engine.ai.reasoner import TriageResult
from engine.config import OutputConfig
from engine.connectors.elastic import ConnectorError, ElasticConnector
from engine.normalize.timeutil import ms_to_iso, now_utc_iso

logger = logging.getLogger(__name__)

TRIAGE_STATUS_TRIAGED = "triaged"
TRIAGE_STATUS_AI_UNAVAILABLE = "ai_unavailable"
TRIAGE_STATUS_PENDING = "pending"


def build_writeback_doc(
    summary: dict[str, Any],
    triage: Optional[TriageResult],
    output: OutputConfig,
    *,
    report_markdown: str = "",
    triage_status: Optional[str] = None,
    triage_error: str = "",
) -> dict[str, Any]:
    """One results-index document for one attack chain.

    ``summary`` is CorrelationEngine.cluster_summary() output. When the AI
    layer was unavailable the document still carries the deterministic
    correlation result, honestly marked ``ai_unavailable`` — never a
    fabricated verdict.
    """
    cluster_id = summary["cluster_id"]
    doc: dict[str, Any] = {
        # Event time of the chain's latest alert, so the document sits on
        # the incident timeline in Kibana rather than at ingest time.
        "@timestamp": ms_to_iso(summary["last_time"]),
        "cluster_id": cluster_id,
        "dashboard_url": output.dashboard_url_for(cluster_id),
        "source": "loglookup-ai",
        "written_at": now_utc_iso(),
        "chain": {
            "alert_count": summary["alert_count"],
            "alerts": summary["alerts"],
            "entities": summary.get("entities", []),
            "primary_entity": summary["primary_entity"],
            "first_time": ms_to_iso(summary["first_time"]),
            "last_time": ms_to_iso(summary["last_time"]),
            "tactic_sequence": summary["tactic_sequence"],
            "disposition": summary["disposition"],
            "risk_score": summary["risk_score"],
            "surfaced": summary["surfaced"],
        },
    }
    if triage is not None:
        doc["triage_status"] = triage_status or TRIAGE_STATUS_TRIAGED
        doc["triage"] = triage.as_dict()
    else:
        doc["triage_status"] = triage_status or TRIAGE_STATUS_PENDING
        if triage_error:
            doc["triage_error"] = triage_error
    if report_markdown:
        doc["report_markdown"] = report_markdown
    return doc


class ResultWriter:
    """Writes chain documents to the configured Elastic results index."""

    def __init__(self, connector: ElasticConnector, output: OutputConfig) -> None:
        self._connector = connector
        self._index = output.results_index

    @property
    def index(self) -> str:
        return self._index

    async def write(self, doc: dict[str, Any]) -> bool:
        """Index one chain document; returns False on connector failure.

        A write-back failure must not kill the pipeline — the result is
        logged and the caller keeps the document in its local store.
        """
        cluster_id = doc["cluster_id"]
        try:
            await self._connector.index_doc(self._index, cluster_id, doc)
        except ConnectorError as exc:
            logger.error("write-back failed for %s: %s", cluster_id, exc)
            return False
        logger.info("write-back: %s -> %s (%s)", cluster_id, self._index,
                    doc.get("triage_status"))
        return True

    async def read(self, cluster_id: str) -> Optional[dict[str, Any]]:
        """Fetch a previously written chain document (dashboard deep links)."""
        try:
            return await self._connector.get_doc(self._index, cluster_id)
        except ConnectorError as exc:
            logger.warning("result lookup failed for %s: %s", cluster_id, exc)
            return None
