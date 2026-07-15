"""Triage service: correlation output -> triaged, reported, written-back.

The seam between the deterministic engine and the two output surfaces.
For each in-scope attack chain it

    1. runs the AI reasoner (RAG-grounded, schema-validated, post-validated),
    2. renders the report-ready case (report.py),
    3. builds the write-back document (cluster_id + dashboard_url),
    4. stores it locally and pushes it to Elastic when a writer is attached.

Degradation is honest: no ATT&CK KB or no reachable model means the
document ships with ``triage_status: ai_unavailable`` and the deterministic
correlation result — never an invented verdict.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from engine.ai.kb import AttackKB, KBError
from engine.ai.provider import ProviderManager
from engine.ai.reasoner import TriageError, TriageReasoner, TriageResult
from engine.ai.report import build_report
from engine.ai.retriever import RetrieverUnavailable, build_retriever
from engine.config import Config
from engine.connectors.writeback import (
    TRIAGE_STATUS_AI_UNAVAILABLE,
    ResultWriter,
    build_writeback_doc,
)
from engine.correlate.engine import Cluster, CorrelationEngine

logger = logging.getLogger(__name__)

#: Bound on the in-process document mirror. Elasticsearch is the source of
#: truth; documents evicted here remain readable through the results index.
MAX_LOCAL_RESULTS = 500


class TriageService:
    """Orchestrates AI triage, reporting, and write-back for chains."""

    def __init__(
        self,
        config: Config,
        provider_manager: Optional[ProviderManager] = None,
        *,
        writer: Optional[ResultWriter] = None,
        create_fn: Optional[Callable] = None,
        ai_enabled: bool = True,
    ) -> None:
        self._config = config
        self.providers = provider_manager or ProviderManager(config.ai)
        self._writer = writer
        self._create_fn = create_fn
        self._ai_enabled = ai_enabled
        self._kb: Optional[AttackKB] = None
        self._reasoner: Optional[TriageReasoner] = None
        self._ai_disabled_reason = ""
        self._results: dict[str, dict[str, Any]] = {}
        #: cluster_id -> fingerprint of the chain state last processed, so
        #: unchanged chains are not re-triaged (and re-written) every cycle.
        self._fingerprints: dict[str, tuple] = {}

    # -- AI stack (lazy, honest about unavailability) --------------------------

    @property
    def kb(self) -> Optional[AttackKB]:
        self._ensure_ai_stack()
        return self._kb

    @property
    def ai_enabled(self) -> bool:
        """False when this process was started with AI triage switched off."""
        return self._ai_enabled

    @property
    def ai_available(self) -> bool:
        self._ensure_ai_stack()
        return self._reasoner is not None

    @property
    def ai_disabled_reason(self) -> str:
        self._ensure_ai_stack()
        return self._ai_disabled_reason

    def _ensure_ai_stack(self) -> None:
        if self._reasoner is not None or self._ai_disabled_reason:
            return
        try:
            self._kb = AttackKB.load(self._config.ai.rag.kb_path)
            retriever = build_retriever(self._kb, self._config.ai.rag)
        except (KBError, RetrieverUnavailable) as exc:
            self._ai_disabled_reason = str(exc)
            logger.warning("AI triage disabled: %s", exc)
            return
        self._reasoner = TriageReasoner(
            self.providers, retriever, self._config.ai,
            create_fn=self._create_fn,
        )

    # -- results store ----------------------------------------------------------

    @property
    def results(self) -> dict[str, dict[str, Any]]:
        """Chain documents from this process, keyed by cluster_id."""
        return self._results

    def get_result(self, cluster_id: str) -> Optional[dict[str, Any]]:
        return self._results.get(cluster_id)

    # -- processing ---------------------------------------------------------------

    def in_scope(self, cluster: Cluster) -> bool:
        if self._config.ai.triage_scope == "all":
            return True
        return cluster.surfaced

    def _fingerprint(self, cluster: Cluster) -> tuple:
        """Chain state relevant to triage: alert set + provider identity.

        A chain is re-processed when it gains alerts (or the surfaced flag
        flips) or when the AI provider changed — never merely because a poll
        evaluation cycle happened to run.
        """
        return (
            tuple(cluster.alert_uids),
            cluster.surfaced,
            self.providers.current.model_id if self._ai_enabled else "",
        )

    async def process_cluster(
        self,
        engine: CorrelationEngine,
        cluster: Cluster,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Triage + report + write back one chain; returns its document."""
        fingerprint = self._fingerprint(cluster)
        if not force:
            existing = self._results.get(cluster.cluster_id)
            if (
                existing is not None
                and self._fingerprints.get(cluster.cluster_id) == fingerprint
            ):
                if existing.get("triage_status") != TRIAGE_STATUS_AI_UNAVAILABLE:
                    return existing
                # Earlier triage failed. Self-heal when the provider looks
                # reachable again, but never hammer a dead endpoint with
                # full-timeout calls every evaluation cycle.
                status = await self.providers.current.health()
                if status.reachable is False:
                    return existing
        summary = engine.cluster_summary(cluster)
        dashboard_url = self._config.output.dashboard_url_for(
            cluster.cluster_id
        )

        triage: Optional[TriageResult] = None
        triage_status: Optional[str] = None
        triage_error = ""
        if self._ai_enabled and (force or self.in_scope(cluster)):
            if self.ai_available:
                try:
                    triage = await self._reasoner.triage(engine, cluster)
                except TriageError as exc:
                    triage_status = TRIAGE_STATUS_AI_UNAVAILABLE
                    # First line only: the document needs the reason, the
                    # full traceback belongs in the engine log.
                    triage_error = str(exc).split("\n", 1)[0][:500]
                    logger.warning("%s", exc)
            else:
                triage_status = TRIAGE_STATUS_AI_UNAVAILABLE
                triage_error = self.ai_disabled_reason

        report_markdown = build_report(
            summary, triage, kb=self._kb, dashboard_url=dashboard_url
        )
        doc = build_writeback_doc(
            summary,
            triage,
            self._config.output,
            report_markdown=report_markdown,
            triage_status=triage_status,
            triage_error=triage_error,
        )
        self._store_result(cluster.cluster_id, doc, fingerprint)
        if self._writer is not None:
            await self._writer.write(doc)
        return doc

    def _store_result(
        self, cluster_id: str, doc: dict[str, Any], fingerprint: tuple
    ) -> None:
        """Keep the local mirror bounded; oldest documents are evicted first
        (they stay available through the Elastic results index)."""
        self._results.pop(cluster_id, None)  # re-insert as most recent
        self._results[cluster_id] = doc
        self._fingerprints[cluster_id] = fingerprint
        while len(self._results) > MAX_LOCAL_RESULTS:
            oldest = next(iter(self._results))
            del self._results[oldest]
            self._fingerprints.pop(oldest, None)

    async def process_all(
        self,
        engine: CorrelationEngine,
        clusters: list[Cluster],
    ) -> list[dict[str, Any]]:
        """Process every chain (in-scope ones get AI triage)."""
        docs = []
        for cluster in clusters:
            docs.append(await self.process_cluster(engine, cluster))
        return docs
