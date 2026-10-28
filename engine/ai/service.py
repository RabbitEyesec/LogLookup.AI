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

import hashlib
import json
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
        #: optional ``async (summary) -> {"identity": ..., "actions": [...]}``
        #: installed by the v2 runtime; supplies deterministic context only.
        self.context_provider: Optional[Callable] = None

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

    @staticmethod
    def _stamp(engine: CorrelationEngine, cluster: Cluster) -> str:
        """Fingerprint of the evidence an analysis would be based on.
        It changes when an alert is revised in a way that matters (severity,
        title, ATT&CK, host, user, process, time) and not otherwise."""
        parts = []
        for a in engine.alerts_of(cluster):
            device = a.device.hostname if a.device else ""
            user = a.actor.user.name if a.actor and a.actor.user else ""
            proc = a.actor.process if a.actor else None
            attacks = sorted(
                (x.tactic.name if x.tactic else "",
                 x.technique.uid if x.technique else "")
                for x in a.finding_info.attacks)
            parts.append([a.uid, a.time, a.severity_id, a.finding_info.title,
                          device, user, proc.name if proc else "",
                          proc.cmd_line if proc else "", attacks])
        return hashlib.sha256(
            json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:20]

    def _fingerprint(self, cluster: Cluster, stamp: str = "") -> tuple:
        """Chain state relevant to triage: alert set + provider identity.

        A chain is re-processed when it gains alerts (or the surfaced flag
        flips) or when the AI provider changed — never merely because a poll
        evaluation cycle happened to run.
        """
        return (
            tuple(cluster.alert_uids),
            cluster.surfaced,
            self.providers.current.model_id if self._ai_enabled else "",
            stamp,
        )

    async def process_cluster(
        self,
        engine: CorrelationEngine,
        cluster: Cluster,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Triage + report + write back one chain; returns its document."""
        stamp = self._stamp(engine, cluster)
        fingerprint = self._fingerprint(cluster, stamp)
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
        existing = self._results.get(cluster.cluster_id)
        if (not force and existing is not None and existing.get("triage")
                and existing.get("evidence_stamp") not in (None, stamp)):
            return await self._mark_stale(engine, cluster, existing, stamp,
                                          fingerprint)
        summary = engine.cluster_summary(cluster)
        context: dict[str, Any] = {}
        if self.context_provider is not None:
            try:
                context = await self.context_provider(summary) or {}
            except Exception:  # context is additive; never block triage on it
                logger.exception("context provider failed for %s",
                                 cluster.cluster_id)
        dashboard_url = self._config.output.dashboard_url_for(
            cluster.cluster_id
        )

        triage: Optional[TriageResult] = None
        triage_status: Optional[str] = None
        triage_error = ""
        if self._ai_enabled and (force or self.in_scope(cluster)):
            if self.ai_available:
                try:
                    triage = await self._reasoner.triage(
                        engine, cluster, context=context or None)
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
            summary, triage, kb=self._kb, dashboard_url=dashboard_url,
            context=context,
        )
        doc = build_writeback_doc(
            summary,
            triage,
            self._config.output,
            report_markdown=report_markdown,
            triage_status=triage_status,
            triage_error=triage_error,
        )
        doc["evidence_stamp"] = stamp
        self._store_result(cluster.cluster_id, doc, fingerprint)
        if self._writer is not None:
            await self._writer.write(doc)
        return doc

    async def _mark_stale(self, engine: CorrelationEngine, cluster: Cluster,
                          existing: dict[str, Any], stamp: str,
                          fingerprint: tuple) -> dict[str, Any]:
        """The evidence changed after an AI analysis was written.

        The chain facts (risk, timeline) are refreshed, the earlier analysis
        is kept but clearly marked stale, and no new analysis is requested
        automatically - a person re-runs it.
        """
        summary = engine.cluster_summary(cluster)
        doc = build_writeback_doc(
            summary, None, self._config.output,
            report_markdown=existing.get("report_markdown", ""),
            triage_status=existing.get("triage_status"))
        doc["triage"] = existing["triage"]
        doc["triage_status"] = existing.get("triage_status")
        doc["triage_stale"] = True
        doc["triage_stale_reason"] = (
            "The evidence changed after this analysis (an alert was revised). "
            "Re-run triage to refresh it.")
        doc["evidence_stamp"] = existing.get("evidence_stamp")  # what it analysed
        doc["current_evidence_stamp"] = stamp
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
