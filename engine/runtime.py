"""V2Runtime: durable multi-source orchestration around the pipeline.

Owns the SQLite store, the connector supervisor, the evaluation loop that
turns committed observations into persisted investigation revisions, and
the approval-gated response dispatcher. The deterministic pipeline is
unchanged; this layer feeds it and persists what it produces.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path
from typing import Any, Callable

import httpx
import msgspec

from engine.config import Config
from engine.connectors.base import SourceConnection, STATUS_PAUSED
from engine.connectors.outputs.logic_apps import LogicAppsTransport
from engine.connectors.registry import REGISTRY, build_connector
from engine.connectors.supervisor import Supervisor
from engine.enrich.identity import identity_context
from engine.envelope import evidence_ref
from engine.ingest import RawRecord
from engine.normalize.timeutil import now_utc_iso
from engine.pipeline import Pipeline
from engine.response.approvals import ActionService
from engine.response.audit import AuditLog
from engine.response.dispatcher import Dispatcher
from engine.response.outbox import Outbox
from engine.response.policy import ResponsePolicy
from engine.response.reconcile import Reconciler
from engine.secure.store import SecretStore, auth_profile_name
from engine.store import (CursorStore, Database, EvidenceVault, InvestigationStore,
                          Ledger)
from engine.store.connections import ConnectionRepo
from engine.store.ledger import AcceptedRecord

logger = logging.getLogger(__name__)

EVIDENCE_KEY_PURPOSE = "evidence-vault"


class V2Runtime:
    def __init__(
        self,
        config: Config,
        pipeline: Pipeline,
        service,
        secrets: SecretStore,
        home: Path,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
        token_getter_factory: Callable[[SourceConnection], Any] | None = None,
        logic_transport=None,
        evaluate_interval: float | None = None,
        db_path: Path | None = None,
        include_legacy: bool = False,
        legacy_health: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config
        self.pipeline = pipeline
        self.service = service
        self.secrets = secrets
        self.home = Path(home)
        self.scope_id = config.scope_id
        self._http_transport = http_transport
        self._token_getter_factory = token_getter_factory
        #: expose the original single-Elastic ``siem`` block as a connection
        #: only when this process is actually polling it
        self._include_legacy = include_legacy
        #: async probe for the legacy poller's real reachability
        self.legacy_health = legacy_health
        self._logic_transport = logic_transport
        self._interval = evaluate_interval or max(
            5.0, config.correlation.evaluate_every_minutes * 60.0)
        path = Path(config.storage.db_path)
        self._db_path = db_path or (path if path.is_absolute() else self.home / path)
        self.db = Database(self._db_path)
        self._eval_task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._eval_lock = asyncio.Lock()
        self.revisions: dict[str, int] = {}
        self.started = False
        self._last_purge = float("-inf")

    # -- lifecycle ---------------------------------------------------------------

    async def start(self) -> None:
        await self.db.open()
        self.vault = EvidenceVault(self.secrets.derived_key(EVIDENCE_KEY_PURPOSE))
        self.ledger = Ledger(self.db, self.vault)
        self.cursors = CursorStore(self.db)
        self.investigations = InvestigationStore(self.db, self.scope_id)
        self.repo = ConnectionRepo(self.db, self.scope_id)
        self.audit = AuditLog(self.db)
        self.outbox = Outbox(self.db)
        la = self.config.logic_apps
        self.policy = ResponsePolicy(la.allowed_workflows)
        self.actions = ActionService(
            self.db, self.policy, self.audit, self.outbox, scope_id=self.scope_id,
            dispatch_enabled=la.enabled)
        self.reconciler = Reconciler(self.db, self.audit, self.actions, self.policy)
        self.dispatcher: Dispatcher | None = None
        transport = self._logic_transport or self._build_logic_transport()
        self.dispatcher = Dispatcher(self.db, self.outbox, transport, self.audit,
                                     self.policy)
        self.supervisor = Supervisor(
            self.db, self.ledger, self.cursors, self._make_connector,
            self._on_accepted)

        anchors, counters = await self.investigations.load_id_state()
        self.pipeline.correlator.preload_ids(anchors, counters)

        replayed = await self._rehydrate()
        if replayed:
            logger.info("rebuilt correlation state from %d ledger detection(s)",
                        replayed)

        for conn in self.config.effective_sources(self._include_legacy):
            await self.repo.upsert(conn)
        for conn, paused in await self.repo.list():
            # DB is authoritative for active/paused so UI changes persist.
            await self.supervisor.add(conn, start=False)
            worker = self.supervisor.workers[conn.connection_id]
            if paused:
                worker.pause()
        for conn, paused in await self.repo.list():
            worker = self.supervisor.workers[conn.connection_id]
            if conn.active and conn.origin != "legacy":
                await worker.start()
        if transport is not None and la.enabled:
            await self.dispatcher.start()
        self.service.context_provider = self._ai_context
        self._stop.clear()
        self._eval_task = asyncio.create_task(self._evaluate_loop())
        self.started = True
        logger.info("v2 runtime started (store=%s, sources=%d)", self._db_path,
                    len(self.supervisor.workers))

    async def stop(self) -> None:
        self._stop.set()
        if self._eval_task is not None:
            self._eval_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._eval_task
        if self.dispatcher is not None:
            await self.dispatcher.stop()
        await self.supervisor.stop()
        if self._logic_transport is None and getattr(
                self.dispatcher, "_transport", None) is not None:
            with contextlib.suppress(Exception):
                await self.dispatcher._transport.aclose()
        await self.db.close()
        self.started = False

    async def _rehydrate(self) -> int:
        """Replay recent ledger detections into the (empty) correlator."""
        records = await self.ledger.replayable_detections(
            self.config.correlation.entity_retention_minutes)
        for env, payload in records:
            self.pipeline.process(RawRecord(
                source=env.provider, payload=payload,
                raw=msgspec.json.encode(payload), received_at=now_utc_iso(),
                envelope=env))
        return len(records)

    def _build_logic_transport(self):
        la = self.config.logic_apps
        if not la.enabled:
            return None
        from engine.connectors.auth.microsoft import MicrosoftCredentialProvider, parse_profile
        import json

        raw = self.secrets.get(auth_profile_name(la.auth_profile_id))
        try:
            profile = json.loads(raw) if raw else {}
        except ValueError:
            profile = {}
        if not profile:
            logger.warning("Logic Apps enabled but auth profile %r is empty",
                           la.auth_profile_id)
            return None
        getter = None
        if profile.get("auth", "entra") == "entra":
            broker = MicrosoftCredentialProvider(
                str(profile.get("tenant_id", "")),
                parse_profile(json.dumps(profile.get("credential") or {})),
                profile_id=la.auth_profile_id)
            getter = broker.token
        try:
            return LogicAppsTransport(profile, token_getter=getter,
                                      timeout=float(la.timeout_seconds))
        except Exception as exc:
            logger.warning("Logic Apps transport unavailable: %s", exc)
            return None

    def _make_connector(self, conn: SourceConnection):
        return build_connector(conn, self.secrets, transport=self._http_transport,
                               token_getter_factory=self._token_getter_factory)

    # -- ingestion callback ---------------------------------------------------------------

    async def _on_accepted(self, conn: SourceConnection,
                           accepted: list[AcceptedRecord]) -> None:
        for rec in accepted:
            env = rec.envelope
            if rec.duplicate_of:
                logger.info("%s duplicates event %s; retained, not correlated",
                            evidence_ref(env), rec.duplicate_of[:12])
                continue
            if not env.is_detection:
                continue  # context / incident records: stored, not detections
            if rec.is_update:
                continue  # new revision is in the ledger; chain keeps first view
            self.pipeline.process(RawRecord(
                source=env.provider, payload=rec.payload,
                raw=msgspec.json.encode(rec.payload), received_at=now_utc_iso(),
                envelope=env))

    # -- evaluation + persistence ---------------------------------------------------------

    async def _purge_expired_evidence(self) -> None:
        """Retention: drop encrypted payloads past ``raw_retention_days``
        (content hashes and metadata remain), at most hourly."""
        import time

        now = time.monotonic()
        if now - self._last_purge < 3600:
            return
        self._last_purge = now
        dropped = await self.ledger.purge_raw_older_than(
            self.config.storage.raw_retention_days)
        if dropped:
            logger.info("retention: dropped %d expired raw payload(s)", dropped)

    async def _evaluate_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                return
            except asyncio.TimeoutError:
                pass
            try:
                await self.evaluate_now()
                await self._purge_expired_evidence()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("v2 evaluation cycle failed")

    async def evaluate_now(self) -> dict[str, int]:
        """Correlate, persist revisions, run triage. Safe to call on demand."""
        async with self._eval_lock:
            result = self.pipeline.evaluate()
            corr = self.pipeline.correlator
            summaries = [corr.cluster_summary(c) for c in result.clusters]
            self.revisions = await self.investigations.sync(
                summaries, corr.id_anchors, corr.merge_aliases())
            for summary in summaries:
                ids = [a["source"]["canonical_event_id"]
                       for a in summary["alerts"]
                       if (a.get("source") or {}).get("canonical_event_id")]
                await self.investigations.link_provider_incidents(
                    summary["cluster_id"], ids)
            if result.clusters:
                await self.service.process_all(corr, result.clusters)
            return self.revisions

    async def _ai_context(self, summary: dict[str, Any]) -> dict[str, Any]:
        """Deterministic supporting context for triage and reports."""
        actions = [a.view() for a in
                   await self.actions.list_for(summary["cluster_id"])]
        return {"identity": await self.context_for(summary), "actions": actions}

    # -- views for the API ---------------------------------------------------------------

    async def connection_view(self, conn: SourceConnection, paused: bool) -> dict[str, Any]:
        spec = REGISTRY[conn.provider]
        worker = self.supervisor.workers.get(conn.connection_id)
        health = worker.health.view() if worker else {}
        if conn.origin == "legacy" and self.legacy_health is not None:
            health = {**health, **await self.legacy_health()}
        if paused:
            health["status"] = STATUS_PAUSED
        cursors = await self.cursors.all_for(conn.connection_id)
        return {
            **conn.public_view(),
            "paused": paused,
            "label": spec.label,
            "capabilities": list(spec.capabilities),
            "emits": list(spec.emits),
            "prerequisites": spec.prerequisites,
            "health": health,
            "managed_by": "legacy_poll" if conn.origin == "legacy" else "supervisor",
            "checkpoints": {k: v["committed_at"] for k, v in cursors.items()},
        }

    async def context_for(self, summary: dict[str, Any]) -> dict[str, Any]:
        return await identity_context(self.ledger, self.scope_id, summary)

    async def metrics(self) -> dict[str, Any]:
        counts = await self.db.counts()
        backlog = await self.outbox.backlog()
        recon = await self.db.fetchone(
            "SELECT COUNT(*) AS n FROM response_actions WHERE state=?",
            ("reconciliation_required",))
        return {
            "schema_version": await self.db.schema_version(),
            "store": str(self._db_path),
            "counts": counts,
            "outbox_backlog": backlog,
            "reconciliation_required": int(recon["n"]),
            "quarantined": counts.get("source_errors", 0),
            "active_investigations": len(self.revisions),
            "sources": self.supervisor.health(),
            "ai_available": bool(self.service.ai_available),
        }
