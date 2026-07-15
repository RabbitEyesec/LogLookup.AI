"""pipeline.py — wires the stages.

    ingest -> normalize (OCSF) -> pre-filter -> entity resolution
           -> correlate (chains + cluster_id) -> risk scoring (RBA)
           [-> AI triage (--triage) -> Elastic write-back (--writeback)]

The deterministic engine runs by itself and emits attack chains as JSON
lines. With ``--triage`` the AI layer reasons over each in-scope chain
(RAG-grounded MITRE, CoT-first schema, grounding validator) and with
``--writeback`` the chain documents are pushed to the Elastic results
index tagged with cluster_id + dashboard_url. The web UI is served
separately by ``python -m engine.server``.

Usage:
    python -m engine.pipeline --config config.yaml --input alerts.ndjson
    python -m engine.pipeline --config config.yaml --mode batch \
        --since 2026-07-11T00:00:00Z --until 2026-07-11T06:00:00Z \
        --triage --writeback
    python -m engine.pipeline --config config.yaml --mode poll
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from engine.config import Config, load_config
from engine.connectors.elastic import ElasticConnector
from engine.correlate.engine import Cluster, CorrelationEngine
from engine.ingest import (
    RawRecord,
    iter_elastic_batch,
    iter_elastic_poll,
    iter_file_records,
)
from engine.log import setup_logging
from engine.normalize.adapters import get_adapter
from engine.normalize.timeutil import coerce_time
from engine.prefilter import PreFilter

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Outcome of a pipeline run (batch) or cycle (poll)."""

    ingested: int = 0
    normalized: int = 0
    parse_flagged: int = 0
    suppressed: int = 0
    correlated: int = 0
    clusters: list[Cluster] = field(default_factory=list)

    @property
    def surfaced(self) -> list[Cluster]:
        return [c for c in self.clusters if c.surfaced]


class Pipeline:
    """Deterministic engine pipeline: one instance holds correlation state."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._file_adapter = get_adapter("file")
        self._siem_adapter = get_adapter(config.siem.type)
        self._prefilter = PreFilter(config.prefilter, config.siem)
        self.correlator = CorrelationEngine(config.correlation)
        self._result = PipelineResult()

    def process(self, record: RawRecord) -> None:
        """Run one raw record through normalize -> prefilter -> correlate."""
        self._result.ingested += 1
        adapter = (
            self._file_adapter if record.source == "file" else self._siem_adapter
        )
        alert = adapter.parse(record)
        self._result.normalized += 1
        if alert.has_parse_errors:
            self._result.parse_flagged += 1
        decision = self._prefilter.evaluate(alert)
        if decision.suppressed:
            self._result.suppressed += 1
            return
        self.correlator.add(alert)
        self._result.correlated += 1

    def evaluate(self, *, flush: bool = False) -> PipelineResult:
        """Correlate what's ready and refresh the run summary."""
        self._result.clusters = self.correlator.evaluate(flush=flush)
        return self._result

    # -- drivers -------------------------------------------------------------

    def run_batch_file(self, path: str | Path) -> PipelineResult:
        for record in iter_file_records(path):
            self.process(record)
        return self.evaluate(flush=True)

    async def run_batch_elastic(
        self,
        since_ms: int,
        until_ms: int,
        connector: Optional[ElasticConnector] = None,
    ) -> PipelineResult:
        connector = connector or ElasticConnector(self._config.siem)
        try:
            async for record in iter_elastic_batch(connector, since_ms, until_ms):
                self.process(record)
        finally:
            await connector.aclose()
        return self.evaluate(flush=True)

    async def run_poll(
        self,
        since_ms: Optional[int] = None,
        *,
        stop: Optional[asyncio.Event] = None,
        on_cycle=None,
        on_cursor=None,
    ) -> PipelineResult:
        """Poll the SIEM forever; evaluate on the configured cadence.

        Evaluation runs on its own timer, independent of alert arrival — a
        quiet SIEM must not leave buffered alerts stuck behind the watermark
        or stop stale-entity flushing. ``on_cursor`` (optional) receives the
        advanced poll cursor for persistence, so a restarted process resumes
        where it left off instead of skipping the downtime window.
        """
        connector = ElasticConnector(self._config.siem)
        evaluate_every_s = (
            self._config.correlation.evaluate_every_minutes * 60
        )
        retention_ms = (
            self._config.correlation.entity_retention_minutes * 60_000
        )
        emitted: set[str] = set()

        def evaluate_cycle() -> None:
            result = self.evaluate()
            self.correlator.resolver.flush_stale(int(time.time() * 1000))
            watermark = self.correlator.watermark_ms
            if watermark is not None:
                self.correlator.prune_before(watermark - retention_ms)
            self._emit_new_surfaced(result, emitted)
            if on_cycle is not None:
                on_cycle(result)

        async def ticker() -> None:
            while True:
                await asyncio.sleep(evaluate_every_s)
                evaluate_cycle()

        tick_task = asyncio.get_running_loop().create_task(ticker())
        try:
            async for record in iter_elastic_poll(
                connector, since_ms, stop=stop, on_cursor=on_cursor
            ):
                self.process(record)
        finally:
            tick_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await tick_task
            await connector.aclose()
        result = self.evaluate(flush=True)
        self._emit_new_surfaced(result, emitted)
        return result

    def _emit_new_surfaced(
        self, result: PipelineResult, emitted: set[str]
    ) -> None:
        for cluster in result.surfaced:
            if cluster.cluster_id not in emitted:
                emitted.add(cluster.cluster_id)
                print(json.dumps(self.correlator.cluster_summary(cluster)))
                sys.stdout.flush()

    def summary(self, result: PipelineResult) -> dict[str, Any]:
        return {
            "ingested": result.ingested,
            "normalized": result.normalized,
            "parse_flagged": result.parse_flagged,
            "suppressed_benign": result.suppressed,
            "sent_to_correlation": result.correlated,
            "chains": len(result.clusters),
            "surfaced_chains": len(result.surfaced),
            "entities": self.correlator.resolver.entity_count,
        }


def _parse_time_arg(value: str) -> int:
    ms, _ = coerce_time(value)
    return ms


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m engine.pipeline",
        description="LogLookup AI deterministic engine (Phases 0-9).",
    )
    parser.add_argument("--config", default="config.yaml",
                        help="path to config.yaml")
    parser.add_argument("--input",
                        help="fixture file (JSON array / NDJSON / CSV); "
                             "implies file batch mode")
    parser.add_argument("--mode", choices=("batch", "poll"), default=None,
                        help="Elastic batch pull or continuous poll")
    parser.add_argument("--since", help="batch start time (ISO-8601 or epoch)")
    parser.add_argument("--until", help="batch end time (ISO-8601 or epoch)")
    parser.add_argument("--triage", action="store_true",
                        help="run AI triage (verdict + report) on in-scope "
                             "chains after correlation")
    parser.add_argument("--writeback", action="store_true",
                        help="write chain documents to the Elastic results "
                             "index (cluster_id + dashboard_url)")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    setup_logging(args.log_level)
    config = load_config(args.config)
    pipeline = Pipeline(config)

    if args.input:
        result = pipeline.run_batch_file(args.input)
    elif args.mode == "batch":
        if not args.since or not args.until:
            parser.error("--mode batch requires --since and --until")
        result = asyncio.run(
            pipeline.run_batch_elastic(
                _parse_time_arg(args.since), _parse_time_arg(args.until)
            )
        )
    elif args.mode == "poll":
        try:
            result = asyncio.run(pipeline.run_poll())
        except KeyboardInterrupt:
            logger.info("poll interrupted; final state follows")
            result = pipeline.evaluate(flush=True)
    else:
        parser.error("provide --input FILE, or --mode batch/poll")
        return 2

    for cluster in result.clusters:
        print(json.dumps(pipeline.correlator.cluster_summary(cluster)))

    if args.triage or args.writeback:
        docs = asyncio.run(
            _triage_and_writeback(
                config, pipeline, result,
                triage=args.triage, writeback=args.writeback,
            )
        )
        for doc in docs:
            print(json.dumps(doc))

    print(json.dumps({"summary": pipeline.summary(result)}))
    return 0


async def _triage_and_writeback(
    config: Config,
    pipeline: Pipeline,
    result: PipelineResult,
    *,
    triage: bool,
    writeback: bool,
) -> list[dict[str, Any]]:
    """Post-correlation stages: AI reasoning and/or Elastic write-back."""
    from engine.ai.service import TriageService
    from engine.connectors.writeback import ResultWriter

    connector: Optional[ElasticConnector] = None
    writer: Optional[ResultWriter] = None
    if writeback:
        connector = ElasticConnector(config.siem)
        writer = ResultWriter(connector, config.output)
    service = TriageService(config, writer=writer, ai_enabled=triage)
    try:
        return await service.process_all(pipeline.correlator, result.clusters)
    finally:
        if connector is not None:
            await connector.aclose()


if __name__ == "__main__":
    sys.exit(main())
