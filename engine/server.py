"""server.py — run the engine with the web API + correlation dashboard.

    python -m engine.server --config config.yaml --input alerts.ndjson
    python -m engine.server --config config.yaml --mode poll --writeback
    python -m engine.server --config config.yaml --mode batch \
        --since 2026-07-11T00:00:00Z --until 2026-07-11T06:00:00Z

One process: ingestion (offline file or live Elastic), deterministic
correlation, AI triage of in-scope chains, Elastic write-back (opt-in),
and the browser dashboard at http://<host>:<port>/ with per-chain deep
links at /incident/<cluster_id>.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys
from typing import Optional
from urllib.parse import urlparse

import uvicorn

from engine.ai.service import TriageService
from engine.api.server import create_app
from engine.config import Config, load_config
from engine.connectors.elastic import ElasticConnector
from engine.connectors.writeback import ResultWriter
from engine.log import setup_logging
from engine.normalize.timeutil import coerce_time
from engine.pipeline import Pipeline, PipelineResult

logger = logging.getLogger(__name__)


class EngineRunner:
    """Owns the pipeline + triage lifecycle around the web app."""

    def __init__(
        self,
        config: Config,
        *,
        input_file: Optional[str],
        mode: Optional[str],
        since_ms: Optional[int],
        until_ms: Optional[int],
        writeback: bool,
        ai_enabled: bool,
        cursor_store=None,
    ) -> None:
        self.config = config
        self.pipeline = Pipeline(config)
        self._input_file = input_file
        self._mode = mode
        self._since_ms = since_ms
        self._until_ms = until_ms
        self._cursor_store = cursor_store
        self._stop = asyncio.Event()
        self._poll_task: Optional[asyncio.Task] = None
        self._startup_task: Optional[asyncio.Task] = None
        self._connector: Optional[ElasticConnector] = None
        writer: Optional[ResultWriter] = None
        self.reader: Optional[ResultWriter] = None
        if config.siem.host and (writeback or mode in ("poll", "batch")):
            self._connector = ElasticConnector(config.siem)
            self.reader = ResultWriter(self._connector, config.output)
            if writeback:
                writer = self.reader
        self.service = TriageService(
            config, writer=writer, ai_enabled=ai_enabled
        )
        self.siem_live = mode in ("poll", "batch")

    # -- lifecycle -------------------------------------------------------------

    async def start(self) -> None:
        """Kick off ingestion without blocking application startup.

        Batch/file processing (and its AI triage) runs as a background task
        so the dashboard answers immediately — with a slow local model, a
        synchronous startup triage would leave the HTTP port unreachable
        for minutes.
        """
        if self._input_file:
            self._startup_task = asyncio.create_task(self._run_file())
        elif self._mode == "batch":
            self._startup_task = asyncio.create_task(self._run_batch())
        elif self._mode == "poll":
            self._poll_task = asyncio.create_task(self._poll())

    async def stop(self) -> None:
        self._stop.set()
        for task in (self._startup_task, self._poll_task):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        if self._connector is not None:
            await self._connector.aclose()

    async def _run_file(self) -> None:
        try:
            result = self.pipeline.run_batch_file(self._input_file)
            await self._process(result)
            logger.info(
                "file batch complete: %d chains (%d surfaced), %d results",
                len(result.clusters), len(result.surfaced),
                len(self.service.results),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("file batch ingestion failed")

    async def _run_batch(self) -> None:
        try:
            result = await self.pipeline.run_batch_elastic(
                self._since_ms, self._until_ms
            )
            await self._process(result)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("elastic batch ingestion failed")

    # -- processing --------------------------------------------------------------

    async def _process(self, result: PipelineResult) -> None:
        await self.service.process_all(
            self.pipeline.correlator, result.clusters
        )

    async def _poll(self) -> None:
        """Continuous poll; triage chains as evaluation cycles complete."""
        queue: asyncio.Queue = asyncio.Queue()

        def on_cycle(result: PipelineResult) -> None:
            queue.put_nowait(list(result.clusters))

        async def consume() -> None:
            while True:
                clusters = await queue.get()
                # Coalesce a backlog: when triage runs slower than the
                # evaluation cadence, only the newest snapshot matters
                # (unchanged chains are skipped by fingerprint anyway).
                while not queue.empty():
                    clusters = queue.get_nowait()
                try:
                    await self.service.process_all(
                        self.pipeline.correlator, clusters
                    )
                except Exception:  # keep polling alive; failures are logged
                    logger.exception("triage cycle failed")

        since_ms = self._since_ms
        on_cursor = None
        if self._cursor_store is not None:
            if since_ms is None:
                stored = self._cursor_store.load()
                if stored is not None:
                    # Re-read one correlation window behind the persisted
                    # cursor: alerts that were ingested but still buffered
                    # at shutdown are recovered and their chains rebuilt.
                    # Duplicates are impossible downstream (alert-uid dedup,
                    # idempotent write-back by cluster_id).
                    correlation = self.config.correlation
                    lookback_ms = (
                        correlation.window_minutes * 60_000
                        + correlation.watermark_grace_seconds * 1000
                    )
                    since_ms = max(0, stored - lookback_ms)
                    logger.info(
                        "resuming poll from persisted cursor %d "
                        "(with %d ms correlation-window lookback)",
                        stored, lookback_ms,
                    )
            on_cursor = self._cursor_store.save

        consumer = asyncio.create_task(consume())
        try:
            await self.pipeline.run_poll(
                since_ms, stop=self._stop, on_cycle=on_cycle,
                on_cursor=on_cursor,
            )
        finally:
            consumer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await consumer


def _parse_time(value: str) -> int:
    ms, _ = coerce_time(value)
    return ms


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m engine.server",
        description="LogLookup AI engine + web dashboard.",
    )
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--input",
                        help="fixture file (JSON array / NDJSON / CSV) to "
                             "ingest at startup")
    parser.add_argument("--mode", choices=("batch", "poll"),
                        help="Elastic batch pull or continuous 60s poll")
    parser.add_argument("--since", help="batch start time (ISO-8601 or epoch)")
    parser.add_argument("--until", help="batch end time (ISO-8601 or epoch)")
    parser.add_argument("--writeback", action="store_true",
                        help="write chain documents to the Elastic results "
                             "index")
    parser.add_argument("--no-ai", action="store_true",
                        help="serve deterministic results without AI triage")
    parser.add_argument("--host", default=None,
                        help="bind host (default: from output."
                             "dashboard_base_url)")
    parser.add_argument("--port", type=int, default=None,
                        help="bind port (default: from output."
                             "dashboard_base_url)")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    setup_logging(args.log_level)
    config = load_config(args.config)

    since_ms = until_ms = None
    if args.mode == "batch":
        if not args.since or not args.until:
            parser.error("--mode batch requires --since and --until")
        since_ms, until_ms = _parse_time(args.since), _parse_time(args.until)
    if args.input and args.mode:
        parser.error("--input and --mode are mutually exclusive")

    parsed = urlparse(config.output.dashboard_base_url)
    host = args.host or parsed.hostname or "127.0.0.1"
    port = args.port or parsed.port or 8080

    runner = EngineRunner(
        config,
        input_file=args.input,
        mode=args.mode,
        since_ms=since_ms,
        until_ms=until_ms,
        writeback=args.writeback,
        ai_enabled=not args.no_ai,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        await runner.start()
        try:
            yield
        finally:
            await runner.stop()

    app = create_app(
        config, runner.service, pipeline=runner.pipeline,
        reader=runner.reader, lifespan=lifespan,
    )
    app.state.siem_live = runner.siem_live

    logger.info("dashboard: http://%s:%d/", host, port)
    uvicorn.run(app, host=host, port=port, log_level=args.log_level.lower())
    return 0


if __name__ == "__main__":
    sys.exit(main())
