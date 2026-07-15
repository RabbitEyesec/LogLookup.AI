"""FastAPI application: status, clusters, dashboard views, AI settings.

Single source of truth rule: results live in Elasticsearch. This API
serves the chain documents produced by the running engine (its local
mirror of what was written back) and falls back to the Elastic results
index for cluster ids from earlier runs  deep links keep working after a
restart. Nothing is recomputed for display.

Settings rule (AI Constitution 5): the AI provider is switchable at
runtime through PUT /api/settings/ai no config file edit, no restart.
Secrets are accepted but never echoed back. In managed mode
(``loglookup serve``) changes persist to the encrypted store + managed
config, so they survive a restart.

Every handler reads the live engine objects from ``app.state`` — the
managed runner swaps them there when onboarding completes or the SIEM
connection changes, without restarting the process.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine.ai.provider import ProviderError
from engine.ai.service import TriageService
from engine.api import views
from engine.api.setup import router as setup_router
from engine.config import Config
from engine.connectors.elastic import ConnectorError, ElasticConnector
from engine.connectors.writeback import ResultWriter
from engine.pipeline import Pipeline

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "dashboard" / "static"


class AiSettingsUpdate(BaseModel):
    """Runtime AI settings changes. Only provided fields are applied."""

    provider: Optional[str] = None
    local_model: Optional[str] = None
    local_base_url: Optional[str] = None
    cloud_model: Optional[str] = None
    cloud_api_key: Optional[str] = Field(default=None, repr=False)
    triage_scope: Optional[str] = None
    redaction: Optional[bool] = None
    zero_data_retention: Optional[bool] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=3600)


def create_app(
    config: Config,
    service: TriageService,
    *,
    pipeline: Optional[Pipeline] = None,
    reader: Optional[ResultWriter] = None,
    settings=None,
    lifespan=None,
) -> FastAPI:
    """Build the API + dashboard app around a triage service.

    ``pipeline`` is the live engine when this process runs ingestion (file
    batch or poll). ``reader`` reads the Elastic results index for chain
    documents this process did not produce. ``settings`` is the
    :class:`engine.settings.ManagedSettings` instance in managed mode
    (None for the dev CLI — nothing persists then).
    """
    app = FastAPI(title="LogLookup AI", version="1.0", docs_url="/api/docs",
                  openapi_url="/api/openapi.json", lifespan=lifespan)
    app.state.config = config
    app.state.service = service
    app.state.pipeline = pipeline
    app.state.reader = reader
    app.state.settings = settings

    app.include_router(setup_router)

    # -- helpers ---------------------------------------------------------------

    async def get_document(request: Request, cluster_id: str) -> dict[str, Any]:
        service: TriageService = request.app.state.service
        reader: Optional[ResultWriter] = request.app.state.reader
        doc = service.get_result(cluster_id)
        if doc is None and reader is not None:
            doc = await reader.read(cluster_id)
        if doc is None:
            raise HTTPException(
                status_code=404,
                detail=f"no results for cluster {cluster_id!r}",
            )
        return doc

    # -- status ------------------------------------------------------------------

    @app.get("/api/status")
    async def status(request: Request) -> dict[str, Any]:
        state = request.app.state
        config: Config = state.config
        service: TriageService = state.service
        pipeline: Optional[Pipeline] = state.pipeline
        siem: dict[str, Any] = {
            "type": config.siem.type,
            "host": config.siem.host,
            "alert_index": config.siem.alert_index,
            "configured": bool(config.siem.host),
            "reachable": None,
            "verify_tls": config.siem.verify_tls,
            "ca_cert_path": config.siem.ca_cert_path,
        }
        if pipeline is not None and getattr(state, "siem_live", False):
            connector = ElasticConnector(config.siem)
            try:
                siem["reachable"] = await connector.ping()
            except ConnectorError as exc:
                siem["reachable"] = False
                siem["detail"] = str(exc)
            finally:
                await connector.aclose()

        ai_status = (await service.providers.current.health()).as_dict()
        ai_status["triage_available"] = service.ai_available
        if not service.ai_available:
            ai_status["disabled_reason"] = service.ai_disabled_reason

        kb = service.kb
        engine_state: dict[str, Any] = {
            "mode": config.engine.mode,
            "results": len(service.results),
        }
        if pipeline is not None:
            clusters = pipeline.correlator.clusters()
            engine_state.update(
                clusters=len(clusters),
                surfaced=sum(1 for c in clusters if c.surfaced),
                entities=pipeline.correlator.resolver.entity_count,
            )
        return {
            "engine": engine_state,
            "siem": siem,
            "ai": ai_status,
            "kb": {
                "loaded": kb is not None,
                "techniques": len(kb) if kb is not None else 0,
                "attack_version": kb.attack_version if kb is not None else "",
            },
        }

    # -- clusters (Phase 15) -------------------------------------------------------

    @app.get("/api/clusters")
    async def list_clusters(
        request: Request, surfaced_only: bool = False, limit: int = 200
    ) -> dict[str, Any]:
        service: TriageService = request.app.state.service
        briefs = [
            views.cluster_brief(doc) for doc in service.results.values()
        ]
        if surfaced_only:
            briefs = [b for b in briefs if b["surfaced"]]
        briefs.sort(key=lambda b: (b["last_time"] or "", b["cluster_id"]),
                    reverse=True)
        return {"clusters": briefs[:max(0, limit)], "total": len(briefs)}

    @app.get("/api/clusters/{cluster_id}")
    async def cluster_detail(request: Request, cluster_id: str) -> dict[str, Any]:
        return await get_document(request, cluster_id)

    @app.post("/api/clusters/{cluster_id}/triage")
    async def retriage(request: Request, cluster_id: str) -> dict[str, Any]:
        service: TriageService = request.app.state.service
        pipeline: Optional[Pipeline] = request.app.state.pipeline
        if pipeline is None:
            raise HTTPException(
                status_code=409,
                detail="no live engine in this process; re-triage requires "
                       "the process that ingested the alerts",
            )
        if not service.ai_enabled:
            raise HTTPException(
                status_code=409,
                detail="AI triage is disabled in this process (started with "
                       "--no-ai)",
            )
        cluster = next(
            (c for c in pipeline.correlator.clusters()
             if c.cluster_id == cluster_id),
            None,
        )
        if cluster is None:
            raise HTTPException(
                status_code=404,
                detail=f"cluster {cluster_id!r} not present in the live engine",
            )
        return await service.process_cluster(
            pipeline.correlator, cluster, force=True
        )

    # -- dashboard data (Phase 16) ---------------------------------------------------

    @app.get("/api/clusters/{cluster_id}/timeline")
    async def cluster_timeline(request: Request, cluster_id: str) -> dict[str, Any]:
        return views.timeline_view(await get_document(request, cluster_id))

    @app.get("/api/clusters/{cluster_id}/graph")
    async def cluster_graph(request: Request, cluster_id: str) -> dict[str, Any]:
        return views.graph_view(await get_document(request, cluster_id))

    @app.get("/api/attack/techniques")
    async def attack_techniques(request: Request, ids: str = "") -> dict[str, Any]:
        """Official ATT&CK metadata for UI names, descriptions, and links."""
        kb = request.app.state.service.kb
        if kb is None:
            return {"techniques": []}
        wanted = {value.strip().upper() for value in ids.split(",") if value.strip()}
        records = kb.techniques() if not wanted else [
            record for uid in sorted(wanted)
            if (record := kb.get(uid)) is not None
        ]
        return {"techniques": [
            {
                "uid": record.uid,
                "name": record.name,
                "description": record.description,
                "url": record.url,
                "tactics": record.tactics,
            }
            for record in records
        ]}

    # -- runtime AI settings ---------------------------------------------------------

    @app.get("/api/settings/ai")
    async def get_ai_settings(request: Request) -> dict[str, Any]:
        return request.app.state.service.providers.settings_view()

    @app.put("/api/settings/ai")
    async def put_ai_settings(
        request: Request, update: AiSettingsUpdate
    ) -> dict[str, Any]:
        service: TriageService = request.app.state.service
        changes = {
            key: value
            for key, value in update.model_dump().items()
            if value is not None
        }
        if not changes:
            raise HTTPException(status_code=400, detail="no settings provided")
        try:
            service.providers.switch(**changes)
        except ProviderError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        managed = request.app.state.settings
        if managed is not None:
            # Persist so the change survives a restart; validation already
            # passed on the live switch above.
            managed.apply_ai_changes(changes)
        return service.providers.settings_view()

    # -- UI shell (Phases 17-19 assets + onboarding wizard) -----------------------------

    def needs_setup(request: Request) -> bool:
        managed = request.app.state.settings
        return managed is not None and not managed.setup_complete

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        @app.get("/", include_in_schema=False)
        async def index(request: Request):
            if needs_setup(request):
                return RedirectResponse("/setup", status_code=307)
            return FileResponse(STATIC_DIR / "incident.html")

        @app.get("/setup", include_in_schema=False)
        async def setup_page(request: Request):
            if not needs_setup(request):
                return RedirectResponse("/", status_code=307)
            return FileResponse(STATIC_DIR / "setup.html")

        @app.get("/incident/{cluster_id}", include_in_schema=False)
        async def incident(cluster_id: str) -> FileResponse:
            # Deep link: /incident/<cluster_id>; the page fetches its data
            # from /api/clusters/<cluster_id>/*.
            return FileResponse(STATIC_DIR / "incident.html")
    else:  # pragma: no cover - packaging error surface
        @app.get("/", include_in_schema=False)
        async def missing_ui() -> JSONResponse:
            return JSONResponse(
                {"detail": "dashboard assets missing", "api": "/api/docs"},
                status_code=200,
            )

    return app
