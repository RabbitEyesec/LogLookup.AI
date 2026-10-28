"""v2 API: connections, multi-source investigations, response workflow.

Every handler resolves the caller server-side (``engine.api.auth``) and
enforces role rank here - never in the browser. Mutations carry the
investigation revision the client acted on; a stale revision is a 409.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from engine.api import views
from engine.api.auth import Principal, authenticate, require
from engine.api.models_v2 import (
    ActionCreate, ActionDecision, AssignRequest, ConnectionCreate,
    ConnectionPatch, NoteCreate, ReconcileRequest,
)
from engine.connectors.base import ConfigurationError, SourceConnection
from engine.connectors.registry import REGISTRY, build_connector
from engine.response.models import ResponseError
from engine.secure.store import auth_profile_name

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v2")


def _rt(request: Request):
    rt = getattr(request.app.state, "v2", None)
    if rt is None or not rt.started:
        raise HTTPException(503, "the v2 runtime is not running")
    return rt


async def _principal(request: Request) -> Principal:
    _rt(request)
    return await authenticate(request)


def install_error_handlers(app) -> None:
    @app.exception_handler(ResponseError)
    async def response_error(_request: Request, exc: ResponseError):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        # Never echo submitted values: bodies can carry write-only secrets.
        errors = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")}
                  for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)


_SECRETISH_KEY = re.compile(
    r"secret|passw|token|api_?key|private_?key|credential", re.I)


def _reject_secrets_in_options(options: dict[str, Any]) -> None:
    """Options are stored and returned in clear text; credentials go in the
    write-only ``credentials`` field instead."""
    bad = [k for k in options if _SECRETISH_KEY.search(str(k))]
    if bad:
        raise HTTPException(
            422, f"options must not contain secrets ({bad}); send them in "
                 "'credentials', which is stored encrypted")


# -- helpers ---------------------------------------------------------------------

async def _document(request: Request, cluster_id: str) -> tuple[str, dict[str, Any]]:
    rt = _rt(request)
    resolved = await rt.investigations.resolve(cluster_id)
    doc = request.app.state.service.get_result(resolved)
    reader = request.app.state.reader
    if doc is None and reader is not None:
        doc = await reader.read(resolved)
    if doc is None:
        raise HTTPException(404, f"no investigation {cluster_id!r}")
    return resolved, doc


def _latest_revision(rt, cluster_id: str) -> int:
    return int(rt.revisions.get(cluster_id, 0))


async def _stored_revision(rt, cluster_id: str) -> int:
    row = await rt.investigations.get(cluster_id)
    return int(row["latest_revision"]) if row else _latest_revision(rt, cluster_id)


def _check_revision(expected: int, actual: int) -> None:
    if expected != actual:
        raise HTTPException(
            409, f"stale revision: you acted on {expected}, current is {actual}")


def _evidence_refs(doc: dict[str, Any]) -> list[str]:
    refs = []
    for alert in doc.get("chain", {}).get("alerts", []):
        ref = (alert.get("source") or {}).get("evidence_ref")
        if ref:
            refs.append(ref)
    return refs


# -- connections -----------------------------------------------------------------

@router.get("/connections")
async def list_connections(request: Request, p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    items = [await rt.connection_view(c, paused) for c, paused in await rt.repo.list()]
    return {"connections": items, "providers": {
        k: {"label": s.label, "capabilities": list(s.capabilities),
            "credential_kinds": list(s.credential_kinds),
            "prerequisites": s.prerequisites} for k, s in REGISTRY.items()}}


@router.post("/connections", status_code=201)
async def create_connection(body: ConnectionCreate, request: Request,
                            p: Principal = Depends(_principal)):
    require(p, "administrator")
    rt = _rt(request)
    _reject_secrets_in_options(body.options)
    if await rt.repo.get(body.connection_id):
        raise HTTPException(409, "a connection with this id already exists")
    profile_id = f"{body.connection_id}-auth" if body.credentials else ""
    try:
        conn = SourceConnection(
            connection_id=body.connection_id, provider=body.provider,
            scope_id=rt.scope_id, name=body.name, active=body.enabled,
            poll_seconds=body.poll_seconds, lookback_seconds=body.lookback_seconds,
            max_page_size=body.max_page_size, auth_profile_id=profile_id,
            tls_verify=body.tls_verify, ca_bundle_path=body.ca_bundle_path,
            options=body.options)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if body.credentials:
        rt.secrets.set(auth_profile_name(profile_id), json.dumps(body.credentials))
    try:
        await _validate_config(rt, conn)
    except HTTPException:
        if profile_id:  # do not leave an orphaned secret behind
            rt.secrets.delete(auth_profile_name(profile_id))
        raise
    await rt.repo.upsert(conn)
    await rt.audit.append(p.username, "connection.created", conn.connection_id,
                          {"provider": conn.provider, "enabled": conn.active})
    await rt.supervisor.add(conn)
    return await rt.connection_view(conn, False)


async def _validate_config(rt, conn: SourceConnection) -> None:
    """Build (without opening) the connector so config errors surface now."""
    try:
        connector = build_connector(
            conn, rt.secrets, transport=rt._http_transport,
            token_getter_factory=rt._token_getter_factory)
    except ConfigurationError as exc:
        if conn.active:
            raise HTTPException(422, str(exc)) from None
        return  # an inactive connection may be saved incomplete
    await connector.close()


@router.get("/connections/{connection_id}")
async def get_connection(connection_id: str, request: Request,
                         p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    found = await rt.repo.get(connection_id)
    if not found:
        raise HTTPException(404, "unknown connection")
    return await rt.connection_view(*found)


@router.patch("/connections/{connection_id}")
async def patch_connection(connection_id: str, body: ConnectionPatch,
                           request: Request, p: Principal = Depends(_principal)):
    require(p, "administrator")
    rt = _rt(request)
    found = await rt.repo.get(connection_id)
    if not found:
        raise HTTPException(404, "unknown connection")
    conn, paused = found
    if conn.origin != "managed":
        raise HTTPException(
            409, f"{conn.origin}-defined connections are changed in their "
                 "own configuration, not through the API")
    import dataclasses

    changes = {k: v for k, v in {
        "name": body.name, "poll_seconds": body.poll_seconds,
        "lookback_seconds": body.lookback_seconds,
        "max_page_size": body.max_page_size,
        "active": body.enabled}.items() if v is not None}
    if body.options is not None:
        _reject_secrets_in_options(body.options)
        changes["options"] = {**conn.options, **body.options}
    try:
        conn = dataclasses.replace(conn, **changes)
        SourceConnection.__post_init__(conn)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    rotated = False
    if body.credentials:
        profile_id = conn.auth_profile_id or f"{connection_id}-auth"
        conn = dataclasses.replace(conn, auth_profile_id=profile_id)
        # Rotation replaces the secret only; cursors and history are kept.
        rt.secrets.set(auth_profile_name(profile_id), json.dumps(body.credentials))
        rotated = True
    await _validate_config(rt, conn)
    await rt.repo.upsert(conn)
    await rt.repo.set_active(connection_id, conn.active)
    await rt.audit.append(p.username, "connection.updated", connection_id,
                          {"fields": sorted(changes), "credential_rotated": rotated})
    await rt.supervisor.add(conn)
    if paused:
        rt.supervisor.workers[connection_id].pause()
    return await rt.connection_view(conn, paused)


async def _set_pause(request: Request, connection_id: str, p: Principal,
                     paused: bool):
    require(p, "administrator")
    rt = _rt(request)
    if not await rt.repo.get(connection_id):
        raise HTTPException(404, "unknown connection")
    worker = rt.supervisor.workers.get(connection_id)
    if worker is not None:
        worker.pause() if paused else worker.resume()
    await rt.repo.set_paused(connection_id, paused)
    await rt.audit.append(p.username,
                          "connection.paused" if paused else "connection.resumed",
                          connection_id, {})
    return await rt.connection_view(*(await rt.repo.get(connection_id)))


@router.post("/connections/{connection_id}/pause")
async def pause_connection(connection_id: str, request: Request,
                           p: Principal = Depends(_principal)):
    return await _set_pause(request, connection_id, p, True)


@router.post("/connections/{connection_id}/resume")
async def resume_connection(connection_id: str, request: Request,
                            p: Principal = Depends(_principal)):
    return await _set_pause(request, connection_id, p, False)


@router.get("/sources/health")
async def sources_health(request: Request, p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    return {"sources": rt.supervisor.health(), "metrics": await rt.metrics()}


# -- investigations --------------------------------------------------------------

@router.get("/investigations")
async def list_investigations(request: Request, provider: str | None = None,
                              surfaced_only: bool = False, limit: int = 100,
                              offset: int = 0, p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    limit = max(1, min(limit, 500))
    rows = await rt.investigations.list(limit=500, offset=0)
    out = []
    for row in rows:
        doc = request.app.state.service.get_result(row["cluster_id"])
        brief = views.cluster_brief(doc) if doc else {}
        sources = (doc or {}).get("chain", {}).get("sources", [])
        if provider and provider not in {s["provider"] for s in sources}:
            continue
        if surfaced_only and not row["surfaced"]:
            continue
        out.append({
            "cluster_id": row["cluster_id"], "revision": row["latest_revision"],
            "status": row["status"], "owner": row["owner"],
            "risk_score": row["risk_score"], "surfaced": bool(row["surfaced"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "sources": sources, "source_diversity": len(
                {s["provider"] for s in sources}),
            "alert_count": (doc or {}).get("chain", {}).get("alert_count"),
            "title": brief.get("incident_title"),
            "severity": brief.get("max_severity"),
        })
    return {"investigations": out[offset:offset + limit], "total": len(out)}


@router.get("/investigations/{cluster_id}")
async def get_investigation(cluster_id: str, request: Request,
                            p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    resolved, doc = await _document(request, cluster_id)
    row = await rt.investigations.get(resolved) or {}
    chain = doc.get("chain", {})
    context = await rt.context_for({
        "entities": chain.get("entities", []), "alerts": chain.get("alerts", []),
        "first_time": _ms(chain.get("first_time")),
        "last_time": _ms(chain.get("last_time"))})
    return {
        "cluster_id": resolved,
        "resolved_from": cluster_id if resolved != cluster_id else None,
        "revision": row.get("latest_revision", 0), "status": row.get("status", "new"),
        "owner": row.get("owner"), "document": doc,
        "identity_context": context,
        "notes": await rt.investigations.notes(resolved),
        "evidence_refs": _evidence_refs(doc),
    }


def _ms(iso: Any) -> int:
    if isinstance(iso, (int, float)):
        return int(iso)
    from engine.normalize.timeutil import coerce_time
    try:
        return coerce_time(iso)[0]
    except Exception:
        return 0


@router.get("/investigations/{cluster_id}/evidence")
async def investigation_evidence(cluster_id: str, request: Request,
                                 include_raw: bool = False, limit: int = 50,
                                 offset: int = 0, p: Principal = Depends(_principal)):
    require(p, "viewer")
    if include_raw:
        require(p, "analyst")  # raw vendor payloads are restricted
    rt = _rt(request)
    resolved, _doc = await _document(request, cluster_id)
    ids = await rt.investigations.event_ids(resolved)
    page = ids[offset:offset + max(1, min(limit, 200))]
    events = []
    for ceid in page:
        ev = await rt.ledger.get_event(ceid, include_raw=include_raw)
        if ev is not None and ev["scope_id"] == p.scope_id:
            events.append(ev)
    if include_raw:
        await rt.audit.append(p.username, "evidence.raw_read", resolved,
                              {"events": [e["canonical_event_id"] for e in events]})
    return {"cluster_id": resolved, "total": len(ids), "events": events}


@router.get("/investigations/{cluster_id}/timeline")
async def investigation_timeline(cluster_id: str, request: Request,
                                 p: Principal = Depends(_principal)):
    require(p, "viewer")
    _resolved, doc = await _document(request, cluster_id)
    view = views.timeline_view(doc)
    view["provenance"] = {
        a["uid"]: a.get("source") for a in doc.get("chain", {}).get("alerts", [])}
    return view


@router.get("/investigations/{cluster_id}/graph")
async def investigation_graph(cluster_id: str, request: Request,
                              p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    resolved, doc = await _document(request, cluster_id)
    graph = views.graph_view(doc)
    chain = doc.get("chain", {})
    graph["sources"] = chain.get("sources", [])
    ctx = await rt.context_for({
        "entities": chain.get("entities", []), "alerts": chain.get("alerts", []),
        "first_time": _ms(chain.get("first_time")),
        "last_time": _ms(chain.get("last_time"))})
    graph["identity_context"] = [
        {"type": o["type"], "principal": o["principal"], "at": o["event_time"]}
        for o in ctx["observations"]]
    return graph


@router.get("/investigations/{cluster_id}/external-links")
async def investigation_links(cluster_id: str, request: Request,
                              p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    resolved, doc = await _document(request, cluster_id)
    links = [{"kind": "provider_incident", **l} for l in
             await rt.investigations.links(resolved) if l.get("url")]
    for alert in doc.get("chain", {}).get("alerts", []):
        src = alert.get("source") or {}
        url = src.get("source_url")
        if isinstance(url, str) and url.startswith("https://"):
            links.append({"kind": "provider_alert", "provider": src.get("provider"),
                          "url": url, "title": alert.get("title")})
    # Rendered as links only; the server never fetches them.
    return {"cluster_id": resolved, "links": links}


@router.post("/investigations/{cluster_id}/notes", status_code=201)
async def add_note(cluster_id: str, body: NoteCreate, request: Request,
                   p: Principal = Depends(_principal)):
    require(p, "analyst")
    rt = _rt(request)
    resolved, _ = await _document(request, cluster_id)
    _check_revision(body.expected_revision, await _stored_revision(rt, resolved))
    note_id = await rt.investigations.add_note(
        resolved, body.expected_revision, p.username, body.body)
    await rt.audit.append(p.username, "investigation.note", resolved,
                          {"note_id": note_id, "revision": body.expected_revision})
    return {"note_id": note_id, "cluster_id": resolved}


@router.post("/investigations/{cluster_id}/assign")
async def assign(cluster_id: str, body: AssignRequest, request: Request,
                 p: Principal = Depends(_principal)):
    require(p, "analyst")
    rt = _rt(request)
    resolved, _ = await _document(request, cluster_id)
    _check_revision(body.expected_revision, await _stored_revision(rt, resolved))
    await rt.investigations.assign(resolved, body.owner)
    await rt.audit.append(p.username, "investigation.assigned", resolved,
                          {"owner": body.owner})
    return {"cluster_id": resolved, "owner": body.owner}


# -- response ------------------------------------------------------------------------

@router.get("/response/workflows")
async def workflows(request: Request, p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    return {"enabled": rt.config.logic_apps.enabled,
            "workflows": [w.view() for w in rt.policy.workflows()]}


@router.post("/investigations/{cluster_id}/actions", status_code=201)
async def propose_action(cluster_id: str, body: ActionCreate, request: Request,
                         p: Principal = Depends(_principal)):
    require(p, "analyst")
    rt = _rt(request)
    resolved, doc = await _document(request, cluster_id)
    _check_revision(body.expected_revision, await _stored_revision(rt, resolved))
    known = set(_evidence_refs(doc))
    unknown = [r for r in body.evidence_refs if r not in known]
    if unknown:
        raise HTTPException(422, f"evidence refs not in this investigation: {unknown}")
    action = await rt.actions.propose(
        p.username, p.role, cluster_id=resolved, revision=body.expected_revision,
        workflow_id=body.workflow_id, payload=body.payload,
        evidence_refs=body.evidence_refs, rationale=body.rationale)
    if (await rt.investigations.get(resolved) or {}).get("status") in ("new", "investigating"):
        await rt.investigations.set_status(resolved, "awaiting_approval")
    return action.view()


@router.get("/investigations/{cluster_id}/actions")
async def list_actions(cluster_id: str, request: Request,
                       p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    resolved, _ = await _document(request, cluster_id)
    return {"cluster_id": resolved,
            "actions": [a.view() for a in await rt.actions.list_for(resolved)]}


@router.post("/actions/{action_id}/approve")
async def approve_action(action_id: str, body: ActionDecision, request: Request,
                         p: Principal = Depends(_principal)):
    rt = _rt(request)
    action = await rt.actions.approve(p.username, p.role, action_id, body.rationale)
    if action.state.value == "queued":
        await rt.investigations.set_status(action.cluster_id, "response_queued")
    return action.view()


@router.post("/actions/{action_id}/reject")
async def reject_action(action_id: str, body: ActionDecision, request: Request,
                        p: Principal = Depends(_principal)):
    rt = _rt(request)
    return (await rt.actions.reject(p.username, p.role, action_id,
                                    body.rationale)).view()


@router.post("/actions/{action_id}/cancel")
async def cancel_action(action_id: str, request: Request,
                        p: Principal = Depends(_principal)):
    rt = _rt(request)
    return (await rt.actions.cancel(p.username, p.role, action_id)).view()


@router.post("/actions/{action_id}/reconcile")
async def reconcile_action(action_id: str, body: ReconcileRequest, request: Request,
                           p: Principal = Depends(_principal)):
    rt = _rt(request)
    return (await rt.reconciler.resolve(
        p.username, p.role, action_id, body.outcome, run_id=body.run_id,
        note=body.note)).view()


@router.get("/actions/{action_id}")
async def get_action(action_id: str, request: Request,
                     p: Principal = Depends(_principal)):
    require(p, "viewer")
    rt = _rt(request)
    return (await rt.actions.get(action_id)).view()


@router.get("/audit")
async def audit(request: Request, target: str | None = None, limit: int = 100,
                p: Principal = Depends(_principal)):
    require(p, "analyst")
    rt = _rt(request)
    entries = await rt.audit.list(target=target, limit=max(1, min(limit, 500)))
    if not p.at_least("responder"):
        own = {a.action_id for a in await rt.actions.list_for()
               if a.requested_by == p.username}
        entries = [e for e in entries
                   if e["actor"] == p.username or e["target"] in own]
    return {"entries": entries}


@router.get("/audit/verify")
async def verify_audit(request: Request, p: Principal = Depends(_principal)):
    require(p, "administrator")
    return await _rt(request).audit.verify()


@router.get("/metrics")
async def metrics(request: Request, p: Principal = Depends(_principal)):
    require(p, "analyst")
    return await _rt(request).metrics()
