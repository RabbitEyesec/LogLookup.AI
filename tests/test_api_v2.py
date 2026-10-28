"""v2 HTTP API: identity, roles, revisions, secrecy, response flow."""

from __future__ import annotations

import httpx
import pytest

from engine.api.auth import hash_token, new_token
from engine.api.server import create_app
from engine.response.models import DispatchResult
from tests.test_response_v2 import LA, FakeTransport
from tests.v2_helpers import DEFENDER_SRC, SENTINEL_SRC, MockVendors, build_runtime, settle

CSRF = {"x-loglookup-client": "1"}


async def make_api(tmp_path, sources=None, transport=None, vendors=None):
    vendors = vendors or MockVendors()
    rt = await build_runtime(tmp_path, sources if sources is not None
                             else [SENTINEL_SRC, DEFENDER_SRC], vendors, **LA)
    rt.dispatcher._transport = transport or FakeTransport()
    await rt.dispatcher.stop()
    if sources is None:
        await settle(rt, 3)
        rt.pipeline.evaluate(flush=True)
        await rt.evaluate_now()
    app = create_app(rt.config, rt.service, pipeline=rt.pipeline)
    app.state.v2 = rt
    return app, rt


def client(app, host="127.0.0.1", host_header="127.0.0.1:8080"):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(host, 5000)),
        base_url=f"http://{host_header}")


async def token_for(rt, user, role):
    token = new_token()
    await rt.db.execute("INSERT INTO api_tokens VALUES (?,?,?,?,?,0)",
                        (hash_token(token), user, role, rt.scope_id, "now"))
    return {"authorization": f"Bearer {token}"}


async def first_cluster(c, h):
    r = await c.get("/api/v2/investigations", headers=h)
    assert r.status_code == 200, r.text
    inv = r.json()["investigations"][0]
    return inv["cluster_id"], inv["revision"]


async def test_remote_peer_without_credentials_is_rejected(tmp_path):
    app, rt = await make_api(tmp_path)
    try:
        async with client(app, host="203.0.113.7") as c:
            assert (await c.get("/api/v2/connections")).status_code == 401
            spoof = await c.get("/api/v2/connections", headers={
                "X-Forwarded-User": "root", "X-Forwarded-Role": "administrator"})
            assert spoof.status_code == 401        # untrusted peer cannot assert identity
            bad = await c.get("/api/v2/connections",
                              headers={"authorization": "Bearer llk_nope"})
            assert bad.status_code == 401
    finally:
        await rt.stop()


async def test_trusted_proxy_identity_is_honoured_only_from_listed_peers(tmp_path):
    app, rt = await make_api(tmp_path)
    rt.config = rt.config.__class__(**{**rt.config.__dict__, "access":
        rt.config.access.__class__(trusted_proxy_ips=("10.0.0.0/8",))})
    app.state.config = rt.config
    try:
        h = {"X-Forwarded-User": "carol", "X-Forwarded-Role": "analyst"}
        async with client(app, host="10.1.2.3") as c:
            assert (await c.get("/api/v2/audit", headers=h)).status_code == 200
        async with client(app, host="198.51.100.1") as c:
            assert (await c.get("/api/v2/audit", headers=h)).status_code == 401
    finally:
        await rt.stop()


async def test_local_owner_needs_csrf_header_for_mutations(tmp_path):
    app, rt = await make_api(tmp_path, sources=[])
    try:
        async with client(app) as c:
            assert (await c.get("/api/v2/connections")).status_code == 200
            body = {"connection_id": "e1", "provider": "entra_id"}
            assert (await c.post("/api/v2/connections", json=body)).status_code == 403
            ok = await c.post("/api/v2/connections", json=body, headers=CSRF)
            assert ok.status_code == 201
            cross = await c.post("/api/v2/connections/e1/pause", headers={
                **CSRF, "origin": "https://evil.example"})
            assert cross.status_code == 403
            # a proxied request is never treated as the implicit local owner
            fwd = await c.get("/api/v2/connections",
                              headers={"x-forwarded-for": "1.2.3.4"})
            assert fwd.status_code == 401
    finally:
        await rt.stop()


async def test_credentials_are_write_only_everywhere(tmp_path):
    app, rt = await make_api(tmp_path, sources=[])
    try:
        async with client(app) as c:
            secret = "s3cr3t-value-123"
            r = await c.post("/api/v2/connections", headers=CSRF, json={
                "connection_id": "sent1", "provider": "sentinel", "enabled": False,
                "options": {"tenant_id": "22222222-2222-2222-2222-222222222222",
                            "workspace_id": "11111111-1111-1111-1111-111111111111"},
                "credentials": {"kind": "client_secret", "client_id": "cid",
                                "client_secret": secret}})
            assert r.status_code == 201 and secret not in r.text
            for path in ("/api/v2/connections", "/api/v2/connections/sent1",
                         "/api/v2/sources/health"):
                assert secret not in (await c.get(path)).text
            # validation errors must not echo submitted values either
            bad = await c.post("/api/v2/connections", headers=CSRF, json={
                "connection_id": "x", "provider": "sentinel", "poll_seconds": "oops",
                "credentials": {"client_secret": secret}})
            assert bad.status_code == 422 and secret not in bad.text
            assert rt.secrets.get("auth_profile:sent1-auth")        # but it IS stored
            # rotation keeps the connection (and its cursor history)
            rot = await c.patch("/api/v2/connections/sent1", headers=CSRF, json={
                "credentials": {"kind": "client_secret", "client_id": "cid",
                                "client_secret": "rotated"}})
            assert rot.status_code == 200 and "rotated" not in rot.text
    finally:
        await rt.stop()


async def test_bad_connection_config_is_rejected_when_enabled(tmp_path):
    app, rt = await make_api(tmp_path, sources=[])
    try:
        async with client(app) as c:
            r = await c.post("/api/v2/connections", headers=CSRF, json={
                "connection_id": "spl", "provider": "splunk", "enabled": True,
                "options": {"management_url": "http://169.254.169.254:8089",
                            "indexes": ["notable"]},
                "credentials": {"kind": "token", "token": "t"}})
            assert r.status_code == 422
            dup = await c.post("/api/v2/connections", headers=CSRF, json={
                "connection_id": "ok1", "provider": "entra_id"})
            again = await c.post("/api/v2/connections", headers=CSRF, json={
                "connection_id": "ok1", "provider": "entra_id"})
            assert dup.status_code == 201 and again.status_code == 409
    finally:
        await rt.stop()


async def test_roles_gate_reads_writes_and_raw_evidence(tmp_path):
    app, rt = await make_api(tmp_path)
    try:
        viewer = await token_for(rt, "vera", "viewer")
        analyst = await token_for(rt, "ann", "analyst")
        async with client(app, host="203.0.113.7") as c:
            cid, rev = await first_cluster(c, viewer)
            ev = await c.get(f"/api/v2/investigations/{cid}/evidence", headers=viewer)
            assert ev.status_code == 200 and "raw" not in ev.json()["events"][0]
            assert (await c.get(f"/api/v2/investigations/{cid}/evidence",
                                params={"include_raw": True}, headers=viewer)).status_code == 403
            raw = await c.get(f"/api/v2/investigations/{cid}/evidence",
                              params={"include_raw": True}, headers=analyst)
            assert raw.status_code == 200 and "raw" in raw.json()["events"][0]
            note = {"body": "looks real", "expected_revision": rev}
            assert (await c.post(f"/api/v2/investigations/{cid}/notes",
                                 json=note, headers=viewer)).status_code == 403
            assert (await c.post(f"/api/v2/investigations/{cid}/notes",
                                 json=note, headers=analyst)).status_code == 201
            stale = {"body": "x", "expected_revision": rev + 5}
            assert (await c.post(f"/api/v2/investigations/{cid}/notes",
                                 json=stale, headers=analyst)).status_code == 409
            assert (await c.post("/api/v2/connections/sentinel-main/pause",
                                 headers=analyst)).status_code == 403
            # raw reads leave an audit trail
            audit = await c.get("/api/v2/audit", headers=analyst)
            assert any(e["action"] == "evidence.raw_read" for e in audit.json()["entries"])
    finally:
        await rt.stop()


async def test_investigation_views_expose_provenance_and_identity(tmp_path):
    app, rt = await make_api(tmp_path)
    try:
        h = await token_for(rt, "vera", "viewer")
        async with client(app, host="203.0.113.7") as c:
            cid, _ = await first_cluster(c, h)
            lst = (await c.get("/api/v2/investigations", headers=h)).json()
            assert lst["investigations"][0]["source_diversity"] == 2
            assert lst["investigations"][0]["title"]
            only = (await c.get("/api/v2/investigations",
                                params={"provider": "splunk"}, headers=h)).json()
            assert only["investigations"] == []
            detail = (await c.get(f"/api/v2/investigations/{cid}", headers=h)).json()
            assert detail["evidence_refs"] and detail["document"]["chain"]["sources"]
            links = (await c.get(f"/api/v2/investigations/{cid}/external-links",
                                 headers=h)).json()["links"]
            assert any(l["url"].startswith("https://") for l in links)
            tl = (await c.get(f"/api/v2/investigations/{cid}/timeline", headers=h)).json()
            assert tl["provenance"]
            assert (await c.get(f"/api/v2/investigations/{cid}/graph", headers=h)).status_code == 200
    finally:
        await rt.stop()


async def test_merged_chain_ids_keep_resolving(tmp_path):
    app, rt = await make_api(tmp_path)
    try:
        h = await token_for(rt, "vera", "viewer")
        async with client(app, host="203.0.113.7") as c:
            cid, _ = await first_cluster(c, h)
            await rt.db.execute("INSERT INTO cluster_aliases VALUES (?,?,?)",
                                ("CHAIN-2026-01-01-old-001", cid, "now"))
            r = await c.get("/api/v2/investigations/CHAIN-2026-01-01-old-001", headers=h)
            assert r.status_code == 200
            assert r.json()["cluster_id"] == cid
            assert r.json()["resolved_from"] == "CHAIN-2026-01-01-old-001"
    finally:
        await rt.stop()


async def test_full_response_flow_over_http(tmp_path):
    t = FakeTransport(DispatchResult("accepted", "run-7", http_status=202))
    app, rt = await make_api(tmp_path, transport=t)
    try:
        analyst = await token_for(rt, "ann", "analyst")
        responder = await token_for(rt, "rob", "responder")
        async with client(app, host="203.0.113.7") as c:
            cid, rev = await first_cluster(c, analyst)
            wf = (await c.get("/api/v2/response/workflows", headers=analyst)).json()
            assert {w["workflow_id"] for w in wf["workflows"]} == {
                "notify-soc-v1", "create-incident-v1"}
            detail = (await c.get(f"/api/v2/investigations/{cid}", headers=analyst)).json()
            body = {"workflow_id": "notify-soc-v1", "expected_revision": rev,
                    "payload": {"message": "triage ws01", "severity": "high"},
                    "evidence_refs": detail["evidence_refs"][:1]}
            made = await c.post(f"/api/v2/investigations/{cid}/actions",
                                json=body, headers=analyst)
            assert made.status_code == 201, made.text
            aid = made.json()["action_id"]
            assert (await c.post(f"/api/v2/investigations/{cid}/actions",
                                 json=body, headers=analyst)).status_code == 409
            bogus = dict(body, evidence_refs=["SRC:made-up:alert:1"])
            assert (await c.post(f"/api/v2/investigations/{cid}/actions",
                                 json=bogus, headers=analyst)).status_code == 422
            assert (await c.post(f"/api/v2/actions/{aid}/approve", json={},
                                 headers=analyst)).status_code == 403
            ok = await c.post(f"/api/v2/actions/{aid}/approve",
                              json={"rationale": "confirmed"}, headers=responder)
            assert ok.json()["state"] == "queued"
            await rt.dispatcher.run_once()
            final = (await c.get(f"/api/v2/actions/{aid}", headers=analyst)).json()
            assert final["state"] == "acknowledged"
            assert final["provider_run_id"] == "run-7"
            assert final["status_layers"]["downstream_effect"] == "not_observed"
            trail = (await c.get("/api/v2/audit", params={"target": aid},
                                 headers=responder)).json()["entries"]
            assert {"action.proposed", "action.approved",
                    "action.acknowledged"} <= {e["action"] for e in trail}
            admin = await token_for(rt, "root", "administrator")
            assert (await c.get("/api/v2/audit/verify", headers=admin)).json()["valid"]
    finally:
        await rt.stop()


async def test_response_channel_disabled_by_default(tmp_path):
    vendors = MockVendors()
    rt = await build_runtime(tmp_path, [], vendors)         # no outputs.logic_apps
    try:
        assert rt.dispatcher._transport is None
        from engine.response.models import ResponseError
        with pytest.raises(ResponseError) as exc:
            await rt.actions.propose("ann", "analyst", cluster_id="C", revision=1,
                                     workflow_id="notify-soc-v1", payload={},
                                     evidence_refs=[])
        assert exc.value.status == 503
    finally:
        await rt.stop()


async def test_pause_and_resume_one_source(tmp_path):
    app, rt = await make_api(tmp_path)
    try:
        admin = await token_for(rt, "root", "administrator")
        async with client(app, host="203.0.113.7") as c:
            p = await c.post("/api/v2/connections/sentinel-main/pause", headers=admin)
            assert p.json()["health"]["status"] == "paused"
            h = (await c.get("/api/v2/sources/health", headers=admin)).json()
            assert h["sources"]["sentinel-main"]["status"] == "paused"
            assert h["sources"]["defender-xdr"]["status"] == "healthy"
            r = await c.post("/api/v2/connections/sentinel-main/resume", headers=admin)
            assert r.json()["paused"] is False
    finally:
        await rt.stop()


async def test_dashboard_serves_v2_modules_and_wires_them(tmp_path):
    app, rt = await make_api(tmp_path, sources=[])
    try:
        async with client(app) as c:
            html = (await c.get("/incident/CHAIN-x")).text
            assert "investigations-v2.js" in html and 'id="v2-drawer"' in html
            for js in ("connections", "investigations-v2", "evidence-v2", "response", "api"):
                r = await c.get(f"/static/js/{js}.js")
                assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    finally:
        await rt.stop()


async def test_dns_rebinding_cannot_borrow_local_authority(tmp_path):
    app, rt = await make_api(tmp_path, sources=[])
    try:
        async with client(app, host_header="evil.example") as c:
            r = await c.get("/api/v2/connections")
            assert r.status_code == 403 and "Host" in r.json()["detail"]
        async with client(app, host_header="localhost:8080") as c:
            assert (await c.get("/api/v2/connections")).status_code == 200
        # bearer tokens are explicit credentials, not ambient authority
        tok = await token_for(rt, "ann", "analyst")
        async with client(app, host="203.0.113.7", host_header="evil.example") as c:
            assert (await c.get("/api/v2/audit", headers=tok)).status_code == 200
    finally:
        await rt.stop()


async def test_secrets_in_options_are_refused_and_failed_create_leaves_no_secret(tmp_path):
    app, rt = await make_api(tmp_path, sources=[])
    try:
        async with client(app) as c:
            r = await c.post("/api/v2/connections", headers=CSRF, json={
                "connection_id": "s1", "provider": "splunk",
                "options": {"management_url": "https://splunk.example.invalid:8089",
                            "indexes": ["notable"], "api_token": "oops"}})
            assert r.status_code == 422 and "credentials" in r.json()["detail"]
            bad = await c.post("/api/v2/connections", headers=CSRF, json={
                "connection_id": "s2", "provider": "splunk", "enabled": True,
                "options": {"management_url": "http://169.254.169.254:8089",
                            "indexes": ["notable"]},
                "credentials": {"kind": "token", "token": "tok-123"}})
            assert bad.status_code == 422
            assert rt.secrets.get("auth_profile:s2-auth") == ""
    finally:
        await rt.stop()
