"""Phase 15/16 acceptance: backend API + dashboard data endpoints.

Runs the full stack in-process: fixture alerts -> correlation -> AI triage
(injected model) -> API, exercised through the FastAPI test client.
"""

from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from engine.ai.service import TriageService
from engine.api.server import create_app
from engine.api.views import graph_view, timeline_view
from tests.test_reasoner import make_verdict


@pytest.fixture()
def app_client(correlated_pipeline, fixture_kb, engine_config, tmp_path):
    pipeline, result = correlated_pipeline
    fixture_kb.save(tmp_path / "kb.json")
    config = dataclasses.replace(
        engine_config,
        ai=dataclasses.replace(
            engine_config.ai,
            rag=dataclasses.replace(
                engine_config.ai.rag, kb_path=str(tmp_path / "kb.json")
            ),
        ),
    )

    async def fake_create(**_kwargs):
        return make_verdict(critical_evidence_fields=["rule.name"])

    service = TriageService(config, create_fn=fake_create)
    app = create_app(config, service, pipeline=pipeline)

    # Populate results the way the server runner does at startup.
    import asyncio

    asyncio.run(service.process_all(pipeline.correlator, result.clusters))

    with TestClient(app) as client:
        yield client, service


SURFACED = "CHAIN-2026-07-11-hostA-001"


def test_status(app_client):
    client, _service = app_client
    body = client.get("/api/status").json()
    assert body["engine"]["clusters"] == 2
    assert body["engine"]["surfaced"] == 1
    assert body["kb"]["loaded"] is True
    assert body["kb"]["techniques"] == 4
    assert body["ai"]["triage_available"] is True
    assert body["ai"]["provider"] == "local"
    assert body["siem"]["configured"] is True
    assert body["siem"]["reachable"] is None  # not a live SIEM process


def test_cluster_list_and_filter(app_client):
    client, _service = app_client
    body = client.get("/api/clusters").json()
    assert body["total"] == 2
    briefs = {b["cluster_id"]: b for b in body["clusters"]}
    surfaced = briefs[SURFACED]
    assert surfaced["verdict"] == "True Positive"
    assert surfaced["mitre_attack_techniques"] == ["T1110", "T1003"]
    assert surfaced["max_severity"] == "High"
    assert surfaced["surfaced"] is True
    assert surfaced["dashboard_url"].endswith(f"/incident/{SURFACED}")

    filtered = client.get("/api/clusters?surfaced_only=true").json()
    assert [b["cluster_id"] for b in filtered["clusters"]] == [SURFACED]


def test_cluster_detail_and_404(app_client):
    client, _service = app_client
    doc = client.get(f"/api/clusters/{SURFACED}").json()
    assert doc["cluster_id"] == SURFACED
    assert doc["triage"]["verdict"] == "True Positive"
    assert "# Attack Chain" in doc["report_markdown"]
    missing = client.get("/api/clusters/CHAIN-nope-000")
    assert missing.status_code == 404


def test_timeline_endpoint(app_client):
    client, _service = app_client
    timeline = client.get(f"/api/clusters/{SURFACED}/timeline").json()
    # Kill-chain lane order: credential access before lateral movement.
    assert timeline["lanes"] == ["Credential Access", "Lateral Movement"]
    events = timeline["events"]
    assert [e["uid"] for e in events] == ["evt-001", "evt-004", "evt-005"]
    by_uid = {e["uid"]: e for e in events}
    assert by_uid["evt-001"]["lane"] == "Credential Access"
    assert by_uid["evt-005"]["lane"] == "Lateral Movement"
    assert by_uid["evt-005"]["lane_index"] == 1
    assert by_uid["evt-004"]["techniques"][0]["uid"] == "T1003"


def test_timeline_untagged_lane():
    doc = {"cluster_id": "c", "chain": {"alerts": [
        {"uid": "a1", "time": 10, "tactics": [], "entities": []},
    ]}}
    view = timeline_view(doc)
    assert view["lanes"] == ["Untagged"]
    assert view["events"][0]["lane_index"] == 0


def test_graph_endpoint(app_client):
    client, _service = app_client
    graph = client.get(f"/api/clusters/{SURFACED}/graph").json()
    nodes = {n["id"]: n for n in graph["nodes"]}
    # Entities as nodes: hosts, user, and the external source IP.
    assert "hostA" in nodes and "hostB" in nodes and "jdoe" in nodes
    assert nodes["hostA"]["is_primary"] is True
    assert nodes["jdoe"]["domain"] == "user"
    # Alerts as edges between co-occurring entities.
    edges = {(l["source"], l["target"], l["alert_uid"])
             for l in graph["links"]}
    assert ("hostA", "jdoe", "evt-004") in edges
    assert ("hostB", "jdoe", "evt-005") in edges
    # Every alert is attached to the nodes it touched.
    assert any(a["uid"] == "evt-001" for a in nodes["hostA"]["alerts"])
    chain_nodes = graph["chain_nodes"]
    assert any(n["kind"] == "event" and n["alert_uid"] == "evt-004"
               for n in chain_nodes)
    assert any(n["kind"] == "technique" and n["technique_uid"] == "T1003"
               for n in chain_nodes)


def test_attack_metadata_endpoint(app_client):
    client, _service = app_client
    body = client.get("/api/attack/techniques?ids=T1059.001,T1003").json()
    records = {record["uid"]: record for record in body["techniques"]}
    assert records["T1059.001"]["name"] == "PowerShell"
    assert records["T1059.001"]["description"]
    assert records["T1059.001"]["url"].startswith("https://attack.mitre.org/")


def test_graph_view_pairwise_expansion():
    doc = {"cluster_id": "c", "chain": {
        "primary_entity": "h1",
        "entities": [{"name": n, "domain": "host", "risk_score": 1,
                      "identifiers": {}} for n in ("h1", "h2", "h3")],
        "alerts": [{"uid": "a1", "entities": ["h1", "h2", "h3"],
                    "title": "t", "time_dt": "", "severity": "High"}],
    }}
    view = graph_view(doc)
    assert len(view["links"]) == 3  # 3 choose 2


def test_ai_settings_roundtrip_and_switch(app_client):
    client, _service = app_client
    settings = client.get("/api/settings/ai").json()
    assert settings["provider"] == "local"
    assert "cloud_api_key" not in settings  # never echoed

    updated = client.put("/api/settings/ai", json={
        "provider": "anthropic", "cloud_api_key": "test-key",
    }).json()
    assert updated["model_id"] == "anthropic/claude-opus-4-8"
    assert updated["cloud_api_key_set"] is True
    assert "test-key" not in str(updated)

    bad = client.put("/api/settings/ai", json={"provider": "skynet"})
    assert bad.status_code == 400
    empty = client.put("/api/settings/ai", json={})
    assert empty.status_code == 400
    # Manager survived the bad requests.
    assert client.get("/api/settings/ai").json()["provider"] == "anthropic"


def test_retriage_endpoint(app_client):
    client, _service = app_client
    # Force triage of the chain that was out of scope (not surfaced).
    body = client.get("/api/clusters").json()
    lone = next(b for b in body["clusters"] if not b["surfaced"])
    assert lone["triage_status"] == "pending"
    doc = client.post(f"/api/clusters/{lone['cluster_id']}/triage").json()
    assert doc["triage_status"] == "triaged"
    missing = client.post("/api/clusters/CHAIN-nope-000/triage")
    assert missing.status_code == 404


def test_ui_routes_serve_html(app_client):
    client, _service = app_client
    index = client.get("/")
    assert index.status_code == 200
    assert "LogLookup" in index.text
    incident = client.get(f"/incident/{SURFACED}")
    assert incident.status_code == 200
    assert "timeline" in incident.text.lower()
    assert client.get("/static/theme.css").status_code == 200
    assert client.get("/static/js/ide.js").status_code == 200
    assert client.get("/static/vendor/3d-force-graph.min.js").status_code == 200
