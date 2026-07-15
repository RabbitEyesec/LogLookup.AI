"""Production-hardening acceptance:

- unchanged chains are NOT re-triaged on later evaluation cycles
  (fingerprint skip), but a grown chain or a provider switch is;
- the correlation engine releases expired chains from live state
  (long-running poll processes stay bounded);
- the poll cursor store survives a restart round-trip;
- re-triage on a --no-ai process is refused honestly (409), never a
  silent "pending" document.
"""

from __future__ import annotations

import asyncio
import dataclasses

import pytest
from fastapi.testclient import TestClient

from engine.ai.service import TriageService
from engine.api.server import create_app
from engine.settings import PollCursorStore
from tests.test_reasoner import make_verdict


@pytest.fixture()
def counting_service(engine_config, fixture_kb, tmp_path):
    """TriageService whose injected model counts invocations."""
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
    calls = {"n": 0}

    async def fake_create(**_kwargs):
        calls["n"] += 1
        return make_verdict(critical_evidence_fields=["rule.name"])

    return TriageService(config, create_fn=fake_create), calls


def test_unchanged_chain_not_retriaged(correlated_pipeline, counting_service):
    pipeline, result = correlated_pipeline
    service, calls = counting_service

    asyncio.run(service.process_all(pipeline.correlator, result.clusters))
    first_calls = calls["n"]
    assert first_calls == 1  # only the surfaced chain is in scope

    surfaced_id = result.surfaced[0].cluster_id
    first_doc = service.get_result(surfaced_id)

    # Same clusters, next cycle: no new AI calls, same document object.
    asyncio.run(service.process_all(pipeline.correlator, result.clusters))
    assert calls["n"] == first_calls
    assert service.get_result(surfaced_id) is first_doc


def test_provider_switch_triggers_retriage(correlated_pipeline,
                                           counting_service):
    pipeline, result = correlated_pipeline
    service, calls = counting_service
    asyncio.run(service.process_all(pipeline.correlator, result.clusters))
    before = calls["n"]

    service.providers.switch(provider="anthropic", cloud_api_key="k")
    asyncio.run(service.process_all(pipeline.correlator, result.clusters))
    assert calls["n"] == before + 1  # surfaced chain re-triaged once


def test_force_bypasses_fingerprint(correlated_pipeline, counting_service):
    pipeline, result = correlated_pipeline
    service, calls = counting_service
    cluster = result.surfaced[0]
    asyncio.run(service.process_cluster(pipeline.correlator, cluster))
    asyncio.run(
        service.process_cluster(pipeline.correlator, cluster, force=True)
    )
    assert calls["n"] == 2


def test_prune_before_releases_expired_chains(correlated_pipeline):
    pipeline, _result = correlated_pipeline
    engine = pipeline.correlator
    clusters = engine.clusters()
    assert len(clusters) == 2
    cutoff = max(c.last_time_ms for c in clusters) + 1

    pruned = engine.prune_before(cutoff)

    assert pruned == 2
    assert engine.clusters() == []
    assert engine._alerts == {}
    assert engine._graph.number_of_nodes() == 0
    assert engine._timelines == {}
    # Pruning is idempotent.
    assert engine.prune_before(cutoff) == 0


def test_prune_before_keeps_live_chains(correlated_pipeline):
    pipeline, result = correlated_pipeline
    engine = pipeline.correlator
    surfaced = result.surfaced[0]
    # Cut between the two chains: only the older one goes.
    others = [c for c in engine.clusters()
              if c.cluster_id != surfaced.cluster_id]
    cutoff = surfaced.last_time_ms  # strictly-before comparison keeps it
    engine.prune_before(cutoff)
    kept = {c.cluster_id for c in engine.clusters()}
    assert surfaced.cluster_id in kept
    for other in others:
        if other.last_time_ms < cutoff:
            assert other.cluster_id not in kept


def test_poll_cursor_store_roundtrip(tmp_path):
    store = PollCursorStore(tmp_path)
    assert store.load() is None
    store.save(1783764000123)
    assert store.load() == 1783764000123
    # A corrupt state file degrades to "no cursor", never an exception.
    (tmp_path / "state.json").write_text("{not json")
    assert PollCursorStore(tmp_path).load() is None


def test_retriage_refused_when_ai_disabled(correlated_pipeline, fixture_kb,
                                           engine_config, tmp_path):
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
    service = TriageService(config, ai_enabled=False)
    asyncio.run(service.process_all(pipeline.correlator, result.clusters))
    app = create_app(config, service, pipeline=pipeline)
    with TestClient(app) as client:
        cluster_id = result.surfaced[0].cluster_id
        response = client.post(f"/api/clusters/{cluster_id}/triage")
        assert response.status_code == 409
        assert "disabled" in response.json()["detail"]
