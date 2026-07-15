"""Phase 14 acceptance (Build Plan Phase-5 milestone checklist):

- a formed cluster becomes a write-back document in Elastic tagged with
  cluster_id + dashboard_url;
- the document id IS the cluster_id, so re-runs update instead of dupe;
- write-back failures are reported honestly and do not kill the pipeline.
"""

from __future__ import annotations

import json

import httpx
import pytest

from engine.ai.service import TriageService
from engine.config import OutputConfig, SiemConfig
from engine.connectors.elastic import ConnectorError, ElasticConnector
from engine.connectors.writeback import (
    TRIAGE_STATUS_AI_UNAVAILABLE,
    ResultWriter,
    build_writeback_doc,
)


class FakeResultsIndex:
    """In-memory Elastic _doc endpoint for the results index."""

    def __init__(self, fail: bool = False) -> None:
        self.docs: dict[str, dict] = {}
        self.fail = fail

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(503, text="unavailable")
        parts = request.url.path.strip("/").split("/")
        assert parts[1] == "_doc"
        doc_id = parts[2]
        if request.method == "PUT":
            created = doc_id not in self.docs
            self.docs[doc_id] = json.loads(request.content)
            return httpx.Response(
                201 if created else 200,
                json={"_id": doc_id, "result": "created" if created else
                      "updated"},
            )
        if request.method == "GET":
            if doc_id not in self.docs:
                return httpx.Response(404, json={"found": False})
            return httpx.Response(
                200, json={"_id": doc_id, "found": True,
                           "_source": self.docs[doc_id]}
            )
        raise AssertionError(f"unexpected {request.method}")


def make_writer(fake: FakeResultsIndex, output=None):
    siem = SiemConfig(host="http://elastic.test:9200", api_key="secret")
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(fake.handler), base_url=siem.host
    )
    connector = ElasticConnector(siem, client=client)
    return ResultWriter(connector, output or OutputConfig())


def _summary(correlated_pipeline):
    pipeline, result = correlated_pipeline
    cluster = result.surfaced[0]
    return pipeline.correlator.cluster_summary(cluster)


def test_writeback_doc_shape(correlated_pipeline):
    summary = _summary(correlated_pipeline)
    doc = build_writeback_doc(summary, None, OutputConfig(),
                              report_markdown="# report")
    assert doc["cluster_id"] == "CHAIN-2026-07-11-hostA-001"
    assert doc["dashboard_url"] == (
        "http://localhost:8080/incident/CHAIN-2026-07-11-hostA-001"
    )
    assert doc["@timestamp"] == "2026-07-11T10:45:00.000Z"  # last alert time
    assert doc["chain"]["alert_count"] == 3
    assert doc["chain"]["disposition"] == "progressing"
    assert doc["triage_status"] == "pending"
    assert doc["report_markdown"] == "# report"
    assert doc["source"] == "loglookup-ai"


async def test_write_is_idempotent_by_cluster_id(correlated_pipeline):
    summary = _summary(correlated_pipeline)
    fake = FakeResultsIndex()
    writer = make_writer(fake)
    doc = build_writeback_doc(summary, None, OutputConfig())
    assert await writer.write(doc) is True
    assert await writer.write(doc) is True  # same id -> update, not dupe
    assert list(fake.docs) == ["CHAIN-2026-07-11-hostA-001"]
    stored = fake.docs["CHAIN-2026-07-11-hostA-001"]
    assert stored["dashboard_url"].endswith(
        "/incident/CHAIN-2026-07-11-hostA-001"
    )


async def test_write_failure_is_survivable(correlated_pipeline):
    summary = _summary(correlated_pipeline)
    writer = make_writer(FakeResultsIndex(fail=True))
    doc = build_writeback_doc(summary, None, OutputConfig())
    assert await writer.write(doc) is False  # logged, not raised


async def test_read_back_by_cluster_id(correlated_pipeline):
    summary = _summary(correlated_pipeline)
    fake = FakeResultsIndex()
    writer = make_writer(fake)
    await writer.write(build_writeback_doc(summary, None, OutputConfig()))
    doc = await writer.read("CHAIN-2026-07-11-hostA-001")
    assert doc is not None and doc["chain"]["alert_count"] == 3
    assert await writer.read("CHAIN-nope-000") is None


async def test_get_doc_raises_on_server_error():
    fake = FakeResultsIndex(fail=True)
    siem = SiemConfig(host="http://elastic.test:9200")
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(fake.handler), base_url=siem.host
    )
    connector = ElasticConnector(siem, client=client)
    with pytest.raises(ConnectorError):
        await connector.get_doc("idx", "id1")


async def test_service_end_to_end_with_writeback(
    correlated_pipeline, fixture_kb, engine_config, tmp_path
):
    """Chain -> triage (injected model) -> report -> Elastic doc."""
    from tests.test_reasoner import make_verdict

    pipeline, result = correlated_pipeline
    fixture_kb.save(tmp_path / "kb.json")
    # Point the service at the saved fixture KB.
    import dataclasses

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

    fake = FakeResultsIndex()
    service = TriageService(
        config, writer=make_writer(fake), create_fn=fake_create
    )
    docs = await service.process_all(pipeline.correlator, result.clusters)

    assert len(docs) == 2  # surfaced chain + lone unsurfaced chain
    surfaced_doc = fake.docs["CHAIN-2026-07-11-hostA-001"]
    assert surfaced_doc["triage_status"] == "triaged"
    assert surfaced_doc["triage"]["verdict"] == "True Positive"
    assert surfaced_doc["triage"]["mitre_attack_techniques"] == [
        "T1110", "T1003",
    ]
    assert "# Attack Chain CHAIN-2026-07-11-hostA-001" in (
        surfaced_doc["report_markdown"]
    )
    # The unsurfaced chain is written deterministically, not AI-triaged
    # (triage_scope: surfaced).
    lone = next(d for cid, d in fake.docs.items() if cid != surfaced_doc[
        "cluster_id"])
    assert lone["triage_status"] == "pending"
    assert "triage" not in lone
    # The service's local store mirrors what was written.
    assert service.get_result("CHAIN-2026-07-11-hostA-001") == surfaced_doc


async def test_service_without_kb_degrades_honestly(
    correlated_pipeline, engine_config
):
    pipeline, result = correlated_pipeline
    # engine_config points at var/attack_kb.json relative default? It uses
    # the repo default path; force a missing path to simulate no KB.
    import dataclasses

    config = dataclasses.replace(
        engine_config,
        ai=dataclasses.replace(
            engine_config.ai,
            rag=dataclasses.replace(
                engine_config.ai.rag, kb_path="/nonexistent/kb.json"
            ),
        ),
    )
    service = TriageService(config)
    doc = await service.process_cluster(
        pipeline.correlator, result.surfaced[0]
    )
    assert doc["triage_status"] == TRIAGE_STATUS_AI_UNAVAILABLE
    assert "knowledge base not found" in doc["triage_error"]
    assert "triage" not in doc  # no invented verdict
    assert "pending. AI triage was not available" in doc["report_markdown"]
