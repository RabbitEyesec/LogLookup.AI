"""Phase 3 checkpoint: Elastic connector reads batches and polls."""

import asyncio
import json

import httpx
import pytest

from engine.config import SiemConfig
from engine.connectors.elastic import ConnectorError, ElasticConnector


def make_hit(doc_id: str, ts_ms: int, **source):
    return {
        "_id": doc_id,
        "_index": ".alerts-security",
        "_source": {"@timestamp": ts_ms, **source},
        "sort": [ts_ms],
    }


class FakeElastic:
    """Minimal in-memory Elastic _search behaviour for the queries we send."""

    def __init__(self, hits):
        self.hits = sorted(hits, key=lambda h: (h["sort"][0], h["_id"]))
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, json={"cluster_name": "fake"})
        body = json.loads(request.content)
        self.requests.append(body)
        flt = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        excluded = set()
        for clause in body["query"]["bool"].get("must_not", []):
            excluded.update(clause["ids"]["values"])
        selected = [
            h
            for h in self.hits
            if flt["gte"] <= h["sort"][0] < flt["lt"] and h["_id"] not in excluded
        ]
        selected = selected[: body["size"]]
        return httpx.Response(200, json={"hits": {"hits": selected}})


def make_connector(fake: FakeElastic, page_size=3, poll_seconds=60):
    siem = SiemConfig(
        host="http://elastic.test:9200",
        api_key="secret",
        poll_seconds=poll_seconds,
    )
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(fake.handler),
        base_url=siem.host,
        headers={"Authorization": f"ApiKey {siem.api_key}"},
    )
    return ElasticConnector(siem, client=client, page_size=page_size)


async def test_ping():
    conn = make_connector(FakeElastic([]))
    assert await conn.ping() is True


async def test_fetch_batch_paginates_in_event_time_order():
    hits = [make_hit(f"a{i}", 1000 + i * 10) for i in range(8)]
    fake = FakeElastic(hits)
    conn = make_connector(fake, page_size=3)
    got = [h["_id"] async for h in conn.fetch_batch(0, 10_000)]
    assert got == [f"a{i}" for i in range(8)]
    assert len(fake.requests) >= 3  # paginated


async def test_fetch_batch_handles_identical_timestamps_across_pages():
    # 5 alerts share one timestamp; page size 2 forces boundary handling.
    hits = [make_hit(f"s{i}", 5000) for i in range(5)]
    hits.append(make_hit("later", 6000))
    fake = FakeElastic(hits)
    conn = make_connector(fake, page_size=2)
    got = sorted([h["_id"] async for h in conn.fetch_batch(0, 10_000)])
    assert got == sorted(["s0", "s1", "s2", "s3", "s4", "later"])  # none skipped


async def test_fetch_batch_respects_range():
    hits = [make_hit("in", 5000), make_hit("out", 20_000)]
    conn = make_connector(FakeElastic(hits))
    got = [h["_id"] async for h in conn.fetch_batch(0, 10_000)]
    assert got == ["in"]


async def test_search_error_raises_connector_error():
    def handler(request):
        return httpx.Response(500, text="boom")

    siem = SiemConfig(host="http://elastic.test:9200")
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url=siem.host
    )
    conn = ElasticConnector(siem, client=client)
    with pytest.raises(ConnectorError):
        _ = [h async for h in conn.fetch_batch(0, 1)]


async def test_poll_yields_new_alerts_and_advances_cursor():
    fake = FakeElastic([make_hit("p1", 1000), make_hit("p2", 2000)])
    conn = make_connector(fake, poll_seconds=1)
    stop = asyncio.Event()
    got = []

    async def run():
        async for hit in conn.poll(since_ms=0, stop=stop):
            got.append(hit["_id"])
            if len(got) == 2:
                stop.set()

    await asyncio.wait_for(run(), timeout=5)
    assert got == ["p1", "p2"]
