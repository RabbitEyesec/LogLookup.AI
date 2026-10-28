"""v2.0.1 reliability: lossless paging, durable correlation hand-off,
atomic response settlement, truthful health, bounded backfill."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from engine.connectors.base import ConnectorError, PageResult, SourceConnection
from engine.connectors.sentinel import SentinelConnector
from engine.connectors.splunk import SplunkConnector
from engine.connectors.supervisor import ConnectionWorker
from engine.response.models import ActionState
from tests.test_api_v2 import CSRF, client, make_api
from tests.test_response_v2 import FakeTransport, propose, runtime as response_runtime
from tests.v2_helpers import (
    SENTINEL_SRC, SPLUNK_SRC, TENANT, WORKSPACE, MockVendors, build_runtime,
    fake_token, settle,
)

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def conn(provider, options, **kw):
    return SourceConnection(connection_id=f"{provider}-1", provider=provider,
                            options=options, **kw)


# --------------------------------------------------------------------------
# Sentinel: composite (TimeGenerated, SystemAlertId) seek
# --------------------------------------------------------------------------

class FakeKql:
    """Evaluates just the paging semantics of the reviewed KQL templates."""

    def __init__(self, rows, partial=False):
        self.rows, self.partial, self.queries = rows, partial, []

    @staticmethod
    def _ticks(t):
        base, _, frac = t.rstrip("Z").partition(".")
        return base, int(frac.ljust(7, "0")) if frac else 0

    def handler(self, request):
        query = json.loads(request.content)["query"]
        self.queries.append(query)
        if self.partial:
            return httpx.Response(200, json={"tables": [{"columns": [], "rows": []}],
                                             "error": {"code": "PartialError"}})
        rows = sorted(self.rows, key=lambda r: (self._ticks(r["TimeGenerated"]),
                                                r["SystemAlertId"]))
        seek = re.search(r'datetime\(([^)]+)\) or \(TimeGenerated == datetime\([^)]+\)'
                         r' and SystemAlertId > "([^"]+)"\)', query)
        if seek:
            lt, lid = seek.group(1), seek.group(2)
            rows = [r for r in rows if (self._ticks(r["TimeGenerated"]), r["SystemAlertId"])
                    > (self._ticks(lt), lid)]
        rows = rows[:int(re.search(r"take (\d+)", query).group(1))]
        cols = ["SystemAlertId", "TimeGenerated"]
        return httpx.Response(200, json={"tables": [{
            "columns": [{"name": c} for c in cols],
            "rows": [[r[c] for c in cols] for r in rows]}]})


def sentinel(fake, limit=2):
    return SentinelConnector(
        conn("sentinel", {"tenant_id": TENANT, "workspace_id": WORKSPACE,
                          "max_rows": limit}),
        fake_token, transport=httpx.MockTransport(fake.handler), clock=lambda: NOW)


async def test_sentinel_equal_timestamp_group_is_fully_traversed():
    t = "2026-10-28T11:59:00.1234567Z"                 # 100 ns precision, all equal
    rows = [{"SystemAlertId": f"a{i}", "TimeGenerated": t} for i in range(1, 6)]
    rows.append({"SystemAlertId": "b1", "TimeGenerated": "2026-10-28T11:59:00.5Z"})
    fake = FakeKql(rows)
    c, cursor, seen = sentinel(fake, limit=2), None, []
    for _ in range(10):
        page = await c.fetch_page(cursor)
        seen += [r["SystemAlertId"] for r in page.records]
        if page.window_complete:
            break
        cursor = page.next_cursor
    assert seen == ["a1", "a2", "a3", "a4", "a5", "b1"]          # nothing skipped or repeated
    assert all("+ 1" not in q and "1us" not in q for q in fake.queries)
    assert 'SystemAlertId > "a2"' in fake.queries[1]               # composite seek
    assert t in fake.queries[1]                                    # exact 100 ns key kept


async def test_sentinel_window_is_frozen_across_pages():
    rows = [{"SystemAlertId": f"a{i}", "TimeGenerated": "2026-10-28T11:59:00Z"}
            for i in range(4)]
    fake = FakeKql(rows)
    c = sentinel(fake, limit=2)
    first = await c.fetch_page(None)
    c._clock = lambda: NOW + timedelta(minutes=30)               # time passes mid-scan
    await c.fetch_page(first.next_cursor)
    spans = [re.findall(r"datetime\(([^)]+)\)", q)[:2] for q in fake.queries]
    assert spans[0] == spans[1]


async def test_sentinel_partial_result_fails_closed_without_a_cursor():
    c = sentinel(FakeKql([], partial=True))
    with pytest.raises(ConnectorError) as exc:
        await c.fetch_page(None)
    assert exc.value.code == "PARTIAL_RESPONSE" and exc.value.status == "degraded"


async def test_sentinel_unkeyed_or_non_advancing_pages_fail_closed():
    c = sentinel(FakeKql([{"SystemAlertId": None, "TimeGenerated": "2026-10-28T11:00:00Z"}]))
    with pytest.raises(ConnectorError) as exc:
        await c.fetch_page(None)
    assert exc.value.code == "UNPARSEABLE_ROW"

    class Stuck(FakeKql):
        def handler(self, request):                              # ignores the seek
            return httpx.Response(200, json={"tables": [{
                "columns": [{"name": "SystemAlertId"}, {"name": "TimeGenerated"}],
                "rows": [["a1", "2026-10-28T11:00:00Z"]]}]})
    c = sentinel(Stuck([]), limit=1)
    first = await c.fetch_page(None)
    with pytest.raises(ConnectorError) as exc:
        await c.fetch_page(first.next_cursor)
    assert exc.value.code == "CURSOR_NON_ADVANCING"


async def test_sentinel_cursor_from_another_query_blocks_instead_of_resetting():
    fake = FakeKql([])
    c = sentinel(fake)
    foreign = {"cursor_version": 2, "fingerprint": "someone-else", "continue": True,
               "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-01T01:00:00Z",
               "last_time": "2026-10-01T00:30:00Z", "last_source_id": "zz"}
    with pytest.raises(ConnectorError) as exc:
        await c.fetch_page(foreign)
    assert exc.value.code == "CURSOR_CONFIG_CHANGED" and exc.value.status == "degraded"
    assert fake.queries == []                                    # no query was even sent


async def test_sentinel_legacy_cursor_still_migrates_by_overlap():
    fake = FakeKql([])
    c = sentinel(fake)
    legacy = {"continue": True, "page_start": "2026-10-28T10:00:00Z",
              "window_end": "2026-10-28T11:00:00Z"}
    page = await c.fetch_page(legacy)
    assert "CURSOR_MIGRATED_FROM_V1" in page.source_warnings
    start = re.findall(r"datetime\(([^)]+)\)", fake.queries[-1])[0]
    assert start.startswith("2026-10-28T09:55")                  # page_start - 300 s overlap


# --------------------------------------------------------------------------
# Splunk: snapshot job, offsets, replay
# --------------------------------------------------------------------------

def splunk(vendors, limit=500, **options):
    return SplunkConnector(
        conn("splunk", {"management_url": "https://splunk.example.invalid:8089",
                        "indexes": ["notable"], "max_results": limit, **options}),
        "tok", transport=httpx.MockTransport(vendors.handler), clock=lambda: NOW)


def rows(n, indextime="1761609700"):
    return [{"_cd": f"1:{i}", "index": "notable", "_indextime": indextime,
             "rule_name": "r"} for i in range(n)]


async def test_splunk_equal_indextime_records_are_all_drained_and_job_released():
    vendors = MockVendors()
    vendors.splunk_rows = rows(1200)                 # one _indextime, 3 pages of 500
    c, cursor, got, pages = splunk(vendors), None, [], []
    for _ in range(10):
        page = await c.fetch_page(cursor)
        got += [r["_cd"] for r in page.records]
        pages.append(page)
        if page.window_complete:
            break
        cursor = page.next_cursor
    assert len(got) == 1200 and len(set(got)) == 1200
    assert [p.next_cursor.get("offset") for p in pages[:2]] == [500, 1000]
    assert vendors.splunk_jobs_created == 1                       # one snapshot, not one per page
    assert vendors.splunk_jobs == {}                              # released when drained
    assert not any(d for d in vendors.requests
                   if d.method == "DELETE" and d is not vendors.requests[-1])


async def test_splunk_expired_job_replays_the_same_window_from_zero():
    vendors = MockVendors()
    vendors.splunk_rows = rows(30)
    c = splunk(vendors, limit=10)
    first = await c.fetch_page(None)
    assert first.next_cursor["offset"] == 10
    vendors.splunk_jobs.clear()                                   # job expired / Splunk restarted
    again = await c.fetch_page(first.next_cursor)
    assert "SNAPSHOT_EXPIRED_REPLAYING" in again.source_warnings
    assert again.next_cursor["job_sid"] != first.next_cursor["job_sid"]
    assert again.next_cursor["offset"] == 10                      # restarted at 0, read 10
    assert [r["_cd"] for r in again.records] == [f"1:{i}" for i in range(10)]
    assert again.next_cursor["window_start"] == first.next_cursor["window_start"]
    assert again.next_cursor["window_end"] == first.next_cursor["window_end"]


async def test_splunk_changed_search_settings_block_and_keep_the_old_snapshot():
    vendors = MockVendors()
    vendors.splunk_rows = rows(30)
    first = await splunk(vendors, limit=10).fetch_page(None)
    other = splunk(vendors, limit=10, indexes=["notable", "other"])
    with pytest.raises(ConnectorError) as exc:
        await other.fetch_page(first.next_cursor)
    assert exc.value.code == "CURSOR_CONFIG_CHANGED"
    sid = first.next_cursor["job_sid"]
    assert sid in vendors.splunk_jobs                             # old checkpoint untouched
    assert not any(r.method == "DELETE" for r in vendors.requests)


async def test_splunk_unidentifiable_or_malformed_results_fail_closed():
    vendors = MockVendors()
    vendors.splunk_rows = [{"index": "notable", "rule_name": "no id at all"}]
    with pytest.raises(ConnectorError) as exc:
        await splunk(vendors).fetch_page(None)
    assert exc.value.code == "UNPARSEABLE_ROW"

    def bad(request):
        if request.url.path.endswith("/results"):
            return httpx.Response(200, text="{not json")
        return MockVendors().handler(request) if False else vendors2.handler(request)
    vendors2 = MockVendors()
    vendors2.splunk_rows = rows(3)
    c = SplunkConnector(conn("splunk", {"management_url": "https://splunk.example.invalid:8089",
                                        "indexes": ["notable"]}), "t",
                        transport=httpx.MockTransport(bad), clock=lambda: NOW)
    with pytest.raises(ConnectorError) as exc:
        await c.fetch_page(None)
    assert exc.value.code == "PARTIAL_RESPONSE"


async def test_splunk_export_mode_is_retired_to_the_job_path_and_reports_it():
    vendors = MockVendors()
    vendors.splunk_rows = rows(2)
    page = await splunk(vendors, search_mode="export").fetch_page(None)
    assert "EXPORT_MODE_RETIRED" in page.source_warnings
    assert not any(r.url.path.endswith("/jobs/export") for r in vendors.requests)


async def test_splunk_event_time_floor_is_explicit_and_can_be_disabled():
    vendors = MockVendors()
    vendors.splunk_rows = rows(1)
    page = await splunk(vendors).fetch_page(None)
    assert "EVENT_TIME_FILTER_ACTIVE" in page.source_warnings
    page = await splunk(vendors, max_event_age_seconds=0).fetch_page(None)
    assert "EVENT_TIME_FILTER_ACTIVE" not in page.source_warnings
    form = dict(httpx.QueryParams([r for r in vendors.requests
                                   if r.method == "POST"][-1].content.decode()))
    assert form["earliest_time"] == "0"


# --------------------------------------------------------------------------
# Durable ledger -> correlation hand-off
# --------------------------------------------------------------------------

def inactive(src):
    return {**src, "enabled": False}


async def frozen(tmp_path, sources, vendors, **extra):
    """A runtime whose background correlation worker is stopped, so a test can
    observe queue states deterministically and drive processing by hand."""
    rt = await build_runtime(tmp_path, sources, vendors, **extra)
    rt._work_task.cancel()
    await asyncio.gather(rt._work_task, return_exceptions=True)
    return rt


async def manual_poll(rt, connection_id):
    worker = rt.supervisor.workers[connection_id]
    connector = rt._make_connector(worker.conn)
    await connector.open()
    try:
        return await worker._poll_once(connector)
    finally:
        await connector.close()


async def test_cursor_advances_while_correlation_is_down_and_nothing_is_lost(tmp_path):
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], MockVendors())
    try:
        real = rt.pipeline.process
        def boom(record):
            raise RuntimeError("correlator unavailable")
        rt.pipeline.process = boom
        await manual_poll(rt, "sentinel-main")
        cursor = await rt.db.fetchone("SELECT * FROM source_cursors")
        assert cursor is not None                                  # acquisition moved on
        await rt._process_batch()
        item = await rt.db.fetchone("SELECT * FROM ingest_work_items")
        assert item["state"] == "failed_retryable" and item["attempts"] == 1
        obs = await rt.db.fetchone("SELECT state FROM processed_observations")
        assert obs["state"] == "queued_for_correlation"            # never "processed" early
        assert rt.pipeline.correlator.clusters() == []

        rt.pipeline.process = real                                 # correlator back
        await rt.db.execute("UPDATE ingest_work_items SET next_attempt_at='2000-01-01T00:00:00Z'")
        await rt.drain_work()
        rt.pipeline.evaluate(flush=True)
        assert sum(c.alert_count for c in rt.pipeline.correlator.clusters()) == 1
        assert (await rt.db.fetchone("SELECT state FROM processed_observations"))["state"] == "correlated"
        await rt.drain_work()                                      # nothing left, nothing doubled
        rt.pipeline.evaluate(flush=True)
        assert sum(c.alert_count for c in rt.pipeline.correlator.clusters()) == 1
    finally:
        await rt.stop()


async def test_items_claimed_by_a_dead_process_are_recovered_without_duplication(tmp_path):
    vendors = MockVendors()
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], vendors)
    await manual_poll(rt, "sentinel-main")
    claimed = await rt.work.claim_batch(10)
    assert len(claimed) == 1                                       # claimed, never acknowledged
    await rt.stop()                                                # "crash"

    rt2 = await build_runtime(tmp_path, [inactive(SENTINEL_SRC)], vendors)
    try:
        await rt2.drain_work()
        rt2.pipeline.evaluate(flush=True)
        assert sum(c.alert_count for c in rt2.pipeline.correlator.clusters()) == 1
        states = await rt2.db.fetchall("SELECT state FROM ingest_work_items")
        assert [s["state"] for s in states] == ["processed"]
    finally:
        await rt2.stop()


async def test_queued_older_revision_keeps_its_own_payload_and_newer_is_a_revision(tmp_path):
    vendors = MockVendors()
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], vendors)
    try:
        await manual_poll(rt, "sentinel-main")                     # revision 1 queued
        vendors.sentinel_rows = [dict(vendors.sentinel_rows[0], Description="CHANGED",
                                      TimeGenerated="2026-10-28T00:09:00Z")]
        await manual_poll(rt, "sentinel-main")                     # revision 2 arrives
        items = await rt.db.fetchall(
            "SELECT revision, operation, state FROM ingest_work_items ORDER BY revision")
        assert [(i["revision"], i["operation"], i["state"]) for i in items] == [
            (1, "correlate", "pending"), (2, "revise", "pending")]
        first, second = await rt.work.claim_batch(10)
        _, original = rt.work.open_item(first)
        _, changed = rt.work.open_item(second)
        assert (first["revision"], second["revision"]) == (1, 2)
        assert original["Description"] == "encoded command"     # revision 1 kept its own payload
        assert changed["Description"] == "CHANGED"
        await rt.work.ack(first)
        await rt.work.ack(second)
        assert (await rt.db.fetchone("SELECT COUNT(*) AS n FROM source_event_revisions"))["n"] == 2
    finally:
        await rt.stop()


async def test_retention_keeps_payloads_that_unresolved_work_still_needs(tmp_path):
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], MockVendors())
    try:
        await manual_poll(rt, "sentinel-main")
        await rt.db.execute("UPDATE source_events SET observed_at='2000-01-01T00:00:00.000Z'")
        await rt.db.execute("UPDATE source_event_revisions SET committed_at='2000-01-01T00:00:00.000Z'")
        await rt.ledger.purge_raw_older_than(30)
        row = await rt.db.fetchone("SELECT raw_enc FROM source_events")
        assert row["raw_enc"] is not None                          # work still pending
        await rt.drain_work()
        await rt.ledger.purge_raw_older_than(30)
        assert (await rt.db.fetchone("SELECT raw_enc FROM source_events"))["raw_enc"] is None
    finally:
        await rt.stop()


async def test_migration_2_snapshots_revisions_already_stored_by_v1(tmp_path, monkeypatch):
    import engine.store.database as dbmod
    from engine.store import Database
    from engine.store.migrations import MIGRATIONS

    monkeypatch.setattr(dbmod, "MIGRATIONS", MIGRATIONS[:1])
    db = await Database(tmp_path / "old.sqlite3").open()
    await db.execute(
        "INSERT INTO source_events (canonical_event_id, scope_id, connection_id,"
        " provider, record_kind, source_event_id, observed_at, raw_sha256, raw_enc,"
        " revision, envelope_json) VALUES ('c1','s','k','sentinel','alert','e',"
        "'t','h',x'00',3,'{}')")
    await db.close()
    monkeypatch.setattr(dbmod, "MIGRATIONS", MIGRATIONS)
    db = await Database(tmp_path / "old.sqlite3").open()
    try:
        rows_ = await db.fetchall("SELECT canonical_event_id, revision FROM source_event_revisions")
        assert rows_ == [{"canonical_event_id": "c1", "revision": 3}]   # additive, no data lost
        assert (await db.fetchone("SELECT COUNT(*) AS n FROM source_events"))["n"] == 1
    finally:
        await db.close()


# --------------------------------------------------------------------------
# Response settlement and recovery
# --------------------------------------------------------------------------

async def test_claim_moves_action_and_outbox_together_and_cancel_wins(tmp_path):
    t = FakeTransport()
    rt = await response_runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        action, item = await rt.dispatcher._claim()
        assert action.state == ActionState.DISPATCHING
        ob = await rt.db.fetchone("SELECT delivery_state FROM outbox")
        assert ob["delivery_state"] == "dispatching"
        assert (await rt.actions.get(a.action_id)).state == ActionState.DISPATCHING

        b = await propose(rt, payload={"message": "second", "severity": "low"}, cluster="C2")
        await rt.actions.approve("bob", "responder", b.action_id)
        await rt.actions.cancel("ann", "analyst", b.action_id)
        assert await rt.dispatcher._claim() is None                # cancelled: nothing to send
        assert t.sent == []
    finally:
        await rt.stop()


async def test_settlement_updates_action_outbox_and_audit_together(tmp_path):
    t = FakeTransport()
    rt = await response_runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        await rt.dispatcher.run_once()
        ob = await rt.db.fetchone("SELECT delivery_state FROM outbox")
        assert ob["delivery_state"] == "delivered"
        assert (await rt.actions.get(a.action_id)).state == ActionState.ACKNOWLEDGED
        trail = {e["action"] for e in await rt.audit.list(target=a.action_id)}
        assert {"action.dispatching", "action.acknowledged"} <= trail
        assert (await rt.audit.verify())["valid"]
    finally:
        await rt.stop()


@pytest.mark.parametrize("final,label", [
    ("acknowledged", "delivered"), ("failed_without_effect", "failed"),
    ("cancelled", "cancelled"), ("expired", "expired"),
])
async def test_recovery_repairs_a_terminal_action_with_a_stale_outbox_row(tmp_path, final, label):
    t = FakeTransport()
    rt = await response_runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        await rt.dispatcher._claim()
        # the old two-commit window: action already final, outbox still 'dispatching'
        await rt.db.execute("UPDATE response_actions SET state=? WHERE action_id=?",
                            (final, a.action_id))
        assert await rt.dispatcher.recover() == 0
        assert (await rt.db.fetchone("SELECT delivery_state FROM outbox"))["delivery_state"] == label
        assert (await rt.actions.get(a.action_id)).state.value == final   # action untouched
        assert await rt.dispatcher.run_once() is False and t.sent == []   # and never resent
    finally:
        await rt.stop()


async def test_recovery_flags_inconsistent_rows_instead_of_sending(tmp_path):
    t = FakeTransport()
    rt = await response_runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        await rt.db.execute("UPDATE response_actions SET state='approval_required'")
        assert await rt.dispatcher.recover() == 1
        assert (await rt.db.fetchone("SELECT delivery_state FROM outbox"))["delivery_state"] == "inconsistent"
        assert await rt.dispatcher.run_once() is False and t.sent == []
    finally:
        await rt.stop()


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------

class FakeConnector:
    streams = ("alerts",)

    def __init__(self, page):
        self.page = page

    async def fetch_page(self, cursor, stream="alerts"):
        return self.page

    def identify(self, record, stream):
        raise AssertionError("no records")


async def test_health_reports_watermark_lag_counters_and_never_fakes_zero_lag(tmp_path):
    rt = await build_runtime(tmp_path, [inactive(SENTINEL_SRC)], MockVendors())
    try:
        worker = rt.supervisor.workers["sentinel-main"]
        assert worker.health.lag_seconds is None                   # nothing committed yet
        old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        page = PageResult([], {"window_end": old, "watermark": old}, True, [])
        await worker._poll_once(FakeConnector(page))
        h = worker.health.view()
        assert h["status"] == "healthy" and h["pages_drained"] == 1
        assert 3500 < h["lag_seconds"] < 3700                      # from the watermark, not 0.0
        assert h["streams"]["alerts"]["watermark"] == old
        assert h["streams"]["alerts"]["window_complete"] is True

        page = PageResult([], {"window_end": old}, True, ["SNAPSHOT_EXPIRED_REPLAYING"])
        await worker._poll_once(FakeConnector(page))
        assert worker.health.status == "degraded"                  # known-incomplete is not "healthy"
        assert "SNAPSHOT_EXPIRED_REPLAYING" in worker.health.warnings
    finally:
        await rt.stop()


async def test_health_counts_new_duplicate_and_unchanged_records(tmp_path):
    vendors = MockVendors()
    rt = await build_runtime(tmp_path, [inactive(SENTINEL_SRC)], vendors)
    try:
        await manual_poll(rt, "sentinel-main")
        await manual_poll(rt, "sentinel-main")                     # same payload again
        h = rt.supervisor.workers["sentinel-main"].health
        assert (h.records_received, h.records_new, h.records_unchanged) == (2, 1, 1)
    finally:
        await rt.stop()


async def test_slow_correlation_marks_a_healthy_source_backlogged(tmp_path):
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], MockVendors())
    try:
        await manual_poll(rt, "sentinel-main")
        await rt.db.execute("UPDATE ingest_work_items SET created_at='2000-01-01T00:00:00.000Z',"
                            " state='failed_retryable', next_attempt_at='2999-01-01T00:00:00.000Z'")
        c, paused = (await rt.repo.list())[0]
        view = await rt.connection_view(c, paused)
        assert view["health"]["status"] == "backlogged"
        assert "INGESTION_BACKLOG" in view["health"]["warnings"]
        assert view["health"]["correlation"]["pending_correlation_items"] == 1
        assert (await rt.metrics())["correlation_queue"]["pending_correlation_items"] == 1
    finally:
        await rt.stop()


# --------------------------------------------------------------------------
# Bounded backfill
# --------------------------------------------------------------------------

async def test_backfill_needs_a_paused_source_is_bounded_and_leaves_the_live_cursor_alone(tmp_path):
    app, rt = await make_api(tmp_path)
    try:
        async with client(app) as c:
            now = datetime.now(timezone.utc)
            body = {"stream": "alerts", "start": (now - timedelta(hours=2)).isoformat(),
                    "end": (now - timedelta(hours=1)).isoformat(), "reason": "tie-group repair"}
            url = "/api/v2/connections/sentinel-main/backfill"
            assert (await c.post(url, json=body, headers=CSRF)).status_code == 409   # not paused
            await c.post("/api/v2/connections/sentinel-main/pause", headers=CSRF)
            before = await rt.db.fetchone(
                "SELECT cursor_json, committed_at FROM source_cursors WHERE connection_id='sentinel-main'")
            too_long = dict(body, start=(now - timedelta(days=9)).isoformat())
            assert (await c.post(url, json=too_long, headers=CSRF)).status_code == 422
            future = dict(body, end=(now + timedelta(hours=1)).isoformat())
            assert (await c.post(url, json=future, headers=CSRF)).status_code == 422
            naive = dict(body, start="2026-10-28T00:00:00", end="2026-10-28T01:00:00")
            assert (await c.post(url, json=naive, headers=CSRF)).status_code == 422
            ok = await c.post(url, json=body, headers=CSRF)
            assert ok.status_code == 202
            for _ in range(100):
                status = (await c.get(url)).json()
                if status["state"] != "running":
                    break
                await asyncio.sleep(0.05)
            assert status["state"] == "complete" and status["pages"] >= 1
            after = await rt.db.fetchone(
                "SELECT cursor_json, committed_at FROM source_cursors WHERE connection_id='sentinel-main'")
            assert after == before                                  # live checkpoint untouched
            trail = [e["action"] for e in await rt.audit.list(target="sentinel-main")]
            assert "connection.backfill" in trail
        async with client(app, host="203.0.113.7") as c:           # administrators only
            tok = await _token(rt, "ann", "analyst")
            r = await c.post(url, json=body, headers=tok)
            assert r.status_code == 403
    finally:
        await rt.stop()


async def _token(rt, user, role):
    from tests.test_api_v2 import token_for
    return await token_for(rt, user, role)


# --------------------------------------------------------------------------
# Operating decisions: bad rows, config changes, the Splunk floor, Elastic
# --------------------------------------------------------------------------

async def wait_status(rt, connection_id, wanted, seconds=6.0):
    from tests.v2_helpers import wait_for

    async def reached():
        return rt.supervisor.health().get(connection_id, {}).get("status") == wanted
    return await wait_for(reached, seconds)


async def test_a_bad_splunk_row_degrades_only_that_source_and_an_admin_can_move_it_on(tmp_path):
    vendors = MockVendors()
    vendors.splunk_rows = [*rows(1), {"index": "notable", "rule_name": "no id"}, *[
        {**r, "_cd": f"9:{i}"} for i, r in enumerate(rows(1))]]
    app, rt = await make_api(tmp_path, sources=[SPLUNK_SRC, SENTINEL_SRC], vendors=vendors)
    try:
        assert await wait_status(rt, "splunk-es", "degraded")
        assert await wait_status(rt, "sentinel-main", "healthy")       # others keep working
        err = await rt.db.fetchone(
            "SELECT * FROM source_errors WHERE connection_id='splunk-es' ORDER BY error_id")
        assert err["code"] == "UNPARSEABLE_ROW" and err["stream_name"] == "notables"
        assert len(err["ref"]) == 32 and "no id" not in err["detail"]   # a hash, never the row
        assert (await rt.db.fetchone(
            "SELECT COUNT(*) AS n FROM source_events WHERE connection_id='splunk-es'"))["n"] == 0
        assert await rt.db.fetchone(
            "SELECT 1 AS x FROM source_cursors WHERE connection_id='splunk-es'") is None

        async with client(app) as c:
            url = "/api/v2/connections/splunk-es"
            short = await c.post(f"{url}/skip-bad-rows", json={"reason": "no"}, headers=CSRF)
            assert short.status_code == 422                              # a reason is required
            assert (await c.post(f"{url}/retry", headers=CSRF)).status_code == 200
            ok = await c.post(f"{url}/skip-bad-rows", headers=CSRF,
                              json={"reason": "vendor sent a malformed notable"})
            assert ok.status_code == 200
        from tests.v2_helpers import wait_for

        async def moved_on():
            row = await rt.db.fetchone(
                "SELECT COUNT(*) AS n FROM source_events WHERE connection_id='splunk-es'")
            return row["n"] == 2
        assert await wait_for(moved_on)                                  # good rows stored
        health = rt.supervisor.workers["splunk-es"].health
        assert health.records_quarantined == 1
        assert rt.supervisor.workers["splunk-es"].tolerate_bad_rows is False   # strict again
        trail = {e["action"] for e in await rt.audit.list(target="splunk-es")}
        assert {"connection.retry", "connection.skip_bad_rows"} <= trail
    finally:
        await rt.stop()


async def test_a_cursor_from_a_different_query_is_kept_until_an_admin_confirms(tmp_path):
    vendors = MockVendors()
    app, rt = await make_api(tmp_path, sources=[inactive(SENTINEL_SRC)], vendors=vendors)
    try:
        old = {"cursor_version": 2, "fingerprint": "an-older-workspace", "continue": False,
               "window_end": "2026-10-20T00:00:00Z", "watermark": "2026-10-20T00:00:00Z"}
        await rt.db.execute(
            "INSERT INTO source_cursors VALUES ('sentinel-main','alerts',?,1,'t')",
            (json.dumps(old),))
        with pytest.raises(ConnectorError) as exc:
            await manual_poll(rt, "sentinel-main")
        assert exc.value.code == "CURSOR_CONFIG_CHANGED"
        kept = await rt.db.fetchone("SELECT cursor_json FROM source_cursors")
        assert json.loads(kept["cursor_json"]) == old                  # nothing was overwritten

        async with client(app) as c:
            url = "/api/v2/connections/sentinel-main/cursor/confirm"
            body = {"stream": "alerts", "reason": "moved to the new workspace"}
            assert (await c.post(url, json=body, headers=CSRF)).status_code == 409   # not paused
            await c.post("/api/v2/connections/sentinel-main/pause", headers=CSRF)
            assert (await c.post(url, json={"stream": "alerts", "reason": "x"},
                                 headers=CSRF)).status_code == 422
            assert (await c.post(url, json=dict(body, start_from="2025-01-01T00:00:00Z"),
                                 headers=CSRF)).status_code == 422   # too far back: use backfill
            ok = await c.post(url, json=body, headers=CSRF)
            assert ok.status_code == 200
            assert (await c.post(url, json=body, headers=CSRF)).status_code == 409   # already matches
        history = await rt.db.fetchone("SELECT * FROM source_cursor_history")
        assert json.loads(history["cursor_json"]) == old and history["reason"] == body["reason"]
        entry = [e for e in await rt.audit.list(target="sentinel-main")
                 if e["action"] == "connection.cursor_confirmed"][0]
        assert entry["detail"]["old_cursor"] == old and entry["actor"] == "local-admin"
        assert await manual_poll(rt, "sentinel-main") is True            # scanning again
    finally:
        await rt.stop()


async def test_splunk_floor_defaults_to_a_day_and_zero_means_no_event_time_filter():
    from engine.connectors._common import backfill_cursor

    vendors = MockVendors()
    vendors.splunk_rows = rows(1)
    default = await splunk(vendors).fetch_page(None)
    assert "EVENT_TIME_FILTER_ACTIVE" in default.source_warnings
    start, end = NOW - timedelta(hours=3), NOW - timedelta(hours=2)
    page = await splunk(vendors).fetch_page(backfill_cursor(start, end, event_time_floor=0))
    assert "FULL_INDEX_TIME_COLLECTION" in page.source_warnings
    forms = [dict(httpx.QueryParams(r.content.decode())) for r in vendors.requests
             if r.method == "POST"]
    assert forms[0]["earliest_time"] == str(int(NOW.timestamp()) - 300 - 86400) \
        or int(forms[0]["earliest_time"]) < int(forms[1]["earliest_time"]) + 1
    assert forms[1]["earliest_time"] == "0"                              # no floor for this backfill


async def test_the_card_shows_the_active_splunk_floor(tmp_path):
    rt = await build_runtime(tmp_path, [inactive({**SPLUNK_SRC, "options": {
        **SPLUNK_SRC["options"], "max_event_age_seconds": 0}})], MockVendors())
    try:
        c, paused = (await rt.repo.list())[0]
        view = await rt.connection_view(c, paused)
        assert view["settings"] == {"event_time_floor_seconds": 0,
                                    "event_time_filter": "none (full index-time collection)"}
    finally:
        await rt.stop()


class FakeElastic:
    def __init__(self):
        self.calls = []

    async def fetch_batch(self, since_ms, until_ms):
        self.calls.append((since_ms, until_ms))
        yield {"_id": "1", "sort": [since_ms + 5], "_source": {"@timestamp": "2026-10-28T00:00:00Z"}}

    async def aclose(self):
        pass


async def test_managed_elastic_connections_support_a_bounded_backfill():
    from engine.connectors._common import backfill_cursor
    from engine.connectors.elastic import ElasticSourceConnector

    fake = FakeElastic()
    c = ElasticSourceConnector(
        conn("elastic", {"host": "https://es.example.invalid:9200"}), "key",
        connector=fake, clock=lambda: 1_900_000_000)
    start, end = NOW - timedelta(hours=3), NOW - timedelta(hours=2)
    page = await c.fetch_page(backfill_cursor(start, end))
    assert fake.calls == [(int(start.timestamp() * 1000), int(end.timestamp() * 1000))]
    assert page.window_complete and len(page.records) == 1


async def test_the_legacy_elastic_path_is_left_alone_and_cannot_be_backfilled(tmp_path):
    import httpx

    from engine.ai.service import TriageService
    from engine.api.server import create_app
    from engine.config import config_from_dict
    from engine.pipeline import Pipeline
    from engine.runtime import V2Runtime
    from engine.secure.store import SecretStore

    cfg = config_from_dict({"siem": {"host": "https://es.example.invalid:9200"}})

    async def probe():
        return {"status": "healthy"}
    rt = V2Runtime(cfg, Pipeline(cfg), TriageService(cfg, ai_enabled=False),
                   SecretStore(tmp_path / "h"), tmp_path / "h", include_legacy=True,
                   legacy_health=probe,
                   http_transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    await rt.start()
    try:
        app = create_app(cfg, rt.service, pipeline=rt.pipeline)
        app.state.v2 = rt
        async with client(app) as c:
            now = datetime.now(timezone.utc)
            r = await c.post("/api/v2/connections/elastic-default/backfill", headers=CSRF, json={
                "stream": "alerts", "start": (now - timedelta(hours=2)).isoformat(),
                "end": (now - timedelta(hours=1)).isoformat()})
            assert r.status_code == 409 and "legacy" in r.json()["detail"]
        # the legacy poller keeps its own state.json cursor; the v2 store never holds one
        assert await rt.db.fetchone("SELECT 1 AS x FROM source_cursors") is None
    finally:
        await rt.stop()
