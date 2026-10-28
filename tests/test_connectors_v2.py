"""Connector transport safety: retries, classification, SSRF, query building."""

from __future__ import annotations

import json

import httpx
import pytest

from engine.connectors.auth.microsoft import (
    GRAPH_SCOPE, LOG_ANALYTICS_SCOPE, MicrosoftCredentialProvider,
)
from engine.connectors.base import (
    STATUS_LIMITED_BY_LICENSE, STATUS_PERMISSION_DENIED, STATUS_THROTTLED,
    ConfigurationError, ConnectorError, SourceConnection,
)
from engine.connectors.defender_xdr import DefenderXdrConnector
from engine.connectors.http import ConnectorHttp, scrub, validate_target
from engine.connectors.sentinel import KQL_TEMPLATES, SentinelConnector
from engine.connectors.splunk import SplunkConnector
from tests.v2_helpers import TENANT, WORKSPACE, MockVendors, fake_token


def conn(provider, options, **kw):
    return SourceConnection(connection_id=f"{provider}-1", provider=provider,
                            options=options, **kw)


# -- shared HTTP ---------------------------------------------------------------

async def test_retries_throttling_then_succeeds_honouring_retry_after():
    calls, slept = [], []

    def handler(request):
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, json={"ok": True})

    async def fake_sleep(s):
        slept.append(s)

    http = ConnectorHttp(transport=httpx.MockTransport(handler), sleep=fake_sleep)
    response = await http.request("GET", "https://example.invalid/x")
    assert response.json() == {"ok": True}
    assert slept == [7.0, 7.0]


async def test_permission_denied_is_not_retried_and_is_classified():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(403, text="Forbidden")

    http = ConnectorHttp(transport=httpx.MockTransport(handler))
    with pytest.raises(ConnectorError) as exc:
        await http.request("GET", "https://example.invalid/x")
    assert exc.value.status == STATUS_PERMISSION_DENIED
    assert len(calls) == 1


async def test_license_gap_is_distinct_from_permission_denied():
    http = ConnectorHttp(transport=httpx.MockTransport(
        lambda r: httpx.Response(403, text="Tenant is not licensed: requires Entra ID P1")))
    with pytest.raises(ConnectorError) as exc:
        await http.request("GET", "https://example.invalid/x")
    assert exc.value.status == STATUS_LIMITED_BY_LICENSE


async def test_persistent_throttle_surfaces_throttled_status():
    async def nosleep(_s):
        pass
    http = ConnectorHttp(transport=httpx.MockTransport(
        lambda r: httpx.Response(429)), sleep=nosleep)
    with pytest.raises(ConnectorError) as exc:
        await http.request("GET", "https://example.invalid/x")
    assert exc.value.status == STATUS_THROTTLED


def test_scrub_removes_tokens_from_text():
    text = scrub("Authorization: Bearer abc.def-123 sig=SECRET&x=1 client_secret=hunter2")
    assert "abc.def-123" not in text and "SECRET" not in text and "hunter2" not in text


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data",
    "https://169.254.169.254/",
    "https://127.0.0.1/",
    "http://example.com/",
    "ftp://example.com/",
])
def test_unsafe_targets_are_refused(url):
    with pytest.raises(ConfigurationError):
        validate_target(url)


def test_loopback_allowed_only_when_explicitly_local():
    assert validate_target("https://127.0.0.1:8089", allow_loopback=True)


# -- Microsoft token broker ---------------------------------------------------------

class FakeCredential:
    def __init__(self):
        self.calls = []

    async def get_token(self, scope):
        self.calls.append(scope)
        from types import SimpleNamespace
        return SimpleNamespace(token=f"tok-{scope}-{len(self.calls)}", expires_on=10_000)


async def test_tokens_are_per_audience_cached_and_refreshed():
    cred, now = FakeCredential(), [1000.0]
    broker = MicrosoftCredentialProvider(
        TENANT, {"kind": "x"}, profile_id="p", credential_factory=lambda *_: cred,
        clock=lambda: now[0])
    a = await broker.token(GRAPH_SCOPE)
    assert await broker.token(GRAPH_SCOPE) == a                 # cached
    b = await broker.token(LOG_ANALYTICS_SCOPE)
    assert b != a and len(cred.calls) == 2                      # separate audience
    now[0] = 9900.0                                             # inside refresh skew
    assert await broker.token(GRAPH_SCOPE) != a


async def test_token_failure_does_not_leak_detail():
    class Bad:
        async def get_token(self, scope):
            raise RuntimeError("AADSTS7000215: client_secret=hunter2 invalid")
    broker = MicrosoftCredentialProvider(
        TENANT, {"kind": "x"}, credential_factory=lambda *_: Bad())
    with pytest.raises(ConnectorError) as exc:
        await broker.token(GRAPH_SCOPE)
    assert "hunter2" not in str(exc.value)
    assert exc.value.status == STATUS_PERMISSION_DENIED


# -- Sentinel ------------------------------------------------------------------------

def sentinel(vendors=None, clock=None, **options):
    vendors = vendors or MockVendors()
    kwargs = {"clock": clock} if clock else {}
    return SentinelConnector(
        conn("sentinel", {"tenant_id": TENANT, "workspace_id": WORKSPACE, **options}),
        fake_token, transport=httpx.MockTransport(vendors.handler), **kwargs), vendors


async def test_sentinel_sends_templated_bounded_kql_with_log_analytics_token():
    c, vendors = sentinel()
    page = await c.fetch_page(None)
    req = vendors.requests[-1]
    body = json.loads(req.content)
    assert req.url.path == f"/v1/workspaces/{WORKSPACE}/query"
    assert req.headers["authorization"] == "Bearer test-token"
    assert body["query"].startswith("SecurityAlert | where TimeGenerated >= datetime(")
    assert "take 500" in body["query"] and "/" in body["timespan"]
    assert page.window_complete and page.records[0]["SystemAlertId"] == "sent-alert-1"


def test_sentinel_rejects_tables_without_a_reviewed_template_and_bad_guids():
    with pytest.raises(ConfigurationError):
        sentinel(enabled_tables=["SecurityAlert", "Heartbeat | take 1"])
    with pytest.raises(ConfigurationError):
        SentinelConnector(conn("sentinel", {"tenant_id": TENANT,
                          "workspace_id": "not-a-guid"}), fake_token)
    assert set(KQL_TEMPLATES) == {"SecurityAlert"}


async def test_sentinel_full_page_continues_instead_of_dropping_rows():
    vendors = MockVendors()
    vendors.sentinel_rows = [
        {"SystemAlertId": f"a{i}", "TimeGenerated": f"2026-10-28T00:00:0{i}Z"}
        for i in range(3)]
    from datetime import datetime, timezone
    c, _ = sentinel(vendors, clock=lambda: datetime(2026, 10, 28, 0, 5, tzinfo=timezone.utc),
                    max_rows=3)
    page = await c.fetch_page(None)
    # continuation is keyed on the last (time, id) pair, not a timestamp hop
    assert not page.window_complete and page.next_cursor["continue"] is True
    assert page.next_cursor["last_source_id"] == "a2"
    assert page.next_cursor["last_time"] == "2026-10-28T00:00:02Z"
    assert page.next_cursor["cursor_version"] == 2
    assert "PAGE_LIMIT_REACHED" in page.source_warnings


# -- Splunk ---------------------------------------------------------------------------

def splunk(vendors=None, **options):
    vendors = vendors or MockVendors()
    return SplunkConnector(
        conn("splunk", {"management_url": "https://splunk.example.invalid:8089",
                        "indexes": ["notable"], **options}),
        "tok", transport=httpx.MockTransport(vendors.handler)), vendors


async def test_splunk_uses_a_snapshot_job_with_bounded_index_time_window():
    vendors = MockVendors()
    vendors.splunk_rows = [{"_cd": "1:1", "index": "notable", "rule_name": "x"}]
    c, _ = splunk(vendors)
    page = await c.fetch_page(None)
    create = next(r for r in vendors.requests
                  if r.method == "POST" and r.url.path.endswith("/search/v2/jobs"))
    assert create.headers["authorization"] == "Bearer tok"
    form = dict(httpx.QueryParams(create.content.decode()))
    assert form["output_mode"] == "json"
    assert "index=notable" in form["search"] and "_index_earliest=" in form["search"]
    assert "| head" not in form["search"]            # no cap inside the SPL
    assert "sort 0 _indextime index _cd" in form["search"]
    assert page.records == vendors.splunk_rows and page.window_complete


@pytest.mark.parametrize("bad", ["main | delete", "a b", "x;y", "*) OR (index=secret"])
def test_splunk_rejects_injectable_index_names(bad):
    with pytest.raises(ConfigurationError):
        splunk(indexes=[bad])


def test_splunk_requires_https_and_blocks_metadata():
    for url in ("http://splunk.example.invalid:8089", "https://169.254.169.254:8089"):
        with pytest.raises(ConfigurationError):
            SplunkConnector(conn("splunk", {"management_url": url,
                            "indexes": ["notable"]}), "t")


# -- Graph ----------------------------------------------------------------------------

async def test_graph_filters_by_window_and_refuses_foreign_next_link():
    vendors = MockVendors()
    c = DefenderXdrConnector(conn("defender_xdr", {"tenant_id": TENANT}), fake_token,
                             transport=httpx.MockTransport(vendors.handler))
    await c.fetch_page(None, "alerts")
    params = vendors.requests[-1].url.params
    assert params["$filter"].startswith("lastUpdateDateTime ge ")
    assert params["$top"] == "500"
    with pytest.raises(ConnectorError) as exc:
        await c.fetch_page({"continue": True, "page_start": "2026-10-28T00:00:00Z",
                            "window_end": "2026-10-28T01:00:00Z",
                            "next_link": "https://evil.example/steal"}, "alerts")
    assert exc.value.code == "bad_next_link"
    assert all(r.url.host != "evil.example" for r in vendors.requests)


async def test_directory_audits_filter_on_activity_time():
    from engine.connectors.entra_id import EntraIdConnector
    vendors = MockVendors()
    c = EntraIdConnector(conn("entra_id", {"tenant_id": TENANT}), fake_token,
                         transport=httpx.MockTransport(vendors.handler))
    await c.fetch_page(None, "directory_audits")
    assert vendors.requests[-1].url.params["$filter"].startswith("activityDateTime ge ")
