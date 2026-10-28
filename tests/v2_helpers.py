"""Shared builders for the v2 tests: mocked vendor APIs + a live runtime."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx

from engine.config import config_from_dict
from engine.pipeline import Pipeline
from engine.runtime import V2Runtime
from engine.secure.store import SecretStore, auth_profile_name
from engine.ai.service import TriageService

WORKSPACE = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"

SENTINEL_ROW = {
    "SystemAlertId": "sent-alert-1", "VendorOriginalId": "sent-alert-1",
    "AlertName": "Suspicious PowerShell", "AlertSeverity": "High",
    "StartTime": "2026-10-28T00:00:00Z", "TimeGenerated": "2026-10-28T00:00:05Z",
    "ProductName": "Azure Sentinel", "Description": "encoded command",
    "Tactics": "Execution", "Techniques": '["T1059.001"]',
    "Entities": json.dumps([
        {"Type": "host", "HostName": "WS01", "DnsDomain": "corp.local"},
        {"Type": "account", "Name": "alice", "NTDomain": "CORP"},
    ]),
    "AlertLink": "https://portal.azure.com/#alert/sent-alert-1",
}


def graph_alert(alert_id="gr-1", provider_id="def-1", service="microsoftDefenderForEndpoint",
                host="ws01.corp.local", when="2026-10-28T00:10:00Z", incident="inc-1"):
    return {
        "id": alert_id, "providerAlertId": provider_id, "incidentId": incident,
        "tenantId": TENANT, "serviceSource": service, "title": "Credential dumping",
        "severity": "high", "category": "CredentialAccess",
        "mitreTechniques": ["T1003"], "createdDateTime": when,
        "firstActivityDateTime": when, "lastUpdateDateTime": when,
        "alertWebUrl": f"https://security.microsoft.com/alerts/{alert_id}",
        "incidentWebUrl": f"https://security.microsoft.com/incidents/{incident}",
        "evidence": [
            {"@odata.type": "#microsoft.graph.security.deviceEvidence",
             "deviceDnsName": "WS01", "mdeDeviceId": "mde-1"},
            {"@odata.type": "#microsoft.graph.security.userEvidence",
             "userAccount": {"accountName": "alice",
                             "userPrincipalName": "alice@corp.com"}},
        ],
    }


SIGNIN = {
    "id": "signin-1", "createdDateTime": "2026-10-28T00:05:00Z",
    "userPrincipalName": "alice@corp.com", "userId": "u-1", "ipAddress": "203.0.113.9",
    "appDisplayName": "Office 365", "status": {"errorCode": 0},
    "conditionalAccessStatus": "success", "correlationId": "c-1",
}


class MockVendors:
    """Routes the vendor endpoints the connectors talk to."""

    def __init__(self) -> None:
        self.sentinel_rows: list[dict] = [SENTINEL_ROW]
        self.graph_alerts: list[dict] = [graph_alert()]
        self.graph_incidents: list[dict] = [{
            "id": "inc-1", "displayName": "Multi-stage incident", "status": "active",
            "createdDateTime": "2026-10-28T00:10:00Z",
            "incidentWebUrl": "https://security.microsoft.com/incidents/inc-1"}]
        self.signins: list[dict] = [SIGNIN]
        self.audits: list[dict] = []
        self.splunk_rows: list[dict] = []
        self.splunk_jobs: dict[str, list[dict]] = {}
        self.splunk_jobs_created = 0
        self.requests: list[httpx.Request] = []
        self.fail_next: dict[str, int] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url, host, path = str(request.url), request.url.host, request.url.path
        for key in list(self.fail_next):
            if key in url and self.fail_next[key] > 0:
                self.fail_next[key] -= 1
                return httpx.Response(429, headers={"Retry-After": "0"}, text="slow down")
        if host == "api.loganalytics.azure.com":
            cols = sorted({k for r in self.sentinel_rows for k in r})
            return httpx.Response(200, json={"tables": [{
                "name": "PrimaryResult",
                "columns": [{"name": c, "type": "string"} for c in cols],
                "rows": [[r.get(c) for c in cols] for r in self.sentinel_rows]}]})
        if host == "graph.microsoft.com":
            if path.endswith("/security/alerts_v2"):
                return httpx.Response(200, json={"value": self.graph_alerts})
            if path.endswith("/security/incidents"):
                return httpx.Response(200, json={"value": self.graph_incidents})
            if path.endswith("/auditLogs/signIns"):
                return httpx.Response(200, json={"value": self.signins})
            if path.endswith("/auditLogs/directoryAudits"):
                return httpx.Response(200, json={"value": self.audits})
        if host == "splunk.example.invalid":
            if path.endswith("/server/info"):
                return httpx.Response(200, json={"entry": []})
            if path.endswith("/search/v2/jobs") and request.method == "POST":
                self.splunk_jobs_created += 1
                sid = f"sid{self.splunk_jobs_created}"
                self.splunk_jobs[sid] = list(self.splunk_rows)
                return httpx.Response(201, json={"sid": sid})
            if "/search/v2/jobs/" in path:
                sid = path.rsplit("/search/v2/jobs/", 1)[1].split("/")[0]
                if request.method == "DELETE":
                    self.splunk_jobs.pop(sid, None)
                    return httpx.Response(200, json={})
                if sid not in self.splunk_jobs:
                    return httpx.Response(404, text="unknown sid")
                rows = self.splunk_jobs[sid]
                if path.endswith("/results"):
                    off = int(request.url.params.get("offset", 0))
                    cnt = int(request.url.params.get("count", 100))
                    return httpx.Response(200, json={"results": rows[off:off + cnt]})
                return httpx.Response(200, json={"entry": [{"content": {
                    "isDone": True, "isFailed": False, "resultCount": len(rows)}}]})
        return httpx.Response(404, text="unmocked " + url)


async def fake_token(_scope: str) -> str:
    return "test-token"


def make_config(sources: list[dict], **extra) -> object:
    return config_from_dict({
        "siem": {"type": "elastic", "host": ""},
        "correlation": {"window_minutes": 60, "risk": {"surface_threshold": 10}},
        "ai": {"provider": "local", "rag": {"backend": "lexical"}},
        "sources": sources, **extra,
    })


def source(cid, provider, options, **kw):
    return {"id": cid, "provider": provider, "enabled": True,
            "poll_seconds": 5, "auth_profile_id": f"{cid}-auth",
            "options": options, **kw}


SENTINEL_SRC = source("sentinel-main", "sentinel",
                      {"tenant_id": TENANT, "workspace_id": WORKSPACE})
DEFENDER_SRC = source("defender-xdr", "defender_xdr", {"tenant_id": TENANT})
ENTRA_SRC = source("entra-id", "entra_id", {"tenant_id": TENANT})
SPLUNK_SRC = source("splunk-es", "splunk", {
    "management_url": "https://splunk.example.invalid:8089",
    "indexes": ["notable"], "search_mode": "jobs"})


async def build_runtime(tmp_path: Path, sources: list[dict], vendors: MockVendors,
                        **extra) -> V2Runtime:
    config = make_config(sources, **extra)
    pipeline = Pipeline(config)
    service = TriageService(config, ai_enabled=False)
    secrets = SecretStore(tmp_path / "home")
    for s in sources:
        secrets.set(auth_profile_name(s["auth_profile_id"]),
                    "splunk-token" if s["provider"] == "splunk"
                    else json.dumps({"kind": "client_secret", "client_id": "c",
                                     "client_secret": "s"}))
    rt = V2Runtime(
        config, pipeline, service, secrets, tmp_path / "home",
        http_transport=httpx.MockTransport(vendors.handler),
        token_getter_factory=lambda _c: fake_token,
        evaluate_interval=3600)
    await rt.start()
    return rt


async def wait_for(predicate, timeout=5.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if await predicate():
            return True
        await asyncio.sleep(0.02)
    return False


async def settle(rt: V2Runtime, expected_events: int, timeout=6.0):
    async def enough():
        row = await rt.db.fetchone("SELECT COUNT(*) AS n FROM source_events")
        return row["n"] >= expected_events
    assert await wait_for(enough, timeout), "sources did not deliver in time"
    # Correlation is a durable, asynchronous stage now: let it catch up.
    await rt.drain_work()
