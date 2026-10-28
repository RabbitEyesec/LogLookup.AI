"""Microsoft Sentinel via the Azure Monitor Logs Query API (KQL).

Queries are built from versioned, stored templates with typed parameters
(window boundaries, allowlisted table). Nothing the operator or a tenant
types is ever interpolated into KQL.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

import httpx

from engine.connectors._common import (
    Clock, iso_z, option_list, parse_iso, require_guid, utc_now, window_for,
)
from engine.connectors.auth.microsoft import LOG_ANALYTICS_SCOPE, TokenGetter
from engine.connectors.base import (
    ConfigurationError, ConnectorError, PageResult, RecordIdentity,
    SourceConnection,
)
from engine.connectors.http import ConnectorHttp, build_tls, validate_target
from engine.envelope import KIND_ALERT

logger = logging.getLogger(__name__)

TEMPLATE_VERSION = "security-alert-v1"
#: only these tables have a reviewed template; others are rejected.
KQL_TEMPLATES = {
    "SecurityAlert": (
        "SecurityAlert "
        "| where TimeGenerated >= datetime({start}) and TimeGenerated < datetime({end}) "
        "| summarize arg_max(TimeGenerated, *) by SystemAlertId "
        "| order by TimeGenerated asc "
        "| take {limit}"
    ),
}
CLOUD_ENDPOINTS = {
    "public": "https://api.loganalytics.azure.com",
    "usgov": "https://api.loganalytics.us",
    "china": "https://api.loganalytics.azure.cn",
}
ALIAS_SCHEME = "ms_alert:microsoftSentinel"


class SentinelConnector:
    provider = "sentinel"
    streams = ("alerts",)

    def __init__(
        self,
        conn: SourceConnection,
        token_getter: TokenGetter,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Clock = utc_now,
    ) -> None:
        o = conn.options
        self._conn = conn
        self._workspace = require_guid(o.get("workspace_id"), "workspace_id")
        self._tenant = require_guid(o.get("tenant_id"), "tenant_id")
        cloud = o.get("cloud_environment", "public")
        if cloud not in CLOUD_ENDPOINTS:
            raise ConfigurationError(f"cloud_environment must be one of {list(CLOUD_ENDPOINTS)}")
        self._base = validate_target(CLOUD_ENDPOINTS[cloud])
        self._scope = CLOUD_ENDPOINTS[cloud] + "/.default"
        tables = option_list(o, "enabled_tables", ["SecurityAlert"])
        unsupported = [t for t in tables if t not in KQL_TEMPLATES]
        if unsupported:
            raise ConfigurationError(
                f"no reviewed KQL template for tables: {unsupported}")
        self._tables = tables
        self._limit = int(o.get("max_rows", conn.max_page_size))
        if not 1 <= self._limit <= 10000:
            raise ConfigurationError("max_rows must be within 1..10000")
        self._token = token_getter
        self._http = ConnectorHttp(
            base_url=self._base, verify=build_tls(conn.tls_verify, conn.ca_bundle_path),
            transport=transport)
        self._clock = clock

    async def open(self) -> None:
        await self._token(self._scope)  # fail fast on credentials

    async def close(self) -> None:
        await self._http.aclose()

    async def fetch_page(self, cursor, stream="alerts") -> PageResult:
        now = self._clock()
        start, end, _ = window_for(cursor, now, self._conn.lookback_seconds)
        query = KQL_TEMPLATES["SecurityAlert"].format(
            start=iso_z(start), end=iso_z(end), limit=self._limit)
        token = await self._token(self._scope)
        response = await self._http.request(
            "POST", f"/v1/workspaces/{self._workspace}/query",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            content=json.dumps(
                {"query": query, "timespan": f"{iso_z(start)}/{iso_z(end)}"}),
        )
        rows = _rows(response.json())
        warnings: list[str] = []
        if len(rows) >= self._limit:
            last = rows[-1].get("TimeGenerated")
            page_start = parse_iso(last) if last else start
            if page_start <= start:  # no forward progress possible
                page_start = start + timedelta(microseconds=1)
                warnings.append(
                    "page cap reached on identical timestamps; records may be skipped")
            return PageResult(
                rows,
                {"continue": True, "page_start": iso_z(page_start),
                 "window_end": iso_z(end), "template": TEMPLATE_VERSION},
                False, warnings)
        return PageResult(rows, {"window_end": iso_z(end),
                                 "template": TEMPLATE_VERSION}, True, warnings)

    def identify(self, record: dict[str, Any], stream: str) -> RecordIdentity:
        sid = str(record.get("SystemAlertId") or "")
        if not sid:
            raise ConnectorError("SecurityAlert row has no SystemAlertId",
                                 code="malformed_record")
        link = record.get("AlertLink")
        return RecordIdentity(
            record_kind=KIND_ALERT,
            source_event_id=sid,
            namespace=self._workspace,
            event_time=record.get("StartTime") or record.get("TimeGenerated"),
            source_updated_at=record.get("TimeGenerated"),
            source_url=link if isinstance(link, str) and link.startswith("https://") else None,
            provenance={"platform": "azure_monitor_logs",
                        "service_source": "microsoftSentinel",
                        "workspace_id": self._workspace,
                        "tenant_id": self._tenant,
                        "provider_product": record.get("ProductName"),
                        "kql_template": TEMPLATE_VERSION},
            aliases=((ALIAS_SCHEME, str(record.get("VendorOriginalId") or sid)),
                     (ALIAS_SCHEME, sid)),
        )


def _rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    tables = body.get("tables") or []
    if not tables:
        return []
    cols = [c["name"] for c in tables[0].get("columns", [])]
    return [dict(zip(cols, row)) for row in tables[0].get("rows", [])]
