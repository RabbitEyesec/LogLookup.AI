"""Microsoft Sentinel via the Azure Monitor Logs Query API (KQL).

Queries are built from versioned, stored templates with typed parameters
(window boundaries, allowlisted table). Nothing the operator or a tenant
types is ever interpolated into KQL.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any

import httpx

from engine.connectors._common import (
    CURSOR_VERSION, Clock, fingerprint, iso_z, option_list, require_guid,
    resolve_window, utc_now,
)
from engine.connectors.auth.microsoft import LOG_ANALYTICS_SCOPE, TokenGetter
from engine.connectors.base import (
    CURSOR_NON_ADVANCING, PAGE_LIMIT_REACHED, PARTIAL_RESPONSE, STATUS_DEGRADED,
    UNPARSEABLE_ROW, ConfigurationError, ConnectorError, PageResult,
    RecordIdentity, SourceConnection,
)
from engine.connectors.http import ConnectorHttp, build_tls, validate_target
from engine.envelope import KIND_ALERT

logger = logging.getLogger(__name__)

TEMPLATE_VERSION = "security-alert-v2"
# One reviewed query shape, two stages. Ordering is TOTAL - (TimeGenerated,
# SystemAlertId) - and the continuation predicate sits AFTER the per-alert
# summarize, so a later page can neither resurrect an older version of an
# alert nor lose the rest of an equal-timestamp group.
_COMMON = (
    "SecurityAlert "
    "| where TimeGenerated >= datetime({start}) and TimeGenerated < datetime({end}) "
    "| summarize arg_max(TimeGenerated, *) by SystemAlertId "
)
_ORDER = "| order by TimeGenerated asc, SystemAlertId asc | take {limit}"
_SEEK = (
    "| where TimeGenerated > datetime({last_time}) or "
    '(TimeGenerated == datetime({last_time}) and SystemAlertId > "{last_id}") '
)
#: only these tables have a reviewed template; others are rejected.
KQL_TEMPLATES = {"SecurityAlert": _COMMON + _ORDER}
KQL_SEEK_TEMPLATES = {"SecurityAlert": _COMMON + _SEEK + _ORDER}
CLOUD_ENDPOINTS = {
    "public": "https://api.loganalytics.azure.com",
    "usgov": "https://api.loganalytics.us",
    "china": "https://api.loganalytics.azure.cn",
}
ALIAS_SCHEME = "ms_alert:microsoftSentinel"

# Values that reach the KQL text are validated against these, not escaped
# ad hoc: a key that does not match is a hard ingestion error.
_ID_RE = re.compile(r"^[A-Za-z0-9_.:{}-]{1,128}$")
_TIME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?Z$")


def _row_ref(row: Any) -> str:
    """Hash of a bad row for diagnostics. The content itself is never kept."""
    return hashlib.sha256(
        json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:32]


def _seek_key(row_time: Any, row_id: Any, row: Any = None) -> tuple[str, str]:
    """Validated ``(time, id)`` page key. The time stays the provider's own
    string: Kusto datetimes carry 100 ns ticks and re-formatting them to
    microseconds would break the equality half of the seek predicate."""
    if not isinstance(row_id, str) or not _ID_RE.match(row_id):
        raise ConnectorError(
            "SecurityAlert row has no usable SystemAlertId", status=STATUS_DEGRADED,
            code=UNPARSEABLE_ROW, ref=_row_ref(row))
    if not isinstance(row_time, str) or not _TIME_RE.match(row_time):
        raise ConnectorError(
            "SecurityAlert row has no usable TimeGenerated", status=STATUS_DEGRADED,
            code=UNPARSEABLE_ROW, ref=_row_ref(row))
    return row_time, row_id


def _ticks(time_str: str) -> tuple[str, int]:
    """Order-correct form of a Kusto timestamp: whole seconds plus the
    fraction padded to 100 ns ticks (``.5Z`` must sort after ``Z``)."""
    base, _, frac = time_str.rstrip("Z").partition(".")
    return base, int(frac.ljust(7, "0")) if frac else 0


def _order_key(key: tuple[str, str]) -> tuple[tuple[str, int], str]:
    return _ticks(key[0]), key[1]


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
        # Everything a saved cursor depends on: a different workspace, table
        # set or query shape must never continue another query's cursor.
        self._fp = fingerprint("sentinel", self._workspace, self._tenant,
                               ",".join(sorted(tables)), TEMPLATE_VERSION)
        self._token = token_getter
        self._http = ConnectorHttp(
            base_url=self._base, verify=build_tls(conn.tls_verify, conn.ca_bundle_path),
            transport=transport)
        self._clock = clock

    @property
    def fingerprint(self) -> str:
        return self._fp

    async def discard_cursor(self, cursor) -> None:
        """Nothing is held server-side for a Sentinel cursor."""

    async def open(self) -> None:
        await self._token(self._scope)  # fail fast on credentials

    async def close(self) -> None:
        await self._http.aclose()

    def _cursor(self, window, *, continuing: bool, last: tuple[str, str] | None,
                watermark: str | None) -> dict[str, Any]:
        cursor: dict[str, Any] = {
            "cursor_version": CURSOR_VERSION, "kind": "sentinel_kql",
            "fingerprint": self._fp, "template_version": TEMPLATE_VERSION,
            "window_start": iso_z(window.start), "window_end": iso_z(window.end),
            "continue": continuing,
        }
        if last is not None:
            cursor["last_time"], cursor["last_source_id"] = last
        if watermark:
            cursor["watermark"] = watermark
        return cursor

    async def fetch_page(self, cursor, stream="alerts") -> PageResult:
        window = resolve_window(cursor, self._clock(),
                                self._conn.lookback_seconds, self._fp)
        warnings = list(window.warnings)
        # The committed watermark is only advanced when a window drains.
        prior_watermark = (cursor or {}).get("watermark")
        seek: tuple[str, str] | None = None
        if window.continuing and cursor and cursor.get("last_time"):
            seek = _seek_key(cursor["last_time"], cursor.get("last_source_id"))

        if seek is None:
            query = KQL_TEMPLATES["SecurityAlert"].format(
                start=iso_z(window.start), end=iso_z(window.end), limit=self._limit)
        else:
            query = KQL_SEEK_TEMPLATES["SecurityAlert"].format(
                start=iso_z(window.start), end=iso_z(window.end), limit=self._limit,
                last_time=seek[0], last_id=seek[1])
        token = await self._token(self._scope)
        response = await self._http.request(
            "POST", f"/v1/workspaces/{self._workspace}/query",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            content=json.dumps({
                "query": query,
                "timespan": f"{iso_z(window.start)}/{iso_z(window.end)}"}),
        )
        rows = self._rows_checked(response, seek)
        if len(rows) >= self._limit:
            last = _seek_key(rows[-1]["TimeGenerated"], rows[-1]["SystemAlertId"])
            return PageResult(
                rows,
                self._cursor(window, continuing=True, last=last,
                             watermark=prior_watermark),
                False, [*warnings, PAGE_LIMIT_REACHED])
        return PageResult(
            rows,
            self._cursor(window, continuing=False, last=None,
                         watermark=iso_z(window.end)),
            True, warnings)

    def _rows_checked(self, response, seek) -> list[dict[str, Any]]:
        """Parse a page and fail closed on anything that is not a complete,
        strictly ordered, strictly advancing result."""
        try:
            body = response.json()
        except ValueError:
            raise ConnectorError("Azure Monitor returned a non-JSON body",
                                 status=STATUS_DEGRADED, code=PARTIAL_RESPONSE) from None
        # HTTP 200 can still carry a partial result: never read it as "empty".
        if isinstance(body, dict) and body.get("error"):
            raise ConnectorError(
                "Azure Monitor returned a partial or truncated result",
                status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
        if not isinstance(body, dict) or not body.get("tables"):
            raise ConnectorError("Azure Monitor response has no result table",
                                 status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
        rows = _rows(body)
        previous = seek
        for row in rows:
            key = _seek_key(row.get("TimeGenerated"), row.get("SystemAlertId"), row)
            if previous is not None and _order_key(key) <= _order_key(previous):
                raise ConnectorError(
                    "page did not advance past the previous (time, id) key",
                    status=STATUS_DEGRADED, code=CURSOR_NON_ADVANCING)
            previous = key
        return rows

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
