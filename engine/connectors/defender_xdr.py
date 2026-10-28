"""Microsoft Defender XDR via Microsoft Graph Security (read-only).

Alerts (``alerts_v2``) become detections; incidents are external-case
records that link alerts together and are *never* counted as detections.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

import httpx

from engine.connectors._common import (
    Clock, iso_z, option_list, parse_iso, require_guid, utc_now, window_for,
)
from engine.connectors.auth.microsoft import GRAPH_SCOPE, TokenGetter
from engine.connectors.base import (
    ConfigurationError, ConnectorError, PageResult, RecordIdentity,
    SourceConnection,
)
from engine.connectors.http import ConnectorHttp, build_tls, validate_target
from engine.envelope import KIND_ALERT, KIND_INCIDENT

logger = logging.getLogger(__name__)

GRAPH_CLOUDS = {
    "public": "https://graph.microsoft.com",
    "usgov": "https://graph.microsoft.us",
    "china": "https://microsoftgraph.chinacloudapi.cn",
}
PATHS = {"alerts": "/v1.0/security/alerts_v2", "incidents": "/v1.0/security/incidents"}


def sentinel_alias_scheme(service_source: str) -> str:
    return f"ms_alert:{service_source}"


class GraphPagedConnector:
    """Shared Graph paging: ``$filter`` window + ``@odata.nextLink``."""

    streams: tuple[str, ...] = ()
    paths: dict[str, str] = {}
    filter_field = "lastUpdateDateTime"
    #: per-stream override (directoryAudits filter on activityDateTime)
    filter_fields: dict[str, str] = {}

    def __init__(
        self, conn: SourceConnection, token_getter: TokenGetter, *,
        transport: httpx.AsyncBaseTransport | None = None, clock: Clock = utc_now,
    ) -> None:
        o = conn.options
        self._conn = conn
        self._tenant = require_guid(o.get("tenant_id"), "tenant_id")
        cloud = o.get("cloud_environment", "public")
        if cloud not in GRAPH_CLOUDS:
            raise ConfigurationError(f"cloud_environment must be one of {list(GRAPH_CLOUDS)}")
        self._base = validate_target(GRAPH_CLOUDS[cloud])
        self._graph_host = urlsplit(self._base).hostname
        wanted = option_list(o, "streams", list(self.paths))
        unknown = [s for s in wanted if s not in self.paths]
        if unknown:
            raise ConfigurationError(f"unsupported streams: {unknown}")
        self.streams = tuple(wanted)
        self._token = token_getter
        self._http = ConnectorHttp(
            base_url=self._base,
            verify=build_tls(conn.tls_verify, conn.ca_bundle_path),
            transport=transport)
        self._clock = clock

    async def open(self) -> None:
        await self._token(GRAPH_SCOPE)

    async def close(self) -> None:
        await self._http.aclose()

    async def fetch_page(self, cursor, stream=None) -> PageResult:
        stream = stream or self.streams[0]
        if stream not in self.streams:
            raise ConnectorError(f"stream {stream!r} is not enabled",
                                 code="bad_stream")
        token = await self._token(GRAPH_SCOPE)
        headers = {"Authorization": f"Bearer {token}"}
        now = self._clock()
        start, end, _ = window_for(cursor, now, self._conn.lookback_seconds)
        link = cursor.get("next_link") if cursor else None
        if link:
            # nextLink is server-supplied: it may only point back at Graph.
            if urlsplit(link).hostname != self._graph_host:
                raise ConnectorError("refusing nextLink to a foreign host",
                                     code="bad_next_link")
            response = await self._http.request("GET", link, headers=headers)
            end = parse_iso(cursor["window_end"])
        else:
            field = self.filter_fields.get(stream, self.filter_field)
            flt = f"{field} ge {iso_z(start)} and {field} lt {iso_z(end)}"
            response = await self._http.request(
                "GET", self.paths[stream], headers=headers,
                params={"$filter": flt, "$top": str(self._conn.max_page_size)})
        body = response.json()
        records = [r for r in body.get("value", []) if isinstance(r, dict)]
        nxt = body.get("@odata.nextLink")
        if nxt:
            return PageResult(
                records,
                {"continue": True, "page_start": iso_z(start),
                 "window_end": iso_z(end), "next_link": nxt,
                 **({"watermark": cursor["watermark"]}
                    if cursor and cursor.get("watermark") else {})},
                False, ["PAGE_LIMIT_REACHED"])
        return PageResult(records, {"window_end": iso_z(end),
                                    "watermark": iso_z(end)}, True, [])


class DefenderXdrConnector(GraphPagedConnector):
    provider = "defender_xdr"
    paths = PATHS
    streams = tuple(PATHS)

    def identify(self, record: dict[str, Any], stream: str) -> RecordIdentity:
        rid = str(record.get("id") or "")
        if not rid:
            raise ConnectorError("Graph record has no id", code="malformed_record")
        tenant = str(record.get("tenantId") or self._tenant)
        if stream == "incidents":
            url = record.get("incidentWebUrl")
            return RecordIdentity(
                record_kind=KIND_INCIDENT, source_event_id=rid, namespace=tenant,
                event_time=record.get("createdDateTime"),
                source_updated_at=record.get("lastUpdateDateTime"),
                source_incident_id=rid,
                source_url=url if isinstance(url, str) and url.startswith("https://") else None,
                provenance={"platform": "microsoft_graph", "service_source": "incident"},
                links=[{"external_incident_id": rid, "url": url,
                        "title": record.get("displayName"),
                        "status": record.get("status"), "cluster_id": ""}],
            )
        service = str(record.get("serviceSource") or "unknown")
        provider_id = record.get("providerAlertId")
        url = record.get("alertWebUrl")
        incident = record.get("incidentId")
        return RecordIdentity(
            record_kind=KIND_ALERT, source_event_id=rid, namespace=tenant,
            event_time=record.get("firstActivityDateTime") or record.get("createdDateTime"),
            source_updated_at=record.get("lastUpdateDateTime"),
            source_incident_id=str(incident) if incident else None,
            source_url=url if isinstance(url, str) and url.startswith("https://") else None,
            provenance={"platform": "microsoft_graph", "service_source": service,
                        "provider_alert_id": provider_id,
                        "classification": record.get("classification"),
                        "determination": record.get("determination"),
                        "incident_url": record.get("incidentWebUrl")},
            aliases=((sentinel_alias_scheme(service), str(provider_id)),)
            if provider_id else (),
            links=[{"external_incident_id": str(incident),
                    "url": record.get("incidentWebUrl"), "cluster_id": ""}]
            if incident else [],
        )
