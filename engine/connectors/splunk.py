"""Splunk Enterprise / Enterprise Security via REST search.

Uses ``/services/search/v2/jobs/export`` (streaming) or
``/services/search/v2/jobs`` + paged ``/results`` (job mode); never the
deprecated v1 export. Windows are on ``_indextime`` so late-indexed events
are caught without relabelling the ``_time`` event timeline.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from engine.connectors._common import (
    Clock, option_list, utc_now, window_for,
)
from engine.connectors.auth.splunk import splunk_headers
from engine.connectors.base import (
    ConfigurationError, ConnectorError, PageResult, RecordIdentity,
    SourceConnection,
)
from engine.connectors.http import ConnectorHttp, build_tls, validate_target
from engine.envelope import KIND_ALERT

logger = logging.getLogger(__name__)

_INDEX_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.*-]{0,63}$")
_APP_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SEARCH_TEMPLATE = (
    "search ({indexes}) _index_earliest={start} _index_latest={end} "
    "| fields _time _indextime _cd _raw _serial index host source sourcetype splunk_server "
    "event_id rule_name rule_title search_name signature severity urgency "
    "security_domain status owner user src dest dest_host src_ip dest_ip "
    "process process_name process_id process_guid parent_process "
    "mitre_technique_id annotations.mitre_attack.mitre_technique_id "
    "annotations.mitre_attack.mitre_tactic "
    "| sort 0 _indextime | head {limit}"
)
JOB_POLL_SECONDS = 1.0
JOB_TIMEOUT_SECONDS = 120


class SplunkConnector:
    provider = "splunk"
    streams = ("notables",)

    def __init__(
        self, conn: SourceConnection, token: str, *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Clock = utc_now, sleep=asyncio.sleep,
    ) -> None:
        o = conn.options
        url = o.get("management_url")
        if not isinstance(url, str):
            raise ConfigurationError("management_url is required")
        self._url = validate_target(url.rstrip("/"), allow_loopback=True)
        self._host = urlsplit(self._url).netloc
        indexes = option_list(o, "indexes", [])
        if not indexes:
            raise ConfigurationError("at least one allowlisted index is required")
        bad = [i for i in indexes if not _INDEX_RE.match(i)]
        if bad:
            raise ConfigurationError(f"invalid index names: {bad}")
        self._indexes = indexes
        mode = o.get("search_mode", "export")
        if mode not in ("export", "jobs"):
            raise ConfigurationError("search_mode must be 'export' or 'jobs'")
        self._mode = mode
        ns = o.get("api_namespace") or {}
        self._prefix = "/services"
        if ns:
            owner, app = str(ns.get("owner", "")), str(ns.get("app", ""))
            if not (_APP_RE.match(owner) and _APP_RE.match(app)):
                raise ConfigurationError("api_namespace owner/app are invalid")
            self._prefix = f"/servicesNS/{owner}/{app}"
        self._limit = int(o.get("max_results", conn.max_page_size))
        self._max_age = int(o.get("max_event_age_seconds", 86400))
        self._headers = {**splunk_headers(token)}
        self._conn = conn
        self._http = ConnectorHttp(
            base_url=self._url, timeout=float(o.get("timeout_seconds", 60)),
            verify=build_tls(conn.tls_verify, conn.ca_bundle_path),
            transport=transport)
        self._clock = clock
        self._sleep = sleep

    async def open(self) -> None:
        await self._http.request(
            "GET", "/services/server/info", headers=self._headers,
            params={"output_mode": "json"})

    async def close(self) -> None:
        await self._http.aclose()

    def _search(self, start: datetime, end: datetime) -> dict[str, str]:
        indexes = " OR ".join(f"index={i}" for i in self._indexes)
        return {
            "search": SEARCH_TEMPLATE.format(
                indexes=indexes, start=int(start.timestamp()),
                end=int(end.timestamp()) + 1, limit=self._limit),
            "earliest_time": str(int(start.timestamp()) - self._max_age),
            "latest_time": "now",
            "output_mode": "json",
        }

    async def fetch_page(self, cursor, stream="notables") -> PageResult:
        now = self._clock()
        start, end, _ = window_for(cursor, now, self._conn.lookback_seconds)
        form = self._search(start, end)
        rows = (await self._export(form) if self._mode == "export"
                else await self._job(form))
        if len(rows) >= self._limit:
            last = _num(rows[-1].get("_indextime"))
            warnings = []
            nxt = last if last and last > start.timestamp() else start.timestamp() + 1
            if nxt == start.timestamp() + 1 and not (last and last > start.timestamp()):
                warnings.append(
                    "result cap reached on identical _indextime; records may be skipped")
            return PageResult(
                rows, {"continue": True, "window_end": end.isoformat(),
                       "page_start": datetime.fromtimestamp(nxt, end.tzinfo).isoformat()},
                False, warnings)
        return PageResult(rows, {"window_end": end.isoformat()}, True, [])

    async def _export(self, form: dict[str, str]) -> list[dict[str, Any]]:
        response = await self._http.request(
            "POST", f"{self._prefix}/search/v2/jobs/export",
            headers=self._headers, data=form)
        out = []
        for line in response.text.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("preview"):
                continue
            if isinstance(item.get("result"), dict):
                out.append(item["result"])
        return out

    async def _job(self, form: dict[str, str]) -> list[dict[str, Any]]:
        created = await self._http.request(
            "POST", f"{self._prefix}/search/v2/jobs", headers=self._headers,
            data=form)
        sid = created.json().get("sid")
        if not sid or not re.match(r"^[A-Za-z0-9_.\-]+$", str(sid)):
            raise ConnectorError("Splunk returned no usable search id",
                                 code="bad_response")
        try:
            waited = 0.0
            while True:
                status = await self._http.request(
                    "GET", f"{self._prefix}/search/v2/jobs/{sid}",
                    headers=self._headers, params={"output_mode": "json"})
                content = (status.json().get("entry") or [{}])[0].get("content", {})
                if content.get("isDone"):
                    break
                if content.get("isFailed"):
                    raise ConnectorError("Splunk search job failed",
                                         code="job_failed")
                if waited >= JOB_TIMEOUT_SECONDS:
                    raise ConnectorError("Splunk search job timed out",
                                         code="job_timeout")
                await self._sleep(JOB_POLL_SECONDS)
                waited += JOB_POLL_SECONDS
            rows: list[dict[str, Any]] = []
            while len(rows) < self._limit:
                page = await self._http.request(
                    "GET", f"{self._prefix}/search/v2/jobs/{sid}/results",
                    headers=self._headers,
                    params={"output_mode": "json", "offset": len(rows),
                            "count": min(500, self._limit - len(rows))})
                results = page.json().get("results") or []
                rows.extend(results)
                if len(results) < 1:
                    break
            return rows
        finally:  # release the search job whatever happened
            try:
                await self._http.request(
                    "DELETE", f"{self._prefix}/search/v2/jobs/{sid}",
                    headers=self._headers, retry=False)
            except ConnectorError:
                logger.debug("could not release Splunk job %s", sid)

    def identify(self, record: dict[str, Any], stream: str) -> RecordIdentity:
        index = str(_one(record.get("index")) or "")
        event_id = _one(record.get("event_id"))
        cd = _one(record.get("_cd"))
        if event_id:
            source_id = str(event_id)
        elif cd:
            source_id = f"{index}:{cd}"
        else:
            source_id = hashlib.sha256(
                json.dumps([record.get("_time"), record.get("_raw"),
                            record.get("host")], default=str).encode()
            ).hexdigest()[:32]
        return RecordIdentity(
            record_kind=KIND_ALERT, source_event_id=source_id,
            namespace=str(_one(record.get("splunk_server")) or self._host),
            event_time=_time_str(record.get("_time")),
            source_updated_at=_time_str(record.get("_indextime")),
            provenance={"platform": "splunk_rest", "index": index,
                        "security_domain": _one(record.get("security_domain")),
                        "splunk_server": _one(record.get("splunk_server")),
                        "indextime": _one(record.get("_indextime"))},
        )


def _one(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def _num(value: Any) -> float | None:
    try:
        return float(_one(value))
    except (TypeError, ValueError):
        return None


def _time_str(value: Any) -> str | None:
    value = _one(value)
    return None if value is None else str(value)
