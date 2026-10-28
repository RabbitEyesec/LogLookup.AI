"""Splunk Enterprise / Enterprise Security via REST search jobs.

Collection is a **snapshot search job** per bounded index-time window. The
job is created once, kept alive while it is drained page by page
(``/results?offset&count``), and released only when drained. The cursor
carries ``(window, job_sid, offset, query fingerprint)``; nothing about a
page depends on a timestamp hop, so any number of records sharing one
``_indextime`` are all reached.

If the job disappears (expired, or Splunk restarted) the SAME frozen window
is searched again from offset 0 - never an old offset against a new job. The
ledger de-duplicates the re-read.

Windows are on ``_indextime`` so late-indexed events are still collected
without relabelling their ``_time`` position. The optional event-time floor
(``max_event_age_seconds``) is an explicit, reported filter, not a silent one.
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
    CURSOR_VERSION, Clock, fingerprint, iso_z, option_list, resolve_window,
    utc_now,
)
from engine.connectors.auth.splunk import splunk_headers
from engine.connectors.base import (
    BAD_ROWS_SKIPPED, EVENT_TIME_FILTER_ACTIVE, EXPORT_MODE_RETIRED,
    FULL_INDEX_TIME_COLLECTION, PAGE_LIMIT_REACHED,
    PARTIAL_RESPONSE, SNAPSHOT_EXPIRED_REPLAYING, SNAPSHOT_RUNNING,
    STATUS_DEGRADED, UNPARSEABLE_ROW, ConfigurationError, ConnectorError,
    PageResult, RecordIdentity, SourceConnection,
)
from engine.connectors.http import ConnectorHttp, build_tls, validate_target
from engine.envelope import KIND_ALERT

logger = logging.getLogger(__name__)

TEMPLATE_VERSION = "notable-snapshot-v2"
_INDEX_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.*-]{0,63}$")
_APP_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,200}$")
# No ``| head``: the snapshot is complete and is paged server-side. The sort
# is total (index time, then index, then record id) so offsets are stable.
SEARCH_TEMPLATE = (
    "search ({indexes}) _index_earliest={start} _index_latest={end} "
    "| fields _time _indextime _cd _raw _serial index host source sourcetype splunk_server "
    "event_id rule_name rule_title search_name signature severity urgency "
    "security_domain status owner user src dest dest_host src_ip dest_ip "
    "process process_name process_id process_guid parent_process "
    "mitre_technique_id annotations.mitre_attack.mitre_technique_id "
    "annotations.mitre_attack.mitre_tactic "
    "| sort 0 _indextime index _cd"
)
JOB_POLL_SECONDS = 1.0
#: how long one fetch waits for a running job before returning "still running"
JOB_WAIT_SECONDS = 30.0
JOB_KEEP_SECONDS = 3600  # server-side keep-alive after the job finishes


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
        mode = o.get("search_mode", "jobs")
        if mode not in ("export", "jobs"):
            raise ConfigurationError("search_mode must be 'jobs' (or legacy 'export')")
        # The streaming export cannot be resumed or verified complete, so it
        # is retired: 'export' now means the snapshot job path.
        self._export_retired = mode == "export"
        ns = o.get("api_namespace") or {}
        self._prefix = "/services"
        if ns:
            owner, app = str(ns.get("owner", "")), str(ns.get("app", ""))
            if not (_APP_RE.match(owner) and _APP_RE.match(app)):
                raise ConfigurationError("api_namespace owner/app are invalid")
            self._prefix = f"/servicesNS/{owner}/{app}"
        self._limit = int(o.get("max_results", conn.max_page_size))
        if not 1 <= self._limit <= 50000:
            raise ConfigurationError("max_results must be within 1..50000")
        # 0 disables the event-time floor (full index-time capture).
        self._max_age = int(o.get("max_event_age_seconds", 86400))
        if self._max_age < 0:
            raise ConfigurationError("max_event_age_seconds must be >= 0")
        self._fp = fingerprint(
            "splunk", self._host, ",".join(sorted(indexes)), self._prefix,
            self._max_age, TEMPLATE_VERSION)
        #: strict (default): a row we cannot identify stops the page. An
        #: administrator can switch this off for ONE window to skip bad rows.
        self.strict = True
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

    @property
    def fingerprint(self) -> str:
        return self._fp

    async def discard_cursor(self, cursor: dict[str, Any] | None) -> None:
        """Release the search job a replaced cursor was holding (best effort)."""
        sid = (cursor or {}).get("job_sid")
        if sid:
            await self._release(str(sid))

    # -- cursor ------------------------------------------------------------------

    def _cursor(self, start: datetime, end: datetime, *, continuing: bool,
                sid: str | None = None, offset: int = 0,
                watermark: str | None = None,
                floor: int | None = None) -> dict[str, Any]:
        cursor: dict[str, Any] = {
            "cursor_version": CURSOR_VERSION, "kind": "splunk_job",
            "mode": "splunk_job", "fingerprint": self._fp,
            "query_fingerprint": self._fp, "template_version": TEMPLATE_VERSION,
            "window_start": iso_z(start), "window_end": iso_z(end),
            "continue": continuing,
        }
        if sid:
            cursor["job_sid"], cursor["offset"] = sid, offset
        if watermark:
            cursor["watermark"] = watermark
        if floor is not None:  # only a backfill carries its own floor
            cursor["event_time_floor"] = floor
        return cursor

    # -- paging ------------------------------------------------------------------

    async def fetch_page(self, cursor, stream="notables") -> PageResult:
        window = resolve_window(cursor, self._clock(),
                                self._conn.lookback_seconds, self._fp)
        warnings = list(window.warnings)
        if self._export_retired:
            warnings.append(EXPORT_MODE_RETIRED)
        # A backfill may carry its own event-time floor (0 = none).
        backfill_floor = (cursor or {}).get("event_time_floor")
        floor = self._max_age if backfill_floor is None else int(backfill_floor)
        warnings.append(EVENT_TIME_FILTER_ACTIVE if floor
                        else FULL_INDEX_TIME_COLLECTION)
        prior_watermark = (cursor or {}).get("watermark")

        sid: str | None = None
        offset = 0
        if window.continuing and cursor and cursor.get("job_sid") \
                and not window.trusted_backfill:
            sid, offset = str(cursor["job_sid"]), int(cursor.get("offset", 0))
            if not _SID_RE.match(sid):
                raise ConnectorError("saved search id is invalid",
                                     status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
        elif window.trusted_backfill and cursor and cursor.get("job_sid"):
            sid, offset = str(cursor["job_sid"]), int(cursor.get("offset", 0))

        state = await self._job_state(sid) if sid else None
        if sid and state is None:
            # Job gone: replay the SAME window from the start, never reuse
            # an offset that belonged to the vanished snapshot.
            warnings.append(SNAPSHOT_EXPIRED_REPLAYING)
            sid, offset = None, 0
        if sid is None:
            sid = await self._create_job(window.start, window.end, floor)
            offset = 0
            state = await self._job_state(sid)
            if state is None:
                raise ConnectorError("Splunk lost the search job it just created",
                                     status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)

        state = await self._wait_done(sid, state)
        if not state["done"]:
            # Still running: keep the sid in the cursor and look again next
            # cycle; nothing is advanced and nothing is skipped.
            return PageResult(
                [], self._cursor(window.start, window.end, continuing=True,
                                 sid=sid, offset=offset, watermark=prior_watermark,
                                 floor=backfill_floor),
                False, [*warnings, SNAPSHOT_RUNNING])

        total = state["result_count"]
        rows, rejected, raw_count = await self._results(sid, offset)
        new_offset = offset + raw_count
        if rejected:
            warnings.append(BAD_ROWS_SKIPPED)
        if not raw_count and offset < total:
            raise ConnectorError(
                "Splunk reported more results than it returned",
                status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
        if new_offset < total:
            return PageResult(
                rows, self._cursor(window.start, window.end, continuing=True,
                                   sid=sid, offset=new_offset,
                                   watermark=prior_watermark,
                                   floor=backfill_floor),
                False, [*warnings, PAGE_LIMIT_REACHED], rejected)
        await self._release(sid)  # drained: release the snapshot
        return PageResult(
            rows, self._cursor(window.start, window.end, continuing=False,
                               watermark=iso_z(window.end)),
            True, warnings, rejected)

    # -- search job plumbing -------------------------------------------------------

    def _form(self, start: datetime, end: datetime, floor: int) -> dict[str, str]:
        indexes = " OR ".join(f"index={i}" for i in self._indexes)
        earliest = str(int(start.timestamp()) - floor) if floor else "0"
        return {
            "search": SEARCH_TEMPLATE.format(
                indexes=indexes, start=int(start.timestamp()),
                end=int(end.timestamp()) + 1),
            "earliest_time": earliest,
            "latest_time": "now",
            "output_mode": "json",
            "timeout": str(JOB_KEEP_SECONDS),
        }

    async def _create_job(self, start: datetime, end: datetime, floor: int) -> str:
        created = await self._http.request(
            "POST", f"{self._prefix}/search/v2/jobs", headers=self._headers,
            data=self._form(start, end, floor))
        sid = _json(created).get("sid")
        if not sid or not _SID_RE.match(str(sid)):
            raise ConnectorError("Splunk returned no usable search id",
                                 status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
        return str(sid)

    async def _job_state(self, sid: str) -> dict[str, Any] | None:
        """Job status, or None when the job no longer exists."""
        try:
            response = await self._http.request(
                "GET", f"{self._prefix}/search/v2/jobs/{sid}",
                headers=self._headers, params={"output_mode": "json"})
        except ConnectorError as exc:
            if exc.code == "not_found":
                return None
            raise
        entry = (_json(response).get("entry") or [{}])[0]
        content = entry.get("content") or {}
        if content.get("isFailed"):
            raise ConnectorError("Splunk search job failed",
                                 status=STATUS_DEGRADED, code="job_failed")
        # A finalised (manually stopped) or truncated job is not a complete
        # snapshot: fail closed rather than treat it as drained.
        messages = " ".join(str(m.get("text", "")) for m in
                            (content.get("messages") or []) if isinstance(m, dict))
        if content.get("isFinalized") or "truncat" in messages.lower():
            raise ConnectorError("Splunk search was finalised or truncated",
                                 status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
        try:
            count = int(content.get("resultCount", 0))
        except (TypeError, ValueError):
            raise ConnectorError("Splunk returned an invalid resultCount",
                                 status=STATUS_DEGRADED, code=PARTIAL_RESPONSE) from None
        return {"done": bool(content.get("isDone")), "result_count": count}

    async def _wait_done(self, sid: str, state: dict[str, Any]) -> dict[str, Any]:
        waited = 0.0
        while not state["done"] and waited < JOB_WAIT_SECONDS:
            await self._sleep(JOB_POLL_SECONDS)
            waited += JOB_POLL_SECONDS
            fresh = await self._job_state(sid)
            if fresh is None:
                raise ConnectorError("Splunk search job vanished while running",
                                     status=STATUS_DEGRADED,
                                     code=SNAPSHOT_EXPIRED_REPLAYING)
            state = fresh
        return state

    async def _results(self, sid: str, offset: int):
        """Returns ``(good_rows, rejected, raw_count)``.

        A row with no ``event_id`` or ``_cd`` cannot be given a trustworthy
        identity. Normally that stops the page (nothing is skipped, no
        identity is invented). Only while an administrator has allowed it for
        one window are such rows set aside, with a hash for diagnostics.
        """
        response = await self._http.request(
            "GET", f"{self._prefix}/search/v2/jobs/{sid}/results",
            headers=self._headers,
            params={"output_mode": "json", "offset": offset, "count": self._limit})
        rows = _json(response).get("results")
        if not isinstance(rows, list):
            raise ConnectorError("Splunk results are missing or malformed",
                                 status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
        good, rejected = [], []
        for row in rows:
            if isinstance(row, dict) and (
                _one(row.get("event_id")) or _one(row.get("_cd"))
            ):
                good.append(row)
                continue
            ref = hashlib.sha256(
                json.dumps(row, sort_keys=True, default=str).encode()
            ).hexdigest()[:32]
            if self.strict:
                raise ConnectorError(
                    "Splunk result row has no event_id or _cd",
                    status=STATUS_DEGRADED, code=UNPARSEABLE_ROW, ref=ref)
            rejected.append({"ref": ref, "reason": UNPARSEABLE_ROW})
        return good, rejected, len(rows)

    async def _release(self, sid: str) -> None:
        if not _SID_RE.match(sid):
            return
        try:
            await self._http.request(
                "DELETE", f"{self._prefix}/search/v2/jobs/{sid}",
                headers=self._headers, retry=False)
        except ConnectorError:
            logger.debug("could not release Splunk job %s", sid)

    # -- identity ----------------------------------------------------------------

    def identify(self, record: dict[str, Any], stream: str) -> RecordIdentity:
        index = str(_one(record.get("index")) or "")
        event_id = _one(record.get("event_id"))
        cd = _one(record.get("_cd"))
        if event_id:
            source_id = str(event_id)
        elif cd:
            source_id = f"{index}:{cd}"
        else:
            raise ConnectorError("Splunk row has no event_id or _cd",
                                 status=STATUS_DEGRADED, code=UNPARSEABLE_ROW)
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


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        raise ConnectorError("Splunk returned a non-JSON body",
                             status=STATUS_DEGRADED, code=PARTIAL_RESPONSE) from None
    if not isinstance(body, dict):
        raise ConnectorError("Splunk returned an unexpected body",
                             status=STATUS_DEGRADED, code=PARTIAL_RESPONSE)
    return body


def _one(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def _time_str(value: Any) -> str | None:
    value = _one(value)
    return None if value is None else str(value)
