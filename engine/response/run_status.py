"""Read-only lookup of an Azure Logic Apps workflow run.

This only ever sends GET requests to Azure Resource Manager. It never calls
the workflow trigger, so checking a status can not cause the action to run
again.

A run is identified in exactly two ways, both exact:
  * the run id Azure returned when the request was accepted, or
  * the client tracking id LogLookup sent (it is the LogLookup action id).
If that finds zero runs, or more than one, nothing is chosen. We never pick
a run because it is "close in time" or has the same workflow name.

What Azure reports about the run is stored as *workflow status*. It is not
proof of what the workflow did downstream.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx

from engine.connectors.auth.microsoft import ARM_CLOUDS
from engine.connectors.base import ConfigurationError, ConnectorError
from engine.connectors.http import ConnectorHttp, scrub
from engine.response.approvals import ActionService
from engine.response.audit import AuditLog
from engine.response.models import (
    ActionState, Conflict, ResponseAction, ResponseError,
)
from engine.response.policy import ResponsePolicy
from engine.store.database import Database, utcnow

KNOWN_STATUSES = ("Running", "Waiting", "Succeeded", "Failed", "Cancelled", "TimedOut")
_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NAME = re.compile(r"^[A-Za-z0-9_.()\-]{1,90}$")
_RUN = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")
MAX_LIST_PAGES = 5


@dataclass
class RunLookup:
    """Outcome of one lookup. ``found`` is only True for exactly one run."""

    found: bool
    reason: str = "ok"          # ok | no_match | ambiguous | id_mismatch
    status: str | None = None    # Azure's own word: Succeeded, Failed, ...
    matched_by: str | None = None
    run_name: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    candidates: int = 0

    def stored(self) -> dict[str, Any]:
        """What gets saved on the action (no raw Azure payload)."""
        return {
            "found": self.found, "reason": self.reason, "status": self.status,
            "matched_by": self.matched_by, "run_name": self.run_name,
            "start_time": self.start_time, "end_time": self.end_time,
            "error_code": self.error_code, "error_message": self.error_message,
            "candidates": self.candidates,
        }


class RunStatusClient:
    """``arm`` is the ``arm`` block of the Logic App auth profile:

    ``{"plan": "consumption" | "standard", "subscription_id": "<guid>",
       "resource_group": "...", "workflow_name": "...",
       "site_name": "<standard only: the Logic App (Standard) resource>",
       "cloud": "public" | "usgov" | "china"}``
    """

    def __init__(self, arm: dict[str, Any],
                 token_getter: Callable[[str], Awaitable[str]], *,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._plan = arm.get("plan", "consumption")
        if self._plan not in ("consumption", "standard"):
            raise ConfigurationError("arm.plan must be 'consumption' or 'standard'")
        sub = arm.get("subscription_id", "")
        if not _GUID.match(str(sub)):
            raise ConfigurationError("arm.subscription_id must be a GUID")
        group, workflow = arm.get("resource_group", ""), arm.get("workflow_name", "")
        for label, value in (("resource_group", group), ("workflow_name", workflow)):
            if not _NAME.match(str(value)):
                raise ConfigurationError(f"arm.{label} is missing or invalid")
        cloud = arm.get("cloud", "public")
        if cloud not in ARM_CLOUDS:
            raise ConfigurationError(f"arm.cloud must be one of {list(ARM_CLOUDS)}")
        self._host, self._scope = ARM_CLOUDS[cloud]
        root = f"/subscriptions/{sub}/resourceGroups/{group}"
        if self._plan == "consumption":
            self._base = f"{root}/providers/Microsoft.Logic/workflows/{workflow}"
            self._api = "2016-06-01"
        else:
            site = arm.get("site_name", "")
            if not _NAME.match(str(site)):
                raise ConfigurationError("arm.site_name is required for Standard")
            self._base = (f"{root}/providers/Microsoft.Web/sites/{site}/hostruntime/"
                          f"runtime/webhooks/workflow/api/management/workflows/{workflow}")
            self._api = "2018-11-01"
        self._token = token_getter
        self._http = ConnectorHttp(base_url=f"https://{self._host}", transport=transport)

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- public ------------------------------------------------------------------

    async def lookup(self, action_id: str, run_id: str | None) -> RunLookup:
        if not _is_uuid(action_id):
            raise ConfigurationError("action id is not a UUID")
        if run_id:
            if not _RUN.match(run_id):
                return RunLookup(False, "id_mismatch")
            run = await self._get_run(run_id)
            if run is not None:
                seen = _tracking_id(run)
                # A run id that belongs to some other request is not ours.
                if seen and seen != action_id:
                    return RunLookup(False, "id_mismatch", candidates=1)
                return _describe(run, "run_id")
        # No (valid) run id: find the run by the id we sent with the request.
        matches = await self._find_by_tracking_id(action_id)
        if len(matches) == 0:
            return RunLookup(False, "no_match")
        if len(matches) > 1:
            return RunLookup(False, "ambiguous", candidates=len(matches))
        return _describe(matches[0], "client_tracking_id")

    # -- Azure calls (GET only) ------------------------------------------------------

    async def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self._token(self._scope)}"}

    async def _get_run(self, run_name: str) -> dict[str, Any] | None:
        try:
            response = await self._http.request(
                "GET", f"{self._base}/runs/{run_name}",
                headers=await self._headers(), params={"api-version": self._api})
        except ConnectorError as exc:
            if exc.code == "not_found":
                return None
            raise
        return _body(response)

    async def _find_by_tracking_id(self, action_id: str) -> list[dict[str, Any]]:
        """Runs whose client tracking id is exactly ``action_id``.

        The server-side filter just narrows the list; every run is re-checked
        here, so a wrong or ignored filter can not produce a wrong match.
        """
        params = {"api-version": self._api,
                  "$filter": f"clientTrackingId eq '{action_id}'"}
        try:
            return await self._collect(params, action_id)
        except ConnectorError as exc:
            if exc.code != "http_400":  # filter not supported: list and check
                raise
        return await self._collect({"api-version": self._api, "$top": "250"}, action_id)

    async def _collect(self, params: dict[str, str], action_id: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        url, query = f"{self._base}/runs", params
        for _ in range(MAX_LIST_PAGES):
            response = await self._http.request(
                "GET", url, headers=await self._headers(), params=query)
            body = _body(response)
            found += [r for r in body.get("value", [])
                      if isinstance(r, dict) and _tracking_id(r) == action_id]
            nxt = body.get("nextLink")
            if not nxt:
                return found
            # a server-supplied link may only point back at Azure Resource Manager
            parts = httpx.URL(nxt)
            if parts.host != self._host:
                raise ConnectorError("refusing a next link to another host",
                                     code="bad_next_link")
            url, query = parts.path + ("?" + parts.query.decode() if parts.query else ""), None
        return found


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def _body(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        raise ConnectorError("Azure returned a non-JSON body", code="bad_response") from None
    if not isinstance(body, dict):
        raise ConnectorError("Azure returned an unexpected body", code="bad_response")
    return body


def _tracking_id(run: dict[str, Any]) -> str | None:
    props = run.get("properties") or {}
    return (props.get("correlation") or {}).get("clientTrackingId")


def _describe(run: dict[str, Any], matched_by: str) -> RunLookup:
    props = run.get("properties") or {}
    error = props.get("error") if isinstance(props.get("error"), dict) else {}
    message = error.get("message")
    return RunLookup(
        found=True, status=props.get("status"), matched_by=matched_by,
        run_name=run.get("name"), start_time=props.get("startTime"),
        end_time=props.get("endTime"),
        error_code=(error.get("code") or props.get("code")),
        error_message=scrub(str(message))[:300] if message else None,
        candidates=1)


# ---------------------------------------------------------------------------
# The "Check remote status" operation
# ---------------------------------------------------------------------------

#: a run in one of these states proves the request was DELIVERED
DELIVERED_STATES = ("Running", "Waiting", "Succeeded")


class RunStatusService:
    """Responder-only status check for one action.

    It records what Azure said, apart from LogLookup's own action state and
    apart from any downstream effect. It moves an action out of
    ``reconciliation_required`` in just one case: a single run with this
    action's tracking id exists and is Running, Waiting or Succeeded. That
    proves the request arrived (the question the ambiguity was about); it
    does not prove the workflow did the right thing. A Failed, TimedOut or
    Cancelled run might have done part of its work, and a missing run proves
    nothing, so those stay with a person.
    """

    def __init__(self, db: Database, audit: AuditLog, actions: ActionService,
                 policy: ResponsePolicy, client: RunStatusClient | None) -> None:
        self._db, self._audit = db, audit
        self._actions, self._policy, self._client = actions, policy, client

    @property
    def available(self) -> bool:
        return self._client is not None

    async def check(self, user: str, role: str, action_id: str) -> ResponseAction:
        self._policy.require_role(role, "responder")
        action = await self._actions.get(action_id)
        if action.state not in (ActionState.ACKNOWLEDGED, ActionState.COMPLETED,
                                ActionState.RECONCILIATION_REQUIRED):
            raise Conflict("only an action that was sent has a remote run to check "
                           f"(this one is {action.state.value})")
        if self._client is None:
            raise ResponseError(
                "remote status lookup is not set up: add an 'arm' block to the "
                "Logic App auth profile", status=503)
        try:
            found = await self._client.lookup(action.action_id, action.provider_run_id)
        except ConnectorError as exc:
            await self._audit.append(user, "action.remote_status_failed", action_id,
                                     {"error": exc.code})
            raise ResponseError(f"Azure lookup failed ({exc.code})", status=502) from None

        label = found.status or "unresolved"
        note = None
        async with self._db.transaction() as conn:
            fresh = await self._actions.get(action_id)  # state may have moved
            await conn.execute(
                "UPDATE response_actions SET remote_status=?, remote_status_at=?,"
                " remote_run_json=?, provider_run_id=COALESCE(?, provider_run_id),"
                " updated_at=? WHERE action_id=?",
                (label, utcnow(), json.dumps(found.stored()),
                 found.run_name if found.found else None, utcnow(), action_id))
            if (fresh.state == ActionState.RECONCILIATION_REQUIRED
                    and found.found and found.status in DELIVERED_STATES):
                note = ("a single workflow run with this action's tracking id "
                        f"exists ({found.status}); delivery proven, effect not assumed")
                fresh.transitions.append({
                    "at": utcnow(), "by": "system", "from": fresh.state.value,
                    "to": ActionState.ACKNOWLEDGED.value, "note": note})
                moved = await conn.execute(
                    "UPDATE response_actions SET state='acknowledged',"
                    " transitions_json=? WHERE action_id=? AND"
                    " state='reconciliation_required'",
                    (json.dumps(fresh.transitions), action_id))
                if (moved.rowcount or 0):
                    await conn.execute(
                        "UPDATE outbox SET delivery_state='delivered', updated_at=?"
                        " WHERE action_id=?", (utcnow(), action_id))
                else:
                    note = None
            await self._audit.append(
                user, "action.remote_status_checked", action_id,
                {"status": label, "reason": found.reason,
                 "matched_by": found.matched_by, "run": found.run_name,
                 "finalised": bool(note)}, commit=False)
        return await self._actions.get(action_id)
