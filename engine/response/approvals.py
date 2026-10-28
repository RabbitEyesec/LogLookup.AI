"""Proposal, approval and rejection of response actions.

Server-side authority only: every method takes an authenticated
:class:`Principal`-like ``(username, role)`` and enforces role rank,
separation of duties, expiry and the state machine itself. Nothing here
trusts a browser to hide a button.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from engine.envelope import canonical_json
from engine.response.audit import AuditLog
from engine.response.models import (
    TERMINAL, ActionState, Conflict, Forbidden, NotFound, ResponseAction,
    ResponseError, TRANSITIONS,
)
from engine.response.outbox import Outbox
from engine.response.policy import ResponsePolicy
from engine.store.database import Database, utcnow

DESTINATION = "logic_apps"


async def current_revision(conn, cluster_id: str) -> int | None:
    """Latest saved investigation revision (following merges), or None when
    the investigation is not stored (legacy chains: nothing to compare)."""
    for _ in range(5):
        async with conn.execute(
            "SELECT latest_revision, merged_into FROM investigations "
            "WHERE cluster_id=?", (cluster_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        if not row["merged_into"]:
            return int(row["latest_revision"])
        cluster_id = row["merged_into"]
    return None


def _row_to_action(r: dict[str, Any]) -> ResponseAction:
    return ResponseAction(
        action_id=r["action_id"], scope_id=r["scope_id"],
        cluster_id=r["cluster_id"], revision=r["revision"],
        workflow_id=r["workflow_id"], requested_by=r["requested_by"],
        payload=json.loads(r["payload_json"]),
        canonical_payload_hash=r["canonical_payload_hash"],
        idempotency_key=r["idempotency_key"], state=ActionState(r["state"]),
        approvals_required=r["approvals_required"],
        approvals=json.loads(r["approvals_json"]),
        rejected_by=r["rejected_by"], rationale=r["rationale"],
        provider_run_id=r["provider_run_id"],
        last_remote_observation=r["last_remote_observation"],
        expires_at=r["expires_at"],
        transitions=json.loads(r["transitions_json"]),
        created_at=r["created_at"], updated_at=r["updated_at"],
        remote_status=r.get("remote_status"),
        remote_status_at=r.get("remote_status_at"),
        remote_run=json.loads(r["remote_run_json"]) if r.get("remote_run_json") else None,
        downstream_effect=r.get("downstream_effect") or "not_observed",
    )


class ActionService:
    def __init__(self, db: Database, policy: ResponsePolicy, audit: AuditLog,
                 outbox: Outbox, *, scope_id: str, dispatch_enabled: bool) -> None:
        self._db = db
        self._policy = policy
        self._audit = audit
        self._outbox = outbox
        self._scope = scope_id
        self._enabled = dispatch_enabled

    # -- reads -------------------------------------------------------------------

    async def get(self, action_id: str) -> ResponseAction:
        row = await self._db.fetchone(
            "SELECT * FROM response_actions WHERE action_id=? AND scope_id=?",
            (action_id, self._scope))
        if row is None:
            raise NotFound(f"action {action_id!r} not found")
        return _row_to_action(row)

    async def list_for(self, cluster_id: str | None = None,
                       limit: int = 200) -> list[ResponseAction]:
        sql, params = "SELECT * FROM response_actions WHERE scope_id=?", [self._scope]
        if cluster_id:
            sql += " AND cluster_id=?"
            params.append(cluster_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [_row_to_action(r) for r in await self._db.fetchall(sql, params)]

    # -- propose -------------------------------------------------------------------

    async def propose(self, user: str, role: str, *, cluster_id: str,
                      revision: int, workflow_id: str, payload: dict[str, Any],
                      evidence_refs: list[str], rationale: str = "") -> ResponseAction:
        self._policy.require_role(role, "analyst")
        if not self._enabled:
            raise ResponseError(
                "the Logic Apps response channel is not enabled", status=503)
        workflow = self._policy.get(workflow_id)
        clean = self._policy.validate_payload(workflow, payload)
        refs = sorted(set(evidence_refs))
        phash = hashlib.sha256(canonical_json(
            {"w": workflow_id, "p": clean, "e": refs})).hexdigest()
        idem = hashlib.sha256("|".join(
            (self._scope, DESTINATION, workflow_id, cluster_id, str(revision),
             phash)).encode()).hexdigest()
        now = utcnow()
        action_id = str(uuid.uuid4())
        expires = (datetime.now(timezone.utc)
                   + timedelta(seconds=workflow.ttl_seconds)
                   ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        transitions = [
            {"at": now, "by": user, "from": None, "to": "proposed"},
            {"at": now, "by": user, "from": "proposed", "to": "approval_required"},
        ]
        try:
            async with self._db.transaction() as conn:
                await conn.execute(
                    "INSERT INTO response_actions (action_id, scope_id, cluster_id,"
                    " revision, workflow_id, requested_by, approvals_json,"
                    " approvals_required, rationale, payload_json,"
                    " canonical_payload_hash, idempotency_key, state, expires_at,"
                    " transitions_json, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?, '[]', ?,?,?,?,?, 'approval_required',?,?,?,?)",
                    (action_id, self._scope, cluster_id, revision, workflow_id, user,
                     workflow.approvals_required, rationale,
                     json.dumps({"fields": clean, "evidence_refs": refs},
                                sort_keys=True), phash, idem, expires,
                     json.dumps(transitions), now, now))
                await self._audit.append(
                    user, "action.proposed", action_id,
                    {"cluster_id": cluster_id, "revision": revision,
                     "workflow_id": workflow_id, "payload_hash": phash,
                     "evidence_refs": refs}, commit=False)
        except sqlite3.IntegrityError:
            raise Conflict(
                "an identical action for this investigation revision is "
                "already pending, in flight or delivered") from None
        return await self.get(action_id)

    # -- approve / reject ------------------------------------------------------------

    async def approve(self, user: str, role: str, action_id: str,
                      rationale: str = "") -> ResponseAction:
        self._policy.require_role(role, "responder")
        refusal = None
        async with self._db.transaction() as conn:
            action = await self._load_locked(action_id)
            self._ensure_open(action)
            if await self._expire_if_due(action):
                refusal = "action has expired and can no longer be approved"
            elif await self._expire_if_stale(conn, action):
                # The investigation moved on after this was proposed. A person
                # must look at the current evidence and propose again.
                refusal = ("the investigation changed after this action was "
                           "proposed; review the current evidence and propose "
                           "it again")
            else:
                workflow = self._policy.get(action.workflow_id)
                if workflow.separation_of_duties and user == action.requested_by:
                    raise Forbidden(
                        "separation of duties: the requester cannot approve "
                        "this action")
                if any(a["by"] == user for a in action.approvals):
                    raise Conflict("you have already approved this action")
                now = utcnow()
                action.approvals.append(
                    {"by": user, "at": now, "rationale": rationale})
                enough = len(action.approvals) >= action.approvals_required
                if enough:
                    self._move(action, ActionState.APPROVED, user,
                               "approval threshold met")
                    self._move(action, ActionState.QUEUED, "system",
                               "queued for dispatch")
                await conn.execute(
                    "UPDATE response_actions SET approvals_json=?, state=?,"
                    " transitions_json=?, updated_at=? WHERE action_id=? AND state=?",
                    (json.dumps(action.approvals), action.state.value,
                     json.dumps(action.transitions), now, action_id,
                     ActionState.APPROVAL_REQUIRED.value))
                if enough:
                    await self._outbox.enqueue(
                        conn, action_id, action.idempotency_key, DESTINATION,
                        self._contract(action, user))
                await self._audit.append(
                    user, "action.approved", action_id,
                    {"approvals": len(action.approvals),
                     "required": action.approvals_required, "queued": enough,
                     "payload_hash": action.canonical_payload_hash}, commit=False)
        if refusal:
            raise Conflict(refusal)
        return await self.get(action_id)

    async def reject(self, user: str, role: str, action_id: str,
                     rationale: str = "") -> ResponseAction:
        self._policy.require_role(role, "responder")
        async with self._db.transaction() as conn:
            action = await self._load_locked(action_id)
            if action.state != ActionState.APPROVAL_REQUIRED:
                raise Conflict(
                    f"only pending actions can be rejected (state: {action.state.value})")
            self._move(action, ActionState.REJECTED, user, rationale or "rejected")
            await conn.execute(
                "UPDATE response_actions SET state=?, rejected_by=?, rationale=?,"
                " transitions_json=?, updated_at=? WHERE action_id=?",
                (action.state.value, user, rationale, json.dumps(action.transitions),
                 utcnow(), action_id))
            await self._audit.append(user, "action.rejected", action_id,
                                     {"rationale": rationale}, commit=False)
        return await self.get(action_id)

    async def cancel(self, user: str, role: str, action_id: str) -> ResponseAction:
        action = await self.get(action_id)
        if user != action.requested_by:
            self._policy.require_role(role, "responder")
        async with self._db.transaction() as conn:
            action = await self._load_locked(action_id)
            if action.state not in (ActionState.APPROVAL_REQUIRED,
                                    ActionState.APPROVED, ActionState.QUEUED):
                raise Conflict(f"cannot cancel an action in state {action.state.value}")
            if action.state == ActionState.QUEUED:
                await conn.execute(
                    "UPDATE outbox SET delivery_state='cancelled', updated_at=? "
                    "WHERE action_id=? AND delivery_state='queued'",
                    (utcnow(), action_id))
            self._move(action, ActionState.CANCELLED, user, "cancelled")
            await conn.execute(
                "UPDATE response_actions SET state=?, transitions_json=?, updated_at=?"
                " WHERE action_id=?", (action.state.value,
                                       json.dumps(action.transitions), utcnow(),
                                       action_id))
            await self._audit.append(user, "action.cancelled", action_id, {},
                                     commit=False)
        return await self.get(action_id)

    # -- internals -----------------------------------------------------------------

    async def _load_locked(self, action_id: str) -> ResponseAction:
        async with self._db.conn.execute(
            "SELECT * FROM response_actions WHERE action_id=? AND scope_id=?",
            (action_id, self._scope)) as cur:
            row = await cur.fetchone()
        if row is None:
            raise NotFound(f"action {action_id!r} not found")
        return _row_to_action(dict(row))

    @staticmethod
    def _ensure_open(action: ResponseAction) -> None:
        if action.state != ActionState.APPROVAL_REQUIRED:
            raise Conflict(
                f"action is {action.state.value}; only pending actions can be approved")

    async def _expire_if_due(self, action: ResponseAction) -> bool:
        if action.expires_at and action.expires_at < utcnow():
            self._move(action, ActionState.EXPIRED, "system", "time-to-live elapsed")
            await self._db.conn.execute(
                "UPDATE response_actions SET state=?, transitions_json=?,"
                " updated_at=? WHERE action_id=?",
                (action.state.value, json.dumps(action.transitions), utcnow(),
                 action.action_id))
            await self._audit.append("system", "action.expired", action.action_id,
                                     {}, commit=False)
            return True
        return False

    async def _expire_if_stale(self, conn, action: ResponseAction) -> bool:
        latest = await current_revision(conn, action.cluster_id)
        if latest is None or latest == action.revision:
            return False
        note = (f"investigation moved from revision {action.revision} to {latest} "
                "before approval")
        self._move(action, ActionState.EXPIRED, "system", note)
        await conn.execute(
            "UPDATE response_actions SET state=?, transitions_json=?, updated_at=?"
            " WHERE action_id=?", (action.state.value,
                                   json.dumps(action.transitions), utcnow(),
                                   action.action_id))
        await self._audit.append("system", "action.superseded", action.action_id,
                                 {"proposed_on": action.revision, "current": latest},
                                 commit=False)
        return True

    @staticmethod
    def _move(action: ResponseAction, new: ActionState, by: str, note: str) -> None:
        if new not in TRANSITIONS.get(action.state, frozenset()):
            raise Conflict(f"illegal transition {action.state.value} -> {new.value}")
        action.transitions.append({"at": utcnow(), "by": by,
                                   "from": action.state.value, "to": new.value,
                                   "note": note})
        action.state = new

    @staticmethod
    def _contract(action: ResponseAction, approved_by: str) -> dict[str, Any]:
        """Outbound workflow contract (docs/v2/logic-apps-contract.md)."""
        return {
            "schema_version": "2.0",
            "workflow_id": action.workflow_id,
            "action_id": action.action_id,
            "idempotency_key": action.idempotency_key,
            "cluster_id": action.cluster_id,
            "investigation_revision": action.revision,
            "scope_id": action.scope_id,
            "requested_by": action.requested_by,
            "approved_by": [a["by"] for a in action.approvals],
            "approved_at": action.approvals[-1]["at"],
            "evidence_refs": action.payload.get("evidence_refs", []),
            "requested_operation": None,  # filled by dispatcher from policy
            "payload": action.payload.get("fields", {}),
        }

    def is_terminal(self, action: ResponseAction) -> bool:
        return action.state in TERMINAL
