"""Outbox dispatcher: sends approved actions, never repeats ambiguous ones."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any, Protocol

from engine.response.audit import AuditLog
from engine.response.approvals import _row_to_action, current_revision
from engine.response.models import ActionState, DispatchResult, TRANSITIONS
from engine.response.outbox import Outbox
from engine.response.policy import ResponsePolicy
from engine.store.database import Database, utcnow

logger = logging.getLogger(__name__)


class Transport(Protocol):
    async def send(self, contract: dict[str, Any]) -> DispatchResult: ...


class Dispatcher:
    def __init__(self, db: Database, outbox: Outbox, transport: Transport | None,
                 audit: AuditLog, policy: ResponsePolicy, *,
                 interval: float = 2.0) -> None:
        self._db, self._outbox, self._transport = db, outbox, transport
        self._audit, self._policy = audit, policy
        self._interval = interval
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    #: outbox label that mirrors each terminal action state
    _OUTBOX_FOR = {
        ActionState.ACKNOWLEDGED: "delivered", ActionState.COMPLETED: "delivered",
        ActionState.FAILED_WITHOUT_EFFECT: "failed",
        ActionState.RECONCILIATION_REQUIRED: "reconciliation_required",
        ActionState.EXPIRED: "expired", ActionState.CANCELLED: "cancelled",
        ActionState.REJECTED: "cancelled",
    }

    async def recover(self) -> int:
        """Startup: reconcile every open outbox row against the action's REAL
        persisted state. Never resends; returns how many need an operator.

        =========================  ==========================================
        action state               what recovery does
        =========================  ==========================================
        queued                     outbox -> queued (nothing was sent)
        dispatching                action -> reconciliation_required (unknown)
        terminal (any)             repair the outbox label only
        approval_required/other    flag the outbox row ``inconsistent``
        =========================  ==========================================
        """
        needs_operator = 0
        for row in await self._outbox.unsettled():
            action_id = row["action_id"]
            record = await self._db.fetchone(
                "SELECT * FROM response_actions WHERE action_id=?", (action_id,))
            if record is None:
                await self._outbox.finish(action_id, "inconsistent",
                                          "no matching action")
                needs_operator += 1
                continue
            action = _row_to_action(record)
            if action.state == ActionState.QUEUED:
                if row["delivery_state"] == "dispatching":
                    await self._outbox.finish(action_id, "queued", "")
                continue
            if action.state == ActionState.DISPATCHING:
                needs_operator += 1
                await self._settle_from(
                    action, ActionState.RECONCILIATION_REQUIRED, "system",
                    "process stopped during dispatch; delivery unknown")
                continue
            label = self._OUTBOX_FOR.get(action.state)
            if label is not None:
                async with self._db.transaction() as conn:
                    await self._outbox.set_state_in(
                        conn, action_id, label, f"repaired after restart "
                        f"(action {action.state.value})")
                    await self._audit.append(
                        "system", "outbox.repaired", action_id,
                        {"action_state": action.state.value, "outbox": label},
                        commit=False)
                continue
            needs_operator += 1
            await self._outbox.finish(
                action_id, "inconsistent",
                f"action is {action.state.value}; not dispatchable")
        if needs_operator:
            logger.warning("%d outbox row(s) need operator reconciliation",
                           needs_operator)
        return needs_operator

    async def _claim(self) -> tuple[Any, dict[str, Any]] | None:
        """Atomically take the next queued item AND move its action to
        ``dispatching`` (one transaction, compare-and-set on both rows), so a
        crash or a racing cancel can never leave the pair disagreeing."""
        async with self._db.transaction() as conn:
            while True:
                async with conn.execute(
                    "SELECT * FROM outbox WHERE delivery_state='queued' "
                    "ORDER BY created_at LIMIT 1") as cur:
                    row = await cur.fetchone()
                if row is None:
                    return None
                item = dict(row)
                async with conn.execute(
                    "SELECT * FROM response_actions WHERE action_id=?",
                    (item["action_id"],)) as cur:
                    rec = await cur.fetchone()
                action = _row_to_action(dict(rec)) if rec else None
                if action is None or action.state != ActionState.QUEUED:
                    # cancelled/expired after queueing: nothing to send
                    await self._outbox.set_state_in(
                        conn, item["action_id"], "cancelled",
                        "no longer queued at dispatch time", expect="queued")
                    continue
                # Not sent if it ran out of time, or if the investigation
                # moved on since a person approved it. (An action already
                # dispatching is never touched here.)
                why = None
                if action.expires_at and action.expires_at < utcnow():
                    why = "expired before dispatch"
                else:
                    latest = await current_revision(conn, action.cluster_id)
                    if latest is not None and latest != action.revision:
                        why = (f"investigation moved from revision "
                               f"{action.revision} to {latest} before dispatch")
                if why:
                    action.transitions.append({
                        "at": utcnow(), "by": "system", "from": "queued",
                        "to": "expired", "note": why})
                    await conn.execute(
                        "UPDATE response_actions SET state='expired',"
                        " transitions_json=?, updated_at=? WHERE action_id=?"
                        " AND state='queued'",
                        (json.dumps(action.transitions), utcnow(), action.action_id))
                    await self._outbox.set_state_in(
                        conn, action.action_id, "expired", why, expect="queued")
                    await self._audit.append("system", "action.expired",
                                             action.action_id, {"note": why},
                                             commit=False)
                    continue
                action.transitions.append({
                    "at": utcnow(), "by": "system", "from": "queued",
                    "to": "dispatching", "note": "sending"})
                moved = await conn.execute(
                    "UPDATE response_actions SET state='dispatching',"
                    " transitions_json=?, updated_at=? WHERE action_id=?"
                    " AND state='queued'",
                    (json.dumps(action.transitions), utcnow(), action.action_id))
                if (moved.rowcount or 0) == 0:
                    continue
                await conn.execute(
                    "UPDATE outbox SET delivery_state='dispatching',"
                    " attempts=attempts+1, updated_at=? WHERE action_id=?",
                    (utcnow(), action.action_id))
                await self._audit.append("system", "action.dispatching",
                                         action.action_id, {"note": "sending"},
                                         commit=False)
                action.state = ActionState.DISPATCHING
                item["payload"] = json.loads(item.pop("payload_json"))
                return action, item

    async def run_once(self) -> bool:
        """Dispatch at most one queued action; True if one was processed."""
        if self._transport is None:
            return False
        claimed = await self._claim()
        if claimed is None:
            return False
        action, item = claimed
        contract = dict(item["payload"])
        contract["requested_operation"] = self._policy.get(
            action.workflow_id).operation
        try:
            result = await self._transport.send(contract)
        except Exception as exc:  # transport bug: treat as unknown, not retried
            logger.exception("dispatch raised for %s", action.action_id)
            result = DispatchResult("unknown", detail=type(exc).__name__)
        await self._record_result(action.action_id, result)
        return True

    async def _record_result(self, action_id: str, r: DispatchResult) -> None:
        action = _row_to_action(await self._db.fetchone(
            "SELECT * FROM response_actions WHERE action_id=?", (action_id,)))
        if r.outcome == "accepted":
            state = ActionState.ACKNOWLEDGED
        elif r.outcome == "rejected":
            state = ActionState.FAILED_WITHOUT_EFFECT
        else:
            state = ActionState.RECONCILIATION_REQUIRED
        await self._settle_from(action, state, "system", r.detail or r.outcome,
                                run_id=r.run_id,
                                observation=f"http={r.http_status} {r.detail}"[:300])

    async def _settle_from(self, action, state, by, note, *, run_id=None,
                           observation=None) -> bool:
        """Move the action to ``state`` and mirror it onto the outbox row and
        the audit trail in ONE transaction, compare-and-set on the action's
        current state. Returns whether it applied."""
        if state not in TRANSITIONS.get(action.state, frozenset()):
            logger.error("refusing illegal transition %s -> %s for %s",
                         action.state.value, state.value, action.action_id)
            return False
        return await self._set_state(
            action, state, by, note, run_id=run_id, observation=observation,
            expect=action.state, outbox_state=self._OUTBOX_FOR[state])

    async def _set_state(self, action, state, by, note, *, run_id=None,
                         observation=None, expect: ActionState | None = None,
                         outbox_state: str | None = None) -> bool:
        """Persist a transition; with ``expect`` it only applies if the row is
        still in that state. ``outbox_state`` is written in the same
        transaction. Returns whether it applied."""
        previous = action.state
        transitions = action.transitions + [{
            "at": utcnow(), "by": by, "from": previous.value,
            "to": state.value, "note": note}]
        async with self._db.transaction() as conn:
            cur = await conn.execute(
                "UPDATE response_actions SET state=?, transitions_json=?,"
                " provider_run_id=COALESCE(?, provider_run_id),"
                " last_remote_observation=COALESCE(?, last_remote_observation),"
                " updated_at=? WHERE action_id=? AND (? IS NULL OR state=?)",
                (state.value, json.dumps(transitions), run_id, observation,
                 utcnow(), action.action_id,
                 expect.value if expect else None,
                 expect.value if expect else None))
            if cur.rowcount == 0:
                return False
            if outbox_state is not None:
                await self._outbox.set_state_in(
                    conn, action.action_id, outbox_state, note)
            await self._audit.append(by, f"action.{state.value}", action.action_id,
                                     {"note": note, "run_id": run_id}, commit=False)
        action.transitions = transitions
        action.state = state
        return True

    # -- loop ------------------------------------------------------------------------

    async def start(self) -> None:
        await self.recover()
        self._stop.clear()
        self._task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                worked = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("dispatcher cycle failed")
                worked = False
            if not worked:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), self._interval)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
