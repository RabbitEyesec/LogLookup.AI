"""Outbox dispatcher: sends approved actions, never repeats ambiguous ones."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any, Protocol

from engine.response.audit import AuditLog
from engine.response.approvals import _row_to_action
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

    async def recover(self) -> int:
        """Startup: anything caught mid-send becomes reconciliation-required."""
        stuck = await self._outbox.interrupted()
        unknown = 0
        for action_id in stuck:
            row = await self._db.fetchone(
                "SELECT state FROM response_actions WHERE action_id=?",
                (action_id,))
            if row is not None and row["state"] == ActionState.QUEUED.value:
                # Claimed but the 'dispatching' state was never recorded:
                # the request cannot have been sent, so it is safe to requeue.
                await self._outbox.finish(action_id, "queued", "")
                continue
            unknown += 1
            await self._settle(
                action_id, ActionState.RECONCILIATION_REQUIRED, "system",
                note="process stopped during dispatch; delivery unknown",
                outbox_state="reconciliation_required")
        if unknown:
            logger.warning("%d interrupted dispatch(es) require reconciliation",
                           unknown)
        return unknown

    async def run_once(self) -> bool:
        """Dispatch at most one queued action; True if one was processed."""
        if self._transport is None:
            return False
        item = await self._outbox.claim_next()
        if item is None:
            return False
        action_id = item["action_id"]
        row = await self._db.fetchone(
            "SELECT * FROM response_actions WHERE action_id=?", (action_id,))
        action = _row_to_action(row)
        if action.expires_at and action.expires_at < utcnow():
            await self._settle_from(action, ActionState.EXPIRED, "system",
                                    "expired before dispatch",
                                    outbox_state="expired")
            return True
        # queued -> dispatching is recorded before the network call, and only
        # if the action is STILL queued: a cancel that landed after the claim
        # must win, otherwise a cancelled action would be sent.
        if not await self._set_state(action, ActionState.DISPATCHING, "system",
                                     "sending", expect=ActionState.QUEUED):
            await self._outbox.finish(action_id, "cancelled",
                                      "no longer queued at dispatch time")
            return True
        contract = dict(item["payload"])
        contract["requested_operation"] = self._policy.get(
            action.workflow_id).operation
        try:
            result = await self._transport.send(contract)
        except Exception as exc:  # transport bug: treat as unknown, not retried
            logger.exception("dispatch raised for %s", action_id)
            result = DispatchResult("unknown", detail=type(exc).__name__)
        await self._record_result(action_id, result)
        return True

    async def _record_result(self, action_id: str, r: DispatchResult) -> None:
        action = _row_to_action(await self._db.fetchone(
            "SELECT * FROM response_actions WHERE action_id=?", (action_id,)))
        if r.outcome == "accepted":
            state, ob = ActionState.ACKNOWLEDGED, "delivered"
        elif r.outcome == "rejected":
            state, ob = ActionState.FAILED_WITHOUT_EFFECT, "failed"
        else:
            state, ob = ActionState.RECONCILIATION_REQUIRED, "reconciliation_required"
        await self._settle_from(action, state, "system", r.detail or r.outcome,
                                outbox_state=ob, run_id=r.run_id,
                                observation=f"http={r.http_status} {r.detail}"[:300])

    async def _settle(self, action_id: str, state: ActionState, by: str, *,
                      note: str, outbox_state: str) -> None:
        row = await self._db.fetchone(
            "SELECT * FROM response_actions WHERE action_id=?", (action_id,))
        if row is None:
            return
        await self._settle_from(_row_to_action(row), state, by, note,
                                outbox_state=outbox_state)

    async def _settle_from(self, action, state, by, note, *, outbox_state,
                           run_id=None, observation=None) -> None:
        if state not in TRANSITIONS.get(action.state, frozenset()):
            logger.error("refusing illegal transition %s -> %s for %s",
                         action.state.value, state.value, action.action_id)
            return
        await self._set_state(action, state, by, note, run_id=run_id,
                              observation=observation)
        await self._outbox.finish(action.action_id, outbox_state, note)

    async def _set_state(self, action, state, by, note, *, run_id=None,
                         observation=None,
                         expect: ActionState | None = None) -> bool:
        """Persist a transition; with ``expect`` it only applies if the row is
        still in that state. Returns whether it applied."""
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
