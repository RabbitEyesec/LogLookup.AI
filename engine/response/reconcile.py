"""Reconciliation of ambiguous deliveries.

An action in ``reconciliation_required`` is never resent. An authorised
human (or a status lookup wired in later) records what actually happened to
the *original* request, identified by ``action_id`` / workflow run
reference, and the action moves to a definitive state.
"""

from __future__ import annotations

import json

from engine.response.approvals import ActionService, _row_to_action
from engine.response.audit import AuditLog
from engine.response.models import ActionState, Conflict, ResponseAction, TRANSITIONS
from engine.store.database import Database, utcnow

OUTCOMES = ("delivered", "not_delivered")


class Reconciler:
    def __init__(self, db: Database, audit: AuditLog, service: ActionService,
                 policy) -> None:
        self._db, self._audit, self._service, self._policy = db, audit, service, policy

    async def resolve(self, user: str, role: str, action_id: str, outcome: str,
                      *, run_id: str | None = None, note: str = "") -> ResponseAction:
        self._policy.require_role(role, "responder")
        if outcome not in OUTCOMES:
            raise Conflict(f"outcome must be one of {list(OUTCOMES)}")
        action = await self._service.get(action_id)
        if action.state != ActionState.RECONCILIATION_REQUIRED:
            raise Conflict(
                f"action is {action.state.value}; nothing to reconcile")
        new = (ActionState.ACKNOWLEDGED if outcome == "delivered"
               else ActionState.FAILED_WITHOUT_EFFECT)
        assert new in TRANSITIONS[action.state]
        action.transitions.append({"at": utcnow(), "by": user,
                                   "from": action.state.value, "to": new.value,
                                   "note": f"reconciled: {outcome}. {note}".strip()})
        async with self._db.transaction() as conn:
            await conn.execute(
                "UPDATE response_actions SET state=?, transitions_json=?,"
                " provider_run_id=COALESCE(?, provider_run_id),"
                " last_remote_observation=?, updated_at=? WHERE action_id=?",
                (new.value, json.dumps(action.transitions), run_id,
                 f"reconciled by {user}: {outcome}", utcnow(), action_id))
            await conn.execute(
                "UPDATE outbox SET delivery_state=?, updated_at=? WHERE action_id=?",
                ("delivered" if outcome == "delivered" else "failed", utcnow(),
                 action_id))
            await self._audit.append(user, "action.reconciled", action_id,
                                     {"outcome": outcome, "run_id": run_id,
                                      "note": note}, commit=False)
        return await self._service.get(action_id)
