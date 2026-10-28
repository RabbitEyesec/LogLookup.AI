"""Durable dispatch outbox.

``claim_next`` flips ``queued -> dispatching`` before any network call. If
the process dies mid-send, ``recover_interrupted`` moves those rows to
reconciliation: after a crash we cannot know whether the request left the
machine, so it is NEVER re-sent automatically.
"""

from __future__ import annotations

import json
from typing import Any

from engine.store.database import Database, utcnow


class Outbox:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def enqueue(self, conn, action_id: str, idempotency_key: str,
                      destination: str, payload: dict[str, Any]) -> None:
        now = utcnow()
        await conn.execute(
            "INSERT INTO outbox (action_id, idempotency_key, destination,"
            " payload_json, delivery_state, created_at, updated_at) "
            "VALUES (?,?,?,?, 'queued', ?, ?)",
            (action_id, idempotency_key, destination,
             json.dumps(payload, sort_keys=True), now, now),
        )

    async def claim_next(self) -> dict[str, Any] | None:
        async with self._db.transaction() as conn:
            async with conn.execute(
                "SELECT * FROM outbox WHERE delivery_state='queued' "
                "ORDER BY created_at LIMIT 1"
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                return None
            await conn.execute(
                "UPDATE outbox SET delivery_state='dispatching', attempts=attempts+1,"
                " updated_at=? WHERE action_id=?", (utcnow(), row["action_id"]))
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        return item

    async def finish(self, action_id: str, state: str, error: str = "") -> None:
        await self._db.execute(
            "UPDATE outbox SET delivery_state=?, last_error=?, updated_at=? "
            "WHERE action_id=?", (state, error[:300], utcnow(), action_id))

    async def interrupted(self) -> list[str]:
        rows = await self._db.fetchall(
            "SELECT action_id FROM outbox WHERE delivery_state='dispatching'")
        return [r["action_id"] for r in rows]

    async def backlog(self) -> dict[str, int]:
        rows = await self._db.fetchall(
            "SELECT delivery_state, COUNT(*) AS n FROM outbox GROUP BY delivery_state")
        return {r["delivery_state"]: int(r["n"]) for r in rows}
