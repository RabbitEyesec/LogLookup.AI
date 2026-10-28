"""Durable correlation work queue (``ingest_work_items``).

States: ``pending`` -> ``claimed`` -> ``processed``; a failed attempt becomes
``failed_retryable`` with backoff and, after ``MAX_ATTEMPTS``, ``quarantined``
(visible, never silently dropped). ``superseded`` marks a newer revision of an
alert that is already queued/correlated - recorded, never a second detection.

A consumer that dies mid-item leaves it ``claimed``; the lease (or the
startup recovery) makes it claimable again, and correlation intake is
idempotent per canonical event, so reprocessing cannot inflate a chain.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from engine.envelope import SourceEnvelope
from engine.store.database import Database, utcnow
from engine.store.evidence import EvidenceVault
from engine.store.ledger import _env_from_dict

MAX_ATTEMPTS = 8
LEASE_SECONDS = 120
_TS = "%Y-%m-%dT%H:%M:%S.%fZ"


def _later(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(_TS)


class WorkQueue:
    def __init__(self, db: Database, vault: EvidenceVault) -> None:
        self._db, self._vault = db, vault

    async def recover_claimed(self) -> int:
        """Startup: items claimed by the previous (now dead) process."""
        async with self._db.transaction() as conn:
            cur = await conn.execute(
                "UPDATE ingest_work_items SET state='pending', lease_until=NULL "
                "WHERE state='claimed'")
        return cur.rowcount or 0

    async def claim_batch(self, limit: int = 100,
                          lease_seconds: int = LEASE_SECONDS) -> list[dict[str, Any]]:
        now = utcnow()
        lease = _later(lease_seconds)
        async with self._db.transaction() as conn:
            async with conn.execute(
                "SELECT canonical_event_id, revision, operation, connection_id "
                "FROM ingest_work_items WHERE "
                "(state IN ('pending','failed_retryable') AND next_attempt_at <= ?) "
                "OR (state='claimed' AND lease_until < ?) "
                "ORDER BY created_at LIMIT ?", (now, now, limit)) as cur:
                rows = [dict(r) for r in await cur.fetchall()]
            for r in rows:
                await conn.execute(
                    "UPDATE ingest_work_items SET state='claimed', lease_until=?,"
                    " attempts=attempts+1 WHERE canonical_event_id=? AND revision=?"
                    " AND operation=?",
                    (lease, r["canonical_event_id"], r["revision"], r["operation"]))
        items = []
        for r in rows:
            snap = await self._db.fetchone(
                "SELECT encrypted_payload, envelope_json FROM source_event_revisions"
                " WHERE canonical_event_id=? AND revision=?",
                (r["canonical_event_id"], r["revision"]))
            items.append({**r, "snapshot": snap})
        return items

    def open_item(self, item: dict[str, Any]) -> tuple[SourceEnvelope, dict[str, Any]]:
        """Decrypt a claimed item's immutable payload."""
        snap = item["snapshot"]
        if snap is None or snap["encrypted_payload"] is None:
            raise LookupError("revision payload is no longer stored")
        env = _env_from_dict(json.loads(snap["envelope_json"]))
        payload = self._vault.open(
            snap["encrypted_payload"],
            f"ledger:{item['canonical_event_id']}:{item['revision']}",
            env.raw_sha256)
        return env, payload

    async def ack(self, item: dict[str, Any]) -> None:
        now = utcnow()
        async with self._db.transaction() as conn:
            await conn.execute(
                "UPDATE ingest_work_items SET state='processed', processed_at=?,"
                " lease_until=NULL, last_error_code=NULL WHERE canonical_event_id=?"
                " AND revision=? AND operation=?",
                (now, item["canonical_event_id"], item["revision"], item["operation"]))
            await conn.execute(
                "UPDATE processed_observations SET state='correlated', "
                "processed_at=? WHERE canonical_event_id=? AND source_revision=?",
                (now, item["canonical_event_id"], item["revision"]))

    async def fail(self, item: dict[str, Any], code: str) -> str:
        """Record a failed attempt; returns the new state."""
        row = await self._db.fetchone(
            "SELECT attempts FROM ingest_work_items WHERE canonical_event_id=? AND"
            " revision=? AND operation=?",
            (item["canonical_event_id"], item["revision"], item["operation"]))
        attempts = int(row["attempts"]) if row else MAX_ATTEMPTS
        state = "quarantined" if attempts >= MAX_ATTEMPTS else "failed_retryable"
        backoff = min(300.0, 2.0 ** attempts)
        async with self._db.transaction() as conn:
            await conn.execute(
                "UPDATE ingest_work_items SET state=?, last_error_code=?,"
                " next_attempt_at=?, lease_until=NULL WHERE canonical_event_id=? AND"
                " revision=? AND operation=?",
                (state, code[:80], _later(backoff), item["canonical_event_id"],
                 item["revision"], item["operation"]))
            if state == "quarantined":
                await conn.execute(
                    "UPDATE processed_observations SET state='quarantined', "
                    "detail=? WHERE canonical_event_id=? AND source_revision=?",
                    (code[:80], item["canonical_event_id"], item["revision"]))
        return state

    async def stats(self, connection_id: str | None = None) -> dict[str, Any]:
        """Counts per state plus the age of the oldest unfinished item."""
        where, params = "", ()
        if connection_id:
            where, params = " WHERE connection_id=?", (connection_id,)
        rows = await self._db.fetchall(
            "SELECT state, COUNT(*) AS n FROM ingest_work_items" + where
            + " GROUP BY state", params)
        counts = {r["state"]: int(r["n"]) for r in rows}
        open_sql = ("SELECT MIN(created_at) AS oldest FROM ingest_work_items WHERE "
                    "state IN ('pending','claimed','failed_retryable')")
        if connection_id:
            open_sql += " AND connection_id=?"
        oldest = await self._db.fetchone(open_sql, params)
        age = None
        if oldest and oldest["oldest"]:
            created = datetime.strptime(oldest["oldest"], _TS).replace(
                tzinfo=timezone.utc)
            age = max(0.0, (datetime.now(timezone.utc) - created).total_seconds())
        pending = sum(counts.get(k, 0) for k in
                      ("pending", "claimed", "failed_retryable"))
        return {"by_state": counts, "pending_correlation_items": pending,
                "oldest_pending_age_seconds": age,
                "quarantined": counts.get("quarantined", 0)}
