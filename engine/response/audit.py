"""Append-only, hash-chained audit trail for human and system decisions."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from engine.store.database import Database, utcnow

GENESIS = "0" * 64


def _entry_hash(prev: str, ts: str, actor: str, action: str, target: str,
                detail: str) -> str:
    return hashlib.sha256(
        "\x1f".join((prev, ts, actor, action, target, detail)).encode()
    ).hexdigest()


class AuditLog:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._lock = asyncio.Lock()

    async def append(self, actor: str, action: str, target: str,
                     detail: dict[str, Any] | None = None, *,
                     commit: bool = True) -> int:
        """Append one entry. Pass ``commit=False`` from inside an open
        ``db.transaction()`` so the audit row and the state change it records
        land atomically; the default opens its own transaction."""
        if commit:
            async with self._db.transaction() as conn:
                return await self._append(conn, actor, action, target, detail)
        return await self._append(self._db.conn, actor, action, target, detail)

    async def _append(self, conn, actor, action, target, detail) -> int:
        async with self._lock:
            async with conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ) as cur:
                row = await cur.fetchone()
            prev = row["entry_hash"] if row else GENESIS
            ts = utcnow()
            body = json.dumps(detail or {}, sort_keys=True, default=str)
            digest = _entry_hash(prev, ts, actor, action, target, body)
            cur = await conn.execute(
                "INSERT INTO audit_events (ts, actor, action, target, detail_json,"
                " prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, target, body, prev, digest),
            )
            return int(cur.lastrowid)

    async def list(self, *, target: str | None = None, limit: int = 200,
                   before_seq: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        clauses, params = [], []
        if target:
            clauses.append("target=?")
            params.append(target)
        if before_seq:
            clauses.append("seq<?")
            params.append(before_seq)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        rows = await self._db.fetchall(sql, params)
        for r in rows:
            r["detail"] = json.loads(r.pop("detail_json"))
        return rows

    async def verify(self) -> dict[str, Any]:
        """Re-walk the chain; reports the first broken entry, if any."""
        rows = await self._db.fetchall("SELECT * FROM audit_events ORDER BY seq")
        prev = GENESIS
        for r in rows:
            expected = _entry_hash(prev, r["ts"], r["actor"], r["action"],
                                   r["target"], r["detail_json"])
            if r["prev_hash"] != prev or r["entry_hash"] != expected:
                return {"valid": False, "broken_at": r["seq"], "entries": len(rows)}
            prev = r["entry_hash"]
        return {"valid": True, "broken_at": None, "entries": len(rows)}
