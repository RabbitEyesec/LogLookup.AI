"""Per-source, per-stream cursor persistence."""

from __future__ import annotations

import json
from typing import Any

from engine.store.database import Database, utcnow


class CursorStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def get(self, connection_id: str, stream: str) -> dict[str, Any] | None:
        row = await self._db.fetchone(
            "SELECT cursor_json FROM source_cursors "
            "WHERE connection_id=? AND stream_name=?",
            (connection_id, stream),
        )
        return json.loads(row["cursor_json"]) if row else None

    async def all_for(self, connection_id: str) -> dict[str, dict[str, Any]]:
        rows = await self._db.fetchall(
            "SELECT stream_name, cursor_json, window_complete, committed_at "
            "FROM source_cursors WHERE connection_id=?", (connection_id,),
        )
        return {
            r["stream_name"]: {
                "cursor": json.loads(r["cursor_json"]),
                "window_complete": bool(r["window_complete"]),
                "committed_at": r["committed_at"],
            }
            for r in rows
        }

    async def reset(self, connection_id: str, stream: str | None = None) -> None:
        if stream is None:
            await self._db.execute(
                "DELETE FROM source_cursors WHERE connection_id=?", (connection_id,)
            )
        else:
            await self._db.execute(
                "DELETE FROM source_cursors WHERE connection_id=? AND stream_name=?",
                (connection_id, stream),
            )


def upsert_cursor_sql() -> str:
    return (
        "INSERT INTO source_cursors (connection_id, stream_name, cursor_json, "
        "window_complete, committed_at) VALUES (?,?,?,?,?) "
        "ON CONFLICT(connection_id, stream_name) DO UPDATE SET "
        "cursor_json=excluded.cursor_json, window_complete=excluded.window_complete, "
        "committed_at=excluded.committed_at"
    )


__all__ = ["CursorStore", "upsert_cursor_sql", "utcnow"]
