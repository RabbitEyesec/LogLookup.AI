"""Connection repository: non-secret source definitions."""

from __future__ import annotations

import json
from typing import Any

from engine.connectors.base import SourceConnection
from engine.store.database import Database, utcnow


def _to_conn(r: dict[str, Any]) -> SourceConnection:
    return SourceConnection(
        connection_id=r["connection_id"], provider=r["provider"],
        scope_id=r["scope_id"], name=r["name"], active=bool(r["active"]),
        poll_seconds=r["poll_seconds"], lookback_seconds=r["lookback_seconds"],
        max_page_size=r["max_page_size"], auth_profile_id=r["auth_profile_id"],
        tls_verify=bool(r["tls_verify"]), ca_bundle_path=r["ca_bundle_path"],
        origin=r["origin"], options=json.loads(r["options_json"]),
    )


class ConnectionRepo:
    def __init__(self, db: Database, scope_id: str) -> None:
        self._db, self._scope = db, scope_id

    async def upsert(self, c: SourceConnection, *, keep_state: bool = True) -> None:
        now = utcnow()
        await self._db.execute(
            "INSERT INTO connections (connection_id, scope_id, provider, name,"
            " options_json, auth_profile_id, poll_seconds, lookback_seconds,"
            " max_page_size, tls_verify, ca_bundle_path, active, origin, status,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(connection_id) DO UPDATE SET provider=excluded.provider,"
            " name=excluded.name, options_json=excluded.options_json,"
            " auth_profile_id=excluded.auth_profile_id,"
            " poll_seconds=excluded.poll_seconds,"
            " lookback_seconds=excluded.lookback_seconds,"
            " max_page_size=excluded.max_page_size, tls_verify=excluded.tls_verify,"
            " ca_bundle_path=excluded.ca_bundle_path, origin=excluded.origin,"
            " updated_at=excluded.updated_at"
            + ("" if keep_state else ", active=excluded.active"),
            (c.connection_id, c.scope_id, c.provider, c.name,
             json.dumps(c.options, sort_keys=True), c.auth_profile_id,
             c.poll_seconds, c.lookback_seconds, c.max_page_size,
             1 if c.tls_verify else 0, c.ca_bundle_path, 1 if c.active else 0,
             c.origin, "configured" if c.active else "not_configured", now, now))

    async def get(self, connection_id: str) -> tuple[SourceConnection, bool] | None:
        r = await self._db.fetchone(
            "SELECT * FROM connections WHERE connection_id=? AND scope_id=?",
            (connection_id, self._scope))
        return (_to_conn(r), bool(r["paused"])) if r else None

    async def list(self) -> list[tuple[SourceConnection, bool]]:
        rows = await self._db.fetchall(
            "SELECT * FROM connections WHERE scope_id=? ORDER BY connection_id",
            (self._scope,))
        return [(_to_conn(r), bool(r["paused"])) for r in rows]

    async def set_paused(self, connection_id: str, paused: bool) -> None:
        await self._db.execute(
            "UPDATE connections SET paused=?, updated_at=? WHERE connection_id=?",
            (1 if paused else 0, utcnow(), connection_id))

    async def set_active(self, connection_id: str, active: bool) -> None:
        await self._db.execute(
            "UPDATE connections SET active=?, updated_at=? WHERE connection_id=?",
            (1 if active else 0, utcnow(), connection_id))

    async def delete(self, connection_id: str) -> None:
        await self._db.execute(
            "DELETE FROM connections WHERE connection_id=?", (connection_id,))
