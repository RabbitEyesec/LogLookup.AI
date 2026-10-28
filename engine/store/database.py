"""SQLite connection management: WAL, busy timeout, owner-only file."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import aiosqlite

from engine.store.migrations import LATEST_VERSION, MIGRATIONS

logger = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = 5000


class StoreError(Exception):
    """Raised for durable-store failures."""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Database:
    """One writer connection per application home.

    A single SQLite writer is a deliberate v2 deployment boundary: do not
    point two LogLookup processes at the same file.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn: aiosqlite.Connection | None = None
        #: SQLite has one connection here, so a COMMIT from any task would
        #: commit another task's half-finished work. Every write therefore
        #: goes through :meth:`transaction`, which serialises writers.
        self._write_lock = asyncio.Lock()

    async def open(self) -> "Database":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)  # owner-only data directory
        except OSError:  # pragma: no cover - platform dependent
            logger.warning("cannot restrict permissions on %s", self.path.parent)
        existed = self.path.exists()
        if not existed:
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        await conn.execute("PRAGMA synchronous=NORMAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        self._conn = conn
        await self._migrate()
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - platform dependent
            logger.warning("cannot restrict permissions on %s", self.path)
        return self

    async def close(self) -> None:
        if self._conn is not None:
            try:
                await self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except aiosqlite.Error:  # pragma: no cover
                pass
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise StoreError("database is not open")
        return self._conn

    async def _migrate(self) -> None:
        conn = self.conn
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
            "applied_at TEXT NOT NULL)"
        )
        await conn.commit()
        async with conn.execute("SELECT version FROM schema_migrations") as cur:
            applied = {row[0] for row in await cur.fetchall()}
        for version, name, sql in MIGRATIONS:
            if version in applied:
                continue
            await conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in _split_statements(sql):
                    await conn.execute(statement)
                await conn.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                    (version, name, utcnow()),
                )
                await conn.commit()
            except BaseException:
                await conn.rollback()
                raise
            logger.info("applied store migration %d (%s)", version, name)

    async def schema_version(self) -> int:
        async with self.conn.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
        ) as cur:
            row = await cur.fetchone()
        return int(row[0])

    # -- helpers -----------------------------------------------------------------

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        async with self.conn.execute(sql, tuple(params)) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        async with self.conn.execute(sql, tuple(params)) as cur:
            row = await cur.fetchone()
        return dict(row) if row is not None else None

    @contextlib.asynccontextmanager
    async def transaction(self):
        """Exclusive write transaction: commit on success, roll back on error.

        Not re-entrant - do not call :meth:`execute` or open a second
        transaction from inside one.
        """
        async with self._write_lock:
            conn = self.conn
            await conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                await conn.rollback()
                raise
            else:
                await conn.commit()

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        async with self.transaction() as conn:
            await conn.execute(sql, tuple(params))

    async def snapshot(self, destination: str | Path) -> Path:
        """Consistent online copy of the database (for safe upgrades)."""
        dest = Path(destination)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            dest.unlink()
        await self.conn.execute("VACUUM INTO ?", (str(dest),))
        os.chmod(dest, 0o600)
        return dest

    async def counts(self) -> dict[str, int]:
        out = {}
        for table in ("source_events", "investigations", "response_actions",
                      "outbox", "source_errors"):
            row = await self.fetchone(f"SELECT COUNT(*) AS n FROM {table}")
            out[table] = int(row["n"]) if row else 0
        return out


def _split_statements(sql: str) -> list[str]:
    """Split a migration script on ``;`` after dropping ``--`` comment lines
    (so a semicolon inside a comment cannot cut a statement in two)."""
    body = "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    )
    return [s.strip() for s in body.split(";") if s.strip()]


__all__ = ["Database", "StoreError", "utcnow", "LATEST_VERSION"]
