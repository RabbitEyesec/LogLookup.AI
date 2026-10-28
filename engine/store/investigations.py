"""Durable investigations: stable chain ids, revisions, notes, aliases.

The correlator is synchronous and in-memory; this store makes its output
durable *around* it. The key guarantee is id stability: a chain is anchored
by its earliest alert's uid, so replaying an overlapping window after a
restart resolves to the same ``cluster_id`` instead of minting a new one,
and merged chains keep resolving through ``cluster_aliases``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from engine.store.database import Database, utcnow


def content_hash(summary: dict[str, Any]) -> str:
    """Hash of the chain state that defines a revision (not timestamps)."""
    basis = {
        "alerts": [a["uid"] for a in summary.get("alerts", [])],
        "surfaced": summary.get("surfaced"),
        "risk": round(float(summary.get("risk_score", 0)), 3),
        "disposition": summary.get("disposition"),
    }
    return hashlib.sha256(
        json.dumps(basis, sort_keys=True).encode()
    ).hexdigest()


class InvestigationStore:
    def __init__(self, db: Database, scope_id: str) -> None:
        self._db = db
        self._scope = scope_id

    async def load_id_state(self) -> tuple[dict[str, str], dict[tuple[str, str], int]]:
        """``(anchor_uid -> cluster_id, (date, label) -> highest sequence)``."""
        rows = await self._db.fetchall(
            "SELECT cluster_id, anchor_uid FROM investigations WHERE scope_id=?",
            (self._scope,),
        )
        anchors: dict[str, str] = {}
        counters: dict[tuple[str, str], int] = {}
        for r in rows:
            if r["anchor_uid"]:
                anchors[r["anchor_uid"]] = r["cluster_id"]
            parts = r["cluster_id"].split("-")
            # CHAIN-YYYY-MM-DD-<label...>-NNN
            if len(parts) >= 6 and parts[-1].isdigit():
                date = "-".join(parts[1:4])
                label = "-".join(parts[4:-1])
                key = (date, label)
                counters[key] = max(counters.get(key, 0), int(parts[-1]))
        return anchors, counters

    async def resolve(self, cluster_id: str) -> str:
        """Follow merge aliases so old deep links resolve permanently."""
        seen = set()
        current = cluster_id
        while current not in seen:
            seen.add(current)
            row = await self._db.fetchone(
                "SELECT cluster_id FROM cluster_aliases WHERE old_cluster_id=?",
                (current,),
            )
            if row is None:
                return current
            current = row["cluster_id"]
        return current

    async def sync(self, summaries: list[dict[str, Any]],
                   anchors: dict[str, str],
                   merged: dict[str, str]) -> dict[str, int]:
        """Persist the live correlation state; returns cluster -> revision."""
        now = utcnow()
        revisions: dict[str, int] = {}
        async with self._db.transaction() as conn:
            for summary in summaries:
                cid = summary["cluster_id"]
                chash = content_hash(summary)
                row = await self._db.fetchone(
                    "SELECT latest_revision FROM investigations WHERE cluster_id=?",
                    (cid,),
                )
                anchor = next(
                    (uid for uid, c in anchors.items() if c == cid), None
                )
                if row is None:
                    await conn.execute(
                        "INSERT INTO investigations (cluster_id, scope_id, anchor_uid,"
                        " label, latest_revision, status, risk_score, surfaced,"
                        " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (cid, self._scope, anchor, summary.get("primary_entity", ""),
                         0, "new", summary.get("risk_score", 0),
                         1 if summary.get("surfaced") else 0, now, now),
                    )
                    latest = 0
                else:
                    latest = int(row["latest_revision"])
                last = await self._db.fetchone(
                    "SELECT content_hash FROM investigation_revisions "
                    "WHERE cluster_id=? AND revision=?", (cid, latest),
                ) if latest else None
                if last is None or last["content_hash"] != chash:
                    latest += 1
                    await conn.execute(
                        "INSERT INTO investigation_revisions VALUES (?,?,?,?,?)",
                        (cid, latest, chash,
                         json.dumps(_revision_summary(summary), default=str), now),
                    )
                    await conn.execute(
                        "UPDATE investigations SET latest_revision=?, risk_score=?,"
                        " surfaced=?, updated_at=? WHERE cluster_id=?",
                        (latest, summary.get("risk_score", 0),
                         1 if summary.get("surfaced") else 0, now, cid),
                    )
                revisions[cid] = latest
                for alert in summary.get("alerts", []):
                    src = alert.get("source") or {}
                    ceid = src.get("canonical_event_id")
                    if ceid:
                        await conn.execute(
                            "INSERT OR IGNORE INTO investigation_events VALUES (?,?)",
                            (cid, ceid),
                        )
            for old, new in merged.items():
                await conn.execute(
                    "INSERT OR IGNORE INTO cluster_aliases VALUES (?,?,?)",
                    (old, new, now),
                )
                await conn.execute(
                    "UPDATE investigations SET merged_into=? WHERE cluster_id=?",
                    (new, old),
                )
        return revisions

    async def get(self, cluster_id: str) -> dict[str, Any] | None:
        return await self._db.fetchone(
            "SELECT * FROM investigations WHERE cluster_id=?", (cluster_id,)
        )

    async def list(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        return await self._db.fetchall(
            "SELECT * FROM investigations WHERE scope_id=? AND merged_into IS NULL "
            "ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            (self._scope, limit, offset),
        )

    async def event_ids(self, cluster_id: str) -> list[str]:
        rows = await self._db.fetchall(
            "SELECT canonical_event_id FROM investigation_events WHERE cluster_id=?",
            (cluster_id,),
        )
        return [r["canonical_event_id"] for r in rows]

    async def links(self, cluster_id: str) -> list[dict[str, Any]]:
        return await self._db.fetchall(
            "SELECT * FROM incident_links WHERE cluster_id=? AND scope_id=?",
            (cluster_id, self._scope),
        )

    async def link_provider_incidents(self, cluster_id: str,
                                      event_ids: list[str]) -> None:
        """Attach provider incidents referenced by this chain's alerts."""
        if not event_ids:
            return
        marks = ",".join("?" for _ in event_ids)
        rows = await self._db.fetchall(
            f"SELECT DISTINCT provider, source_incident_id, source_url FROM "
            f"source_events WHERE canonical_event_id IN ({marks}) AND "
            f"source_incident_id IS NOT NULL", event_ids,
        )
        for r in rows:
            await self._db.execute(
                "INSERT OR IGNORE INTO incident_links (scope_id, provider,"
                " external_incident_id, cluster_id, url, title, status) "
                "VALUES (?,?,?,?,?,NULL,NULL)",
                (self._scope, r["provider"], r["source_incident_id"], cluster_id,
                 r["source_url"]),
            )

    # -- analyst records (revisioned, append-only) ------------------------------

    async def add_note(self, cluster_id: str, revision: int, author: str,
                       body: str) -> int:
        async with self._db.transaction() as conn:
            cur = await conn.execute(
                "INSERT INTO analyst_notes (cluster_id, revision, author, body,"
                " created_at) VALUES (?,?,?,?,?)",
                (cluster_id, revision, author, body, utcnow()),
            )
        return int(cur.lastrowid)

    async def notes(self, cluster_id: str) -> list[dict[str, Any]]:
        return await self._db.fetchall(
            "SELECT * FROM analyst_notes WHERE cluster_id=? ORDER BY note_id",
            (cluster_id,),
        )

    async def assign(self, cluster_id: str, owner: str | None) -> None:
        await self._db.execute(
            "UPDATE investigations SET owner=?, status=CASE WHEN status='new' "
            "THEN 'investigating' ELSE status END, updated_at=? WHERE cluster_id=?",
            (owner, utcnow(), cluster_id),
        )

    async def set_status(self, cluster_id: str, status: str) -> None:
        await self._db.execute(
            "UPDATE investigations SET status=?, updated_at=? WHERE cluster_id=?",
            (status, utcnow(), cluster_id),
        )


def _revision_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Immutable per-revision snapshot: ids and scores, not raw evidence."""
    return {
        "cluster_id": summary["cluster_id"],
        "alert_uids": [a["uid"] for a in summary.get("alerts", [])],
        "risk_score": summary.get("risk_score"),
        "risk_breakdown": summary.get("risk_breakdown"),
        "surfaced": summary.get("surfaced"),
        "disposition": summary.get("disposition"),
        "sources": summary.get("sources"),
        "tactic_sequence": summary.get("tactic_sequence"),
        "first_time": summary.get("first_time"),
        "last_time": summary.get("last_time"),
    }
