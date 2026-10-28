"""Durable event ledger: dedup, revisions, aliases, and cursor commit.

``commit_page`` is the one place a source page becomes durable. Events and
the cursor advance land in a single ACID transaction, so a crash can never
leave a cursor ahead of its data. Acquisition is at-least-once; the ledger
makes the downstream effect exactly-once-per-revision:

* same canonical id + same payload hash  -> ignored (duplicate poll)
* same canonical id + changed payload    -> new revision (an update)
* different canonical id, same alias     -> stored, flagged ``duplicate_of``
  and kept out of correlation so one underlying alert counts once.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from engine.envelope import SourceEnvelope, evidence_ref
from engine.store.cursors import upsert_cursor_sql
from engine.store.database import Database, utcnow
from engine.store.evidence import EvidenceVault

logger = logging.getLogger(__name__)


@dataclass
class PageItem:
    envelope: SourceEnvelope
    payload: dict[str, Any]
    #: normalised context observation rows (Entra sign-ins etc.), one per
    #: principal the record concerns
    contexts: list[dict[str, Any]] = field(default_factory=list)
    #: external-incident links to persist (provider incidents)
    links: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AcceptedRecord:
    envelope: SourceEnvelope
    payload: dict[str, Any]
    is_update: bool = False
    #: canonical id of the event this one duplicates (via a shared alias)
    duplicate_of: str | None = None

    @property
    def forward_to_correlation(self) -> bool:
        return self.envelope.is_detection and self.duplicate_of is None


class Ledger:
    def __init__(self, db: Database, vault: EvidenceVault) -> None:
        self._db = db
        self._vault = vault

    async def commit_page(
        self,
        connection_id: str,
        stream: str,
        items: list[PageItem],
        next_cursor: dict[str, Any] | None,
        window_complete: bool,
    ) -> list[AcceptedRecord]:
        accepted: list[AcceptedRecord] = []
        now = utcnow()
        async with self._db.transaction() as conn:
            for item in items:
                record = await self._ingest_one(item, now)
                if record is not None:
                    accepted.append(record)
            if next_cursor is not None:
                await conn.execute(
                    upsert_cursor_sql(),
                    (connection_id, stream, json.dumps(next_cursor),
                     1 if window_complete else 0, now),
                )
        return accepted

    async def _ingest_one(self, item: PageItem, now: str) -> AcceptedRecord | None:
        conn = self._db.conn
        env = item.envelope
        async with conn.execute(
            "SELECT raw_sha256, revision, duplicate_of FROM source_events "
            "WHERE canonical_event_id=?", (env.canonical_event_id,),
        ) as cur:
            row = await cur.fetchone()

        if row is not None and row["raw_sha256"] == env.raw_sha256:
            return None  # same revision seen again (overlap window)

        revision = 1 if row is None else int(row["revision"]) + 1
        duplicate_of = row["duplicate_of"] if row is not None else None
        if row is None:
            duplicate_of = await self._claim_aliases(env, now)
        env = dataclasses.replace(
            env,
            revision=revision,
            raw_payload_ref=f"ledger:{env.canonical_event_id}:{revision}",
        )
        blob, sealed_hash = self._vault.seal(item.payload, env.raw_payload_ref)
        if sealed_hash != env.raw_sha256:
            # The connector hashed a different byte form than the vault
            # sees; trust the vault (it hashes what it encrypts).
            env = dataclasses.replace(env, raw_sha256=sealed_hash)

        await conn.execute(
            "INSERT INTO source_events (canonical_event_id, scope_id, connection_id,"
            " provider, record_kind, source_event_id, source_incident_id, source_url,"
            " event_time, source_updated_at, observed_at, raw_sha256, raw_enc,"
            " revision, duplicate_of, envelope_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(canonical_event_id) DO UPDATE SET "
            " source_updated_at=excluded.source_updated_at, observed_at=excluded.observed_at,"
            " raw_sha256=excluded.raw_sha256, raw_enc=excluded.raw_enc,"
            " revision=excluded.revision, envelope_json=excluded.envelope_json,"
            " source_incident_id=excluded.source_incident_id",
            (env.canonical_event_id, env.scope_id, env.connection_id, env.provider,
             env.record_kind, env.source_event_id, env.source_incident_id,
             env.source_url, env.event_time, env.source_updated_at, env.observed_at,
             env.raw_sha256, blob, revision, duplicate_of,
             json.dumps(env.as_dict(), default=str)),
        )
        for c in item.contexts:
            await conn.execute(
                "INSERT OR REPLACE INTO context_observations (context_id, context_type,"
                " scope_id, connection_id, event_time, event_time_ms, principal_key,"
                " entities_json, attributes_json, source_ref, original_record_ref) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (c["context_id"], c["context_type"], env.scope_id, env.connection_id,
                 c["event_time"], c["event_time_ms"], c.get("principal_key"),
                 json.dumps(c["entities"]), json.dumps(c["attributes"], default=str),
                 evidence_ref(env), env.raw_payload_ref),
            )
        for link in item.links:
            await conn.execute(
                "INSERT OR IGNORE INTO incident_links (scope_id, provider,"
                " external_incident_id, cluster_id, url, title, status) "
                "VALUES (?,?,?,?,?,?,?)",
                (env.scope_id, env.provider, link["external_incident_id"],
                 link.get("cluster_id", ""), link.get("url"), link.get("title"),
                 link.get("status")),
            )
        await conn.execute(
            "INSERT OR IGNORE INTO processed_observations VALUES (?,?,?,?,?)",
            (env.canonical_event_id, revision,
             "duplicate" if duplicate_of else "accepted", duplicate_of, now),
        )
        return AcceptedRecord(
            envelope=env, payload=item.payload,
            is_update=row is not None, duplicate_of=duplicate_of,
        )

    async def _claim_aliases(self, env: SourceEnvelope, now: str) -> str | None:
        """Register aliases; return the canonical id of an earlier holder."""
        conn = self._db.conn
        earlier: str | None = None
        for scheme, value in env.aliases:
            async with conn.execute(
                "SELECT canonical_event_id FROM source_aliases "
                "WHERE scope_id=? AND alias_scheme=? AND alias_value=?",
                (env.scope_id, scheme, value),
            ) as cur:
                hit = await cur.fetchone()
            if hit is None:
                await conn.execute(
                    "INSERT INTO source_aliases VALUES (?,?,?,?,?)",
                    (env.scope_id, scheme, value, env.canonical_event_id, now),
                )
            elif hit["canonical_event_id"] != env.canonical_event_id and earlier is None:
                earlier = hit["canonical_event_id"]
        return earlier

    # -- reads ---------------------------------------------------------------------

    async def get_event(
        self, canonical_event_id: str, *, include_raw: bool = False
    ) -> dict[str, Any] | None:
        row = await self._db.fetchone(
            "SELECT * FROM source_events WHERE canonical_event_id=?",
            (canonical_event_id,),
        )
        if row is None:
            return None
        blob = row.pop("raw_enc")
        envelope = json.loads(row.pop("envelope_json"))
        row["envelope"] = envelope
        row["evidence_ref"] = evidence_ref(_env_from_dict(envelope))
        if include_raw and blob is not None:
            row["raw"] = self._vault.open(
                blob, f"ledger:{canonical_event_id}:{row['revision']}",
                row["raw_sha256"],
            )
        return row

    async def replayable_detections(
        self, retention_minutes: int, limit: int = 20000
    ) -> list[tuple[SourceEnvelope, dict[str, Any]]]:
        """Recent, non-duplicate detections, oldest event first.

        Used at startup to rebuild the in-memory correlation state: the
        ledger dedups re-delivered records, so without a replay a restarted
        process would hold no chains until genuinely new alerts arrive.
        """
        rows = await self._db.fetchall(
            "SELECT canonical_event_id, raw_enc, envelope_json, revision FROM "
            "source_events WHERE record_kind='alert' AND duplicate_of IS NULL "
            "AND raw_enc IS NOT NULL AND observed_at >= "
            "strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?) "
            "ORDER BY COALESCE(event_time, observed_at) LIMIT ?",
            (f"-{int(retention_minutes)} minutes", limit),
        )
        out = []
        for r in rows:
            env = _env_from_dict(json.loads(r["envelope_json"]))
            payload = self._vault.open(
                r["raw_enc"], f"ledger:{r['canonical_event_id']}:{r['revision']}",
                env.raw_sha256)
            out.append((env, payload))
        return out

    async def context_for_principals(
        self, scope_id: str, principals: list[str], start_ms: int, end_ms: int,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if not principals:
            return []
        marks = ",".join("?" for _ in principals)
        rows = await self._db.fetchall(
            f"SELECT * FROM context_observations WHERE scope_id=? AND "
            f"principal_key IN ({marks}) AND event_time_ms BETWEEN ? AND ? "
            f"ORDER BY event_time_ms LIMIT ?",
            (scope_id, *[p.lower() for p in principals], start_ms, end_ms, limit),
        )
        for r in rows:
            r["entities"] = json.loads(r.pop("entities_json"))
            r["attributes"] = json.loads(r.pop("attributes_json"))
        return rows

    async def purge_raw_older_than(self, days: int) -> int:
        """Retention: drop encrypted payloads, keep hashes and metadata."""
        async with self._db.transaction() as conn:
            cur = await conn.execute(
                "UPDATE source_events SET raw_enc=NULL WHERE raw_enc IS NOT NULL "
                "AND observed_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
                (f"-{int(days)} days",),
            )
        return cur.rowcount or 0

    async def record_error(
        self, connection_id: str, stream: str | None, code: str, detail: str,
        ref: str | None = None,
    ) -> None:
        await self._db.execute(
            "INSERT INTO source_errors (connection_id, stream_name, code, detail,"
            " ref, occurred_at) VALUES (?,?,?,?,?,?)",
            (connection_id, stream, code, detail[:500], ref, utcnow()),
        )
        # Bounded: keep the newest 500 per connection.
        await self._db.execute(
            "DELETE FROM source_errors WHERE connection_id=? AND error_id NOT IN "
            "(SELECT error_id FROM source_errors WHERE connection_id=? "
            " ORDER BY error_id DESC LIMIT 500)",
            (connection_id, connection_id),
        )


def _env_from_dict(data: dict[str, Any]) -> SourceEnvelope:
    data = dict(data)
    data["aliases"] = tuple(tuple(a) for a in data.get("aliases", ()))
    return SourceEnvelope(**data)
