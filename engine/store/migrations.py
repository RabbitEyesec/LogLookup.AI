"""Explicit, ordered, idempotent schema migrations.

Each migration runs in one transaction and records itself in
``schema_migrations``; re-running is a no-op. Never edit a shipped
migration — append a new one.
"""

from __future__ import annotations

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "v2 foundation", """
CREATE TABLE connections (
    connection_id TEXT PRIMARY KEY,
    scope_id      TEXT NOT NULL,
    provider      TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    options_json  TEXT NOT NULL DEFAULT '{}',
    auth_profile_id TEXT NOT NULL DEFAULT '',
    poll_seconds  INTEGER NOT NULL DEFAULT 60,
    lookback_seconds INTEGER NOT NULL DEFAULT 300,
    max_page_size INTEGER NOT NULL DEFAULT 500,
    tls_verify    INTEGER NOT NULL DEFAULT 1,
    ca_bundle_path TEXT,
    active        INTEGER NOT NULL DEFAULT 0,
    paused        INTEGER NOT NULL DEFAULT 0,
    origin        TEXT NOT NULL DEFAULT 'managed',
    status        TEXT NOT NULL DEFAULT 'not_configured',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE source_cursors (
    connection_id TEXT NOT NULL,
    stream_name   TEXT NOT NULL,
    cursor_json   TEXT NOT NULL,
    window_complete INTEGER NOT NULL DEFAULT 1,
    committed_at  TEXT NOT NULL,
    PRIMARY KEY (connection_id, stream_name)
);

CREATE TABLE source_events (
    canonical_event_id TEXT PRIMARY KEY,
    scope_id      TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    provider      TEXT NOT NULL,
    record_kind   TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    source_incident_id TEXT,
    source_url    TEXT,
    event_time    TEXT,
    source_updated_at TEXT,
    observed_at   TEXT NOT NULL,
    raw_sha256    TEXT NOT NULL,
    raw_enc       BLOB,
    revision      INTEGER NOT NULL DEFAULT 1,
    duplicate_of  TEXT,
    envelope_json TEXT NOT NULL
);
CREATE INDEX ix_source_events_conn ON source_events (connection_id, event_time);
CREATE INDEX ix_source_events_kind ON source_events (scope_id, record_kind, event_time);

CREATE TABLE source_aliases (
    scope_id    TEXT NOT NULL,
    alias_scheme TEXT NOT NULL,
    alias_value TEXT NOT NULL,
    canonical_event_id TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (scope_id, alias_scheme, alias_value)
);

CREATE TABLE processed_observations (
    canonical_event_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL,
    state       TEXT NOT NULL,
    detail      TEXT,
    processed_at TEXT NOT NULL,
    UNIQUE (canonical_event_id, source_revision)
);

CREATE TABLE context_observations (
    context_id  TEXT PRIMARY KEY,
    context_type TEXT NOT NULL,
    scope_id    TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    event_time  TEXT NOT NULL,
    event_time_ms INTEGER NOT NULL,
    principal_key TEXT,
    entities_json TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    source_ref  TEXT NOT NULL,
    original_record_ref TEXT NOT NULL
);
CREATE INDEX ix_context_principal ON context_observations (scope_id, principal_key, event_time_ms);

CREATE TABLE investigations (
    cluster_id  TEXT PRIMARY KEY,
    scope_id    TEXT NOT NULL,
    anchor_uid  TEXT,
    label       TEXT NOT NULL DEFAULT '',
    latest_revision INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'new',
    risk_score  REAL NOT NULL DEFAULT 0,
    surfaced    INTEGER NOT NULL DEFAULT 0,
    merged_into TEXT,
    owner       TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_investigations_anchor ON investigations (scope_id, anchor_uid)
    WHERE anchor_uid IS NOT NULL;

CREATE TABLE investigation_events (
    cluster_id  TEXT NOT NULL,
    canonical_event_id TEXT NOT NULL,
    PRIMARY KEY (cluster_id, canonical_event_id)
);

CREATE TABLE investigation_revisions (
    cluster_id  TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (cluster_id, revision)
);

CREATE TABLE cluster_aliases (
    old_cluster_id TEXT PRIMARY KEY,
    cluster_id  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE incident_links (
    scope_id    TEXT NOT NULL,
    provider    TEXT NOT NULL,
    external_incident_id TEXT NOT NULL,
    cluster_id  TEXT NOT NULL,
    url         TEXT,
    title       TEXT,
    status      TEXT,
    UNIQUE (scope_id, provider, external_incident_id, cluster_id)
);

CREATE TABLE analyst_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id  TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    author      TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE response_actions (
    action_id   TEXT PRIMARY KEY,
    scope_id    TEXT NOT NULL,
    cluster_id  TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    workflow_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    approvals_json TEXT NOT NULL DEFAULT '[]',
    approvals_required INTEGER NOT NULL DEFAULT 1,
    rejected_by TEXT,
    rationale   TEXT,
    payload_json TEXT NOT NULL,
    canonical_payload_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state       TEXT NOT NULL,
    provider_run_id TEXT,
    last_remote_observation TEXT,
    expires_at  TEXT,
    transitions_json TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX ix_actions_cluster ON response_actions (cluster_id);
-- One live action per idempotency key; a rejected/failed/expired/cancelled
-- proposal frees the key so it can be proposed again as a NEW action.
CREATE UNIQUE INDEX ux_actions_idem ON response_actions (idempotency_key)
    WHERE state NOT IN ('rejected','failed_without_effect','expired','cancelled');

CREATE TABLE outbox (
    action_id   TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    destination TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    delivery_state TEXT NOT NULL DEFAULT 'queued',
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE audit_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);

CREATE TABLE api_tokens (
    token_hash  TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    role        TEXT NOT NULL,
    scope_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE source_errors (
    error_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    stream_name TEXT,
    code        TEXT NOT NULL,
    detail      TEXT NOT NULL,
    ref         TEXT,
    occurred_at TEXT NOT NULL
);
CREATE INDEX ix_source_errors_conn ON source_errors (connection_id, occurred_at);
"""),
    (2, "reliability: revision snapshots and correlation work queue", """
-- Immutable per-revision payload copies. source_events keeps only the latest
-- revision, so a queued older revision would otherwise lose its only input.
CREATE TABLE source_event_revisions (
    canonical_event_id TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    raw_sha256  TEXT NOT NULL,
    encrypted_payload BLOB,
    envelope_json TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    PRIMARY KEY (canonical_event_id, revision)
);

-- Durable hand-off from the ledger to the correlation engine. A row is
-- written in the same transaction as the evidence and the source cursor.
CREATE TABLE ingest_work_items (
    canonical_event_id TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    operation   TEXT NOT NULL,
    scope_id    TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    state       TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    lease_until TEXT,
    last_error_code TEXT,
    created_at  TEXT NOT NULL,
    processed_at TEXT,
    PRIMARY KEY (canonical_event_id, revision, operation)
);
CREATE INDEX ix_work_pending ON ingest_work_items (state, next_attempt_at);
CREATE INDEX ix_work_conn ON ingest_work_items (connection_id, scope_id, state);

-- Snapshot every revision already stored by v2.0.0 so the table is complete.
INSERT INTO source_event_revisions (canonical_event_id, revision, raw_sha256,
    encrypted_payload, envelope_json, committed_at)
SELECT canonical_event_id, revision, raw_sha256, raw_enc, envelope_json, observed_at
FROM source_events;
"""),
    (3, "cursor history, review flags, remote run status", """
-- A cursor that an administrator replaced is kept, never overwritten.
CREATE TABLE source_cursor_history (
    history_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    stream_name TEXT NOT NULL,
    cursor_json TEXT NOT NULL,
    replaced_by TEXT NOT NULL,
    reason      TEXT NOT NULL,
    replaced_at TEXT NOT NULL
);

-- An alert revision the engine could not apply deterministically.
CREATE TABLE investigation_review_flags (
    flag_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id  TEXT NOT NULL,
    canonical_event_id TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT
);
CREATE INDEX ix_review_open ON investigation_review_flags (cluster_id, resolved_at);

-- What Azure last said about the workflow run, kept apart from LogLookup's
-- own action state and from any confirmed downstream effect.
ALTER TABLE response_actions ADD COLUMN remote_status TEXT;
ALTER TABLE response_actions ADD COLUMN remote_status_at TEXT;
ALTER TABLE response_actions ADD COLUMN remote_run_json TEXT;
ALTER TABLE response_actions ADD COLUMN downstream_effect TEXT NOT NULL DEFAULT 'not_observed';
"""),
]

LATEST_VERSION = MIGRATIONS[-1][0]
