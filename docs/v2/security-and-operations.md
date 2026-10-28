# Security and operations

## Identity and roles

The API resolves the caller on the server (`engine/api/auth.py`):

1. `Authorization: Bearer llk_...` - a role-bound token (stored hashed).
2. A reverse proxy listed in `access.trusted_proxy_ips` asserting `X-Forwarded-User` / `X-Forwarded-Role`. Headers from any other peer are ignored.
3. A direct loopback connection with no proxy headers: the local owner (`administrator`). Mutations also need the `X-LogLookup-Client` header and a same-origin `Origin`, so a web page cannot drive the local app.

```bash
loglookup token create --user ann --role analyst     # prints the token once
loglookup token list
loglookup token revoke --user ann
```

| Role | Can |
|---|---|
| `viewer` | Read investigations, timelines, evidence metadata, workflows, source health |
| `analyst` | + read raw evidence (audited), notes, assignment, propose actions, read audit |
| `responder` | + approve / reject / cancel / reconcile actions |
| `administrator` | + manage connections and credentials, verify the audit chain |

Role checks run in the route handlers. Hiding a button is not a security boundary. For access beyond localhost, put the service behind an authenticated TLS reverse proxy.

## Data at rest

- Raw vendor payloads: AES-256-GCM in the ledger, key derived (HKDF) from the secret store; the content hash is verified on read.
- Secrets: the existing encrypted secret store, per auth profile.
- Store file and secret files: owner-only (`0600`).
- Retention: encrypted payloads older than `storage.raw_retention_days` are dropped hourly; hashes and metadata remain.

## Audit

`audit_events` is append-only and hash-chained. Every connection change, raw-evidence read, note, assignment, proposal, approval, rejection, dispatch, reconciliation and outcome is recorded with actor and revision. `GET /api/v2/audit/verify` re-walks the chain and reports the first broken entry.

## Reliability

- One independent async worker per connection; one failing source never stops the others.
- Backoff with `Retry-After`, bounded concurrency and page caps; no source-supplied URL is followed off-host.
- A single SQLite writer per application home (WAL, busy timeout); all writes are serialised in short transactions. Do not run two LogLookup processes on one home.
- On start the correlator is rebuilt from the ledger's recent detections, and chain ids come back unchanged (anchored by the chain's earliest alert), so `/incident/<cluster_id>` links survive restarts. Merged chains keep resolving through `cluster_aliases`.
- `loglookup snapshot <path>` writes a consistent copy of the store for upgrades and rollback.

## Metrics and source health

`GET /api/v2/metrics` and `GET /api/v2/sources/health` (the card view adds the same fields to each connection).

| Status | Meaning |
|---|---|
| `healthy` | Polling succeeds and no known completeness problem is outstanding |
| `degraded` | A provider returned a partial/truncated result, an unkeyed row or a non-advancing page, or a snapshot is being replayed. The cursor has not moved past the problem |
| `backlogged` | Acquisition is fine but acquired data has waited longer than 5 minutes for correlation |
| `paused`, `not_configured`, `permission_denied`, `limited_by_license`, `throttled`, `temporarily_unavailable`, `starting` | As before |

Per stream: `window_start`, `window_end`, `watermark`, `window_complete`, `continuation_mode` (`composite_seek`, `snapshot_job`, `next_link`, `continuation`), `snapshot_active`, `snapshot_offset`, `ingest_lag_seconds` (from the committed watermark; `null`, never `0`, when none), `last_page_records`.

Per source: `records_received`, `records_new`, `records_updated`, `records_duplicate`, `records_unchanged`, `records_quarantined`, `pages_drained`, `provider_partial_errors`, `last_attempt`, `last_success`, `last_receipt`, and `correlation` (`pending_correlation_items`, `oldest_pending_age_seconds`, `quarantined`, counts by state). Metrics also carry `correlation_queue`, the outbox backlog and `reconciliation_required`.

Warning codes: `PAGE_LIMIT_REACHED` (normal while draining), `SNAPSHOT_RUNNING`, `SNAPSHOT_EXPIRED_REPLAYING` and `BAD_ROWS_SKIPPED` (degrade), `PARTIAL_RESPONSE`, `UNPARSEABLE_ROW`, `CURSOR_NON_ADVANCING`, `CURSOR_CONFIG_CHANGED` (errors that stop the page and degrade the source), `INGESTION_BACKLOG`, `CURSOR_MIGRATED_FROM_V1`, `EVENT_TIME_FILTER_ACTIVE`, `FULL_INDEX_TIME_COLLECTION`, `EXPORT_MODE_RETIRED`. Credentials, tokens, raw payloads and full provider URLs never appear in health or metrics.

## When a source stops (administrator)

One failing source never stops the others. A stuck source retries with backoff, shows `degraded`, and keeps its diagnostics in `source_errors` (a code and a hash of the offending row, never the row). Three administrator actions, all audited:

| Situation | Action |
|---|---|
| Fixed something (a permission, a network path) | `POST /connections/{id}/retry` replays the saved cursor now instead of waiting out the backoff. Nothing is skipped |
| A Splunk row has no `event_id` or `_cd`, so it cannot be given an identity | The source stays stopped (fail-closed). `POST /connections/{id}/skip-bad-rows` (a reason is required) lets **one** window set such rows aside; each is hashed and recorded, and strict mode returns once that window drains |
| Workspace, indexes or query settings changed (`CURSOR_CONFIG_CHANGED`) | The old cursor is kept. Pause the source, then `POST /connections/{id}/cursor/confirm` (`stream`, `reason`, optional `start_from` within 7 days) to start a new scan, or run a bounded backfill |

## Splunk event-time floor

`max_event_age_seconds` (default `86400`) excludes events whose `_time` is older than that at collection, even though collection is by index time. It is shown on the source card and reported as `EVENT_TIME_FILTER_ACTIVE`. Setting it to `0` collects purely by index time (`FULL_INDEX_TIME_COLLECTION`): nothing is excluded for being old, but searches scan more data and cost more on large indexes. A backfill can carry its own floor (`event_time_floor_seconds`, `0` = none), so a controlled historical re-read does not need a config change.

## Bounded backfill (administrator)

If you suspect a source skipped records (for example a tie group under the v2.0.0 Sentinel/Splunk cursors), re-read an explicit window:

```bash
curl -X POST http://localhost:8080/api/v2/connections/sentinel-main/backfill \
  -H 'X-LogLookup-Client: 1' -H 'Content-Type: application/json' \
  -d '{"stream":"alerts","start":"2026-10-28T00:00:00Z","end":"2026-10-28T06:00:00Z","reason":"tie-group repair"}'
curl http://localhost:8080/api/v2/connections/sentinel-main/backfill      # progress
```

Elastic: the legacy `elastic-default` poller keeps its own `state.json` cursor and is never migrated or overwritten; it cannot be backfilled. Add a cluster as a managed Elastic connection to backfill it.

Rules: the connection must be **paused** first (a live worker and a backfill never run together); UTC offsets are required; the window is at most 7 days and cannot end in the future; the action is audited. A backfill stores through the ledger (duplicates are absorbed) and **never writes the live cursor**, so it cannot move the checkpoint backwards. Resume the source afterwards.

## Service

`deploy/systemd/loglookup.service` runs with `ProtectSystem=strict`, private devices/tmp, restricted address families and namespaces, `UMask=0077`, `Type=notify` and a watchdog. Shutdown order: stop accepting requests, cancel source workers (clients closed), stop the dispatcher (an in-flight send is not retried), checkpoint WAL.

## Operating checklist

1. Create an auth profile and the least-privilege grant listed in [provider-configuration.md](provider-configuration.md).
2. Add the connection (it saves disabled), then enable it; watch its card turn `healthy`.
3. Confirm `GET /api/v2/investigations` shows the source badge you expect.
4. Create tokens for people other than the local owner.
5. Enable the response channel only after the approval roles are in place ([logic-apps-contract.md](logic-apps-contract.md)).
