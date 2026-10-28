# Changelog

## Unreleased

Operating decisions and the two remaining features from the reliability plan. No new integrations; schema migration 3 is additive.

### Operating decisions

- **A bad source row stays fail-closed.** A row without a trustworthy identity stops its page; the cursor does not move and no identity is invented. The source shows `degraded`, backs off, and keeps a code and a hash of the row in `source_errors`. Administrators can `retry` now, or allow `skip-bad-rows` for exactly one window (each skipped row hashed and recorded, audited), or run a bounded backfill. Other sources are unaffected.
- **Splunk event-time floor** stays 86400 s by default; `0` collects purely by index time. The active setting is shown on the source card and in health (`EVENT_TIME_FILTER_ACTIVE` / `FULL_INDEX_TIME_COLLECTION`), and a backfill can carry its own floor.
- **A changed workspace, index set or query no longer resets a cursor automatically.** The page fails with `CURSOR_CONFIG_CHANGED`, the original cursor (and Splunk job) is preserved, and an administrator confirms a new scan (old cursor kept in `source_cursor_history`, decision audited) or runs a bounded backfill.
- **Elastic**: `elastic-default` and its `state.json` cursor are never migrated or overwritten and cannot be backfilled; managed Elastic connections can.

### Added - alert revision-aware re-scoring

- An updated vendor payload is detected by canonical id and payload hash, applied to the same finding (alert count unchanged), and re-scores its chain: risk, risk breakdown, ATT&CK progression, independent-source confirmation.
- Entity or event-time changes re-evaluate membership only when deterministic; otherwise nothing is rewritten and a **review flag** is raised (`/review-flags`).
- A new investigation revision is saved only on a material change and records the previous revision and score, the trigger (source revision and hash), the rule version, and the source revision each alert was scored from. Earlier investigation revisions and source payloads remain readable (`/revisions`, `/evidence/{id}/revisions/{n}`).
- AI analyses written before a material change are marked stale (kept, not re-run). Pending response proposals are re-checked against the current investigation revision before approval and before dispatch and expire if it moved; in-flight actions are untouched.

### Added - Azure Logic Apps run-status lookup

- Read-only Azure Resource Manager adapter for Consumption and Standard, authenticating with a managed identity or service principal. Runs are matched only by run id or by the client tracking id LogLookup now sends; zero or several matches select nothing.
- `POST /api/v2/actions/{id}/check-status` (responder, audited) and a **Check remote status** button. Azure's status (Running, Waiting, Succeeded, Failed, Cancelled, TimedOut) is stored apart from the local action state and from `downstream_effect`.
- Only a unique Running/Waiting/Succeeded run finalises an ambiguous action (to `acknowledged`, delivery proven). Succeeded does not prove the downstream effect; Failed/TimedOut/Cancelled never become `failed_without_effect`; the request is never resent. `downstream_effect` is set only by a person.

### Fixed

- An administrator retry or skip that arrived while a poll was running was lost (the wake flag was cleared before waiting).

## 2.0.1 - 2026-10-28

Reliability patch. No new integrations; every v2.0.0 API, route and stored record is preserved. Schema migration 2 is additive.

### Fixed

- **Sentinel**: a capped page could skip rows sharing the last `TimeGenerated` (the cursor held a timestamp only, and a blocked page advanced it by one microsecond). Paging now uses a total `(TimeGenerated, SystemAlertId)` order with a composite seek applied after the per-alert `summarize`, a frozen window per scan, and the provider's own 100 ns timestamp string. Partial or truncated Azure Monitor results, unkeyed rows and non-advancing pages fail closed: the cursor does not move and the source reports `degraded`.
- **Splunk**: collection no longer caps inside SPL (`| head`) and hops `_indextime` forward. One snapshot search job per bounded index-time window is created, kept alive and paged by `sid` + `offset`; it is released only when drained. A vanished job replays the same frozen window from offset 0 (`SNAPSHOT_EXPIRED_REPLAYING`). A saved `sid` is never used against changed search settings. The streaming export path, which silently dropped malformed lines, is retired (`search_mode: export` now runs the job path and reports `EXPORT_MODE_RETIRED`). Unidentifiable or malformed results fail the page instead of being skipped or identified by content hash. The event-time floor is explicit (`EVENT_TIME_FILTER_ACTIVE`) and can be disabled with `max_event_age_seconds: 0`.
- **Ledger to correlation**: the evidence, the source cursor and a durable work item now commit in one transaction, and a consumer drains the queue into the correlator. A crash or a correlator error after the commit no longer leaves an acquired detection that will never be correlated. Intake is idempotent per canonical event; newer revisions are recorded (`superseded`) and never counted as a second alert; each revision keeps an immutable encrypted payload. Retention never drops a payload that unresolved work still needs.
- **Response**: the dispatcher claims an item and moves its action to `dispatching` atomically, and settles action state, outbox state and audit in one transaction with compare-and-set. Startup recovery reconciles each open outbox row against the action's real state (repairs terminal pairs, queues untouched items, sends ambiguous ones to `reconciliation_required`, flags inconsistent rows) and never resends.
- **Health**: a completed poll no longer reports `lag_seconds = 0.0`. Lag comes from the committed watermark (`null` when there is none).

### Added

- Cursor format v2 (versioned, fingerprinted); v2.0.0 cursors migrate by a bounded overlap re-read (`CURSOR_MIGRATED_FROM_V1`); a changed workspace/index set/template starts fresh (`CURSOR_RESET_CONFIG_CHANGED`).
- Source statuses `degraded` and `backlogged`; per-stream window, watermark, lag, continuation mode and snapshot progress; acquisition counters (received, new, updated, duplicate, unchanged, quarantined, pages drained, provider partial errors); correlation queue depth and oldest-pending age, per source and in `/api/v2/metrics`.
- Administrator-only bounded backfill: `POST/GET /api/v2/connections/{id}/backfill` (paused source, UTC interval, at most 7 days, audited, never writes the live cursor).
- Migration 2: `source_event_revisions`, `ingest_work_items`.

### Changed

- `search_mode` for Splunk defaults to `jobs`.
- Correlation is a durable asynchronous stage; `V2Runtime.drain_work()` waits for it.

### Not changed

OCSF mapping, correlation heuristics, MITRE retrieval, AI prompts, Defender/Entra connectors and auth, the v1 Elastic path, and every existing API payload (new health fields are additive).

## 2.0.0 - 2026-10-28

Multi-source investigation platform. Backward compatible with 0.3.0 configurations, result documents and deep links.

### Added

- **Source connectors**: Microsoft Sentinel (Azure Monitor Logs, versioned KQL templates), Splunk Enterprise / ES (REST search v2 export and job modes, windowed on `_indextime`), Microsoft Defender XDR (Graph Security `alerts_v2`, `incidents`), Microsoft Entra ID (`signIns`, `directoryAudits`), and a registry-facing Elastic wrapper for additional clusters.
- **Connection registry and supervisor**: one independent async worker per connection with backoff, `Retry-After`, per-source health (`healthy`, `paused`, `not_configured`, `permission_denied`, `limited_by_license`, `throttled`, `temporarily_unavailable`), pause/resume and credential rotation without losing cursors.
- **Shared HTTP layer**: pooled client, strict TLS with private CA support, host allowlisting, metadata/link-local refusal, `nextLink` pinned to the provider host, token scrubbing.
- **Microsoft token broker** (`azure-identity`): client secret, certificate and managed identity, cached per tenant/audience/profile.
- **Durable store** (`engine/store/`, SQLite WAL via `aiosqlite`): versioned migrations, event ledger with atomic page+cursor commits, revisions, alias-based duplicate suppression, encrypted raw-evidence vault, investigation revisions, notes, assignment, incident links, outbox, hash-chained audit, API tokens, bounded source-error log, online snapshot.
- **Source envelope** with scope, connection, canonical id, timestamps, content hash and provenance; citable evidence references (`SRC:<connection>:<kind>:<id>`).
- **ContextObservation** model and Entra context adapter (sign-ins, directory audits) - context never counts as a detection.
- **Adapters and mappings** for Sentinel, Splunk and Defender XDR (replacing the v1 stubs), with Splunk `field_aliases` and canonical ATT&CK tactic normalization for Microsoft's CamelCase labels.
- **Cross-source correlation**: per-alert provenance, connection-scoped finding ids, anchored cluster ids that survive restarts, merge aliases, correlator rebuild from the ledger at startup.
- **Risk breakdown**: severity evidence, independent source confirmation, attack progression, benign/conflicting context, with a versioned rule set per revision.
- **Identity enrichment** (`engine/enrich/identity.py`): strict, scope-bound UPN join within the chain window.
- **AI**: source-aware bounded evidence, per-source budget fitting, `<source_coverage>` and `<identity_context>` blocks, `evidence_refs` output field with validator grounding, untrusted-data rule in the system prompt, extended reports (sources, risk rationale, evidence appendix, identity context, response history).
- **Response** (`engine/response/`): allowlisted Azure Logic Apps workflows, typed payload schemas, role-based proposal/approval, separation of duties, expiry, idempotency keys, durable outbox, conservative delivery classification, crash recovery, manual reconciliation, three-layer status.
- **API** `/api/v2` (connections, investigations, evidence, timeline, graph, external links, notes, assignment, workflows, actions, audit, metrics), server-side roles, revision checks, write-only credentials, validation errors that never echo submitted values.
- **Identity**: role-bound API tokens, trusted-proxy identity, protected loopback owner; `loglookup token create|list|revoke`, `loglookup snapshot`.
- **Workspace**: Sources & Response drawer (connections, investigations by source, evidence inspector, response), source chips in the incident header.
- **Docs** under `docs/v2/`; README integration logos.

### Changed

- `Config` gains `scope_id`, `storage`, `sources`, `outputs.logic_apps`, `access` (all optional) and `correlation.risk.independent_source_weight`; the `siem:` block continues to work and is exposed as `elastic-default`.
- Result documents gain additive `schema_version`, `chain.sources`, `chain.risk_breakdown`.
- Report footer no longer says nothing is ever executed: AI recommendations are never executed automatically, and any response workflow requires explicit human approval.
- `deploy/systemd/loglookup.service` hardened (`ProtectSystem=strict`, restricted namespaces and address families, `UMask=0077`, ordered shutdown).
- New runtime dependencies: `aiosqlite`, `azure-identity`; pinned in `deploy/requirements-lock.txt`.

### Not included

Sentinel incident synchronisation, Defender Advanced Hunting enrichment, automated containment actions, and the optional AWS CloudTrail / GuardDuty / CrowdStrike Falcon / Nessus / Qualys connectors. The connector and adapter contracts are in place for them.
