# Changelog

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
