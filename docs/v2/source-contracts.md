# Source contracts

How a vendor record becomes evidence, an observation, or an investigation. Every v2 source follows the same contract, so adding a provider changes a connector and an adapter, not the engine.

## Records and kinds

| Kind | Produced by | Becomes | Counts as a detection |
|---|---|---|---|
| `alert` | Elastic, Sentinel, Splunk, Defender XDR | OCSF Detection Finding (`class_uid` 2004) | Yes |
| `incident` | Defender XDR | External-case link (`incident_links`) | No |
| `signin` | Entra ID | `ContextObservation` | No |
| `directory_audit` | Entra ID | `ContextObservation` | No |

Context never inflates an alert count and is never called malicious by LogLookup. Identity context is joined to a chain only through a scope-bound UPN/email seen on one of that chain's alerts, inside the chain's time window plus a 30-minute margin.

## Source envelope (`engine/envelope.py`)

Every record is wrapped in a `SourceEnvelope` before anything else happens:

| Field | Meaning |
|---|---|
| `scope_id`, `connection_id`, `provider` | Where it came from; the scope travels through every record |
| `record_kind`, `source_event_id` | Vendor identity |
| `canonical_event_id` | `sha256(scope, provider, connection, namespace, kind, source id)` - deterministic, connection-bound |
| `source_incident_id`, `source_url` | Provider case link (https only; never fetched by the server) |
| `event_time`, `source_updated_at`, `observed_at` | Event time, vendor update time, ingestion time - kept separate |
| `raw_sha256`, `raw_payload_ref` | Hash of the canonical payload and a pointer to its encrypted ledger copy |
| `revision` | 1 for first sight; incremented when the vendor payload changes |
| `provenance` | Platform, service source, tenant/workspace, provider alert id |
| `aliases` | `(scheme, value)` pairs that identify the same event in another API |

Citable evidence reference: `SRC:<connection_id>:<record_kind>:<source_event_id>`. The AI layer may cite only references that were supplied in its input.

## Ledger semantics (`engine/store/ledger.py`)

A page and its cursor are committed in **one transaction**; the cursor never moves ahead of durable data. Acquisition is at-least-once with intentional overlap, and the ledger turns that into exactly-once-per-revision:

- same canonical id + same hash -> ignored;
- same canonical id + different hash -> new revision (an update, not a new alert);
- different canonical id + shared alias -> stored, flagged `duplicate_of`, kept out of correlation.

The Sentinel connector and the Graph connector both register `ms_alert:microsoftSentinel` aliases (Sentinel `SystemAlertId` / `VendorOriginalId`; Graph `providerAlertId` when `serviceSource` is `microsoftSentinel`). A Sentinel-origin alert that arrives through both paths counts once. Identifiers that do not match are never merged on title, user or time.

### Alert revisions

A vendor payload that changes for an alert already stored is detected by canonical event id and payload hash. It is saved as a new **source revision** (every revision keeps its own immutable encrypted payload in `source_event_revisions`) and queued as a `revise` work item. Applying it never changes the alert count:

1. The new payload is normalised and compared with the preceding version on the security-relevant parts: severity, title, ATT&CK tags, process, and (for membership) event time, host, user and network endpoints.
2. **Nothing relevant changed** - the stored representation is replaced, nothing else happens, and no investigation revision is created.
3. **Only scoring inputs changed** (severity, title, ATT&CK, process) - the finding is replaced in place and the chain's risk, risk breakdown, ATT&CK progression and independent-source confirmation are recomputed from the current evidence.
4. **Identity or time changed** - membership is re-evaluated, but only when the result is deterministic: removing the alert must not split its chain, and once placed again it must still connect to that chain. Otherwise nothing is changed, the revision is stored, and a **review flag** is raised for an analyst (`/api/v2/investigations/{id}/review-flags`). History is never silently rewritten.
5. A new **investigation revision** is saved only when the investigation state materially changes (alerts, surfaced state, risk, disposition, ATT&CK sequence, risk components, independent providers, who each alert is about, or an open review flag). It records the previous revision and score, what triggered it (source revision, hash, effect), the rule version, and the exact source revision every alert was scored from. Earlier investigation revisions and earlier source payloads stay readable.
6. An AI analysis written before the change is kept but marked **stale** (`triage_stale`); it is not re-run and no response is proposed automatically.
7. A pending response proposal is checked against the current investigation revision before approval and again before dispatch; if the investigation moved on it expires and must be proposed again. An action already in flight is never touched.

Revisions are applied in order: if the original alert is still waiting in the queue, the revision waits and retries.

### Durable hand-off to correlation

The evidence, the source cursor and a **work item** (`ingest_work_items`) are written in one transaction. A consumer drains the queue into the correlator and acknowledges each item only after the pipeline accepted it:

```text
queued_for_correlation -> claimed -> correlated        (processed_observations / work item)
                              '-> failed_retryable (backoff) -> quarantined after 8 attempts
updated payload of a known alert -> operation "revise"   (re-scores the same finding, never a second detection)
duplicate / context / incident link -> ingested         (stored, not queued as a detection)
```

- A page may advance the acquisition cursor while correlation is down; nothing accepted is ever lost, and the backlog drains on restart.
- Intake is idempotent per `canonical_event_id`: a consumer that crashed after processing but before acknowledging, or history replayed at startup and then met again in the queue, cannot count a detection twice.
- Items claimed by a dead process are returned to `pending` on start; a lease also reclaims them while running.
- Retention (`storage.raw_retention_days`) never drops a payload that unresolved work still needs.
- Acquisition, storage and correlation are reported separately in source health.

## Connector contract (`engine/connectors/base.py`)

```python
class SourceConnector(Protocol):
    provider: str
    streams: tuple[str, ...]
    async def open(self) -> None: ...
    async def fetch_page(self, cursor, stream="default") -> PageResult: ...
    def identify(self, record, stream) -> RecordIdentity: ...
    async def close(self) -> None: ...
```

A connector acquires **unaltered vendor records** and says how to identify them. It does no correlation. `PageResult` carries `records`, `next_cursor`, `window_complete` and `source_warnings`. A full page returns `window_complete=False` with a continuation cursor, so results above a cap continue on the next call instead of being dropped. A connector never "escapes" a stuck page by nudging a timestamp: a partial or truncated provider result, a row without a stable key, or a page that does not advance raises an error, the committed cursor stays where it was, and the source reports `degraded`.

### Cursor format v2

```json
{"cursor_version": 2, "kind": "sentinel_kql | splunk_job", "fingerprint": "<hash>",
 "template_version": "...", "window_start": "<UTC>", "window_end": "<UTC>",
 "continue": true, "watermark": "<UTC, last drained window end>",
 "last_time": "...", "last_source_id": "...",        // Sentinel composite seek key
 "job_sid": "...", "offset": 500}                      // Splunk snapshot position
```

- **Frozen window**: a multi-page scan keeps its `window_start`/`window_end`; the next scan restarts `lookback_seconds` before the drained window's end (an intentional overlap the ledger de-duplicates).
- **Fingerprint**: hash of everything the cursor depends on (workspace/tenant/tables, or Splunk host/indexes/namespace/event-time floor, plus the query template version). A cursor with another fingerprint is never continued and never reset automatically: the page fails with `CURSOR_CONFIG_CHANGED`, the original cursor (and any Splunk `sid`) is preserved, and the source shows `degraded`. An administrator then either confirms a new scan (`POST /connections/{id}/cursor/confirm`: the old cursor goes to `source_cursor_history`, the decision to the audit log) or runs a bounded backfill.
- **v2.0.0 cursors** (timestamp only) migrate by a bounded overlap re-read and report `CURSOR_MIGRATED_FROM_V1`.
- **Watermark** is the end of the last fully drained window. Source lag is `now - watermark` (reported as `null`, never `0`, when there is none).

Capabilities are advertised through the registry (`engine/connectors/registry.py`) and surfaced in the UI: `alerts`, `incidents`, `identity_context`, `query_language`, `writeback`.

### Adding a provider

1. Implement a connector (`fetch_page`, `identify`) under `engine/connectors/`.
2. Add a mapping YAML and an adapter under `engine/normalize/adapters/` (or a context adapter for non-detections).
3. Register a `ProviderSpec` in `registry.py` and add the provider to `PROVIDERS`.

No change to the correlator, ledger, API or UI is required.

## Failure classification

Each source reports one of: `healthy`, `starting`, `paused`, `not_configured`, `permission_denied`, `limited_by_license`, `throttled`, `temporarily_unavailable`. They render differently in the UI, and a failing or disabled source is never drawn as healthy. A malformed individual record is quarantined (`source_errors`, hash reference only) without halting its page.

## Per-source query behaviour

| Provider | Transport | Window | Dedup identity |
|---|---|---|---|
| Elastic | `_search` on the alert index | `@timestamp`, inclusive resume | `_id` |
| Sentinel | Azure Monitor Logs query API, versioned KQL template `security-alert-v2` (`arg_max` by `SystemAlertId`, then composite seek, ordered by `TimeGenerated, SystemAlertId`) | `TimeGenerated`, frozen window per scan, bounded overlap | `SystemAlertId` + workspace |
| Splunk | One snapshot search job per window (`/search/v2/jobs`), paged `/results?offset&count`, sorted by `_indextime, index, _cd`, no `head` | `_indextime` (event time stays `_time`) | `event_id`, else `index:_cd` (an unidentifiable row is an error) |
| Defender XDR | Graph `security/alerts_v2`, `security/incidents` | `lastUpdateDateTime`, `@odata.nextLink` | Graph `id` + tenant |
| Entra ID | Graph `auditLogs/signIns` (`createdDateTime`), `directoryAudits` (`activityDateTime`) | bounded overlap | Graph `id` + tenant |

Splunk windows on index time deliberately: a late-indexed event is still collected without relabelling its event-time position.

### Sentinel paging

Equal-timestamp groups are fully reachable: the continuation predicate is `TimeGenerated > last_time or (TimeGenerated == last_time and SystemAlertId > last_id)`, applied after the per-alert `summarize arg_max`, so a later page cannot resurrect an older version of an alert or lose the rest of a group. `last_time` is the provider's own 100 ns string, never re-formatted. KQL comes from two reviewed templates; every value interpolated into them is validated against a strict pattern first.

### Splunk snapshot jobs

The job is created once, kept alive (`timeout=3600`) while drained, and released when drained. Completion is decided from the job's own `resultCount`, never from `len(rows) == limit`. A finalised or truncated job fails the page. If the job is gone, the same frozen window is searched again from offset 0 (`SNAPSHOT_EXPIRED_REPLAYING`); the ledger absorbs the repeat. The streaming export endpoint is retired because it cannot be resumed or proven complete.

`max_event_age_seconds` (default 86400) also bounds the event `_time` at collection. That is a filter, not lossless index-time capture, and is reported as `EVENT_TIME_FILTER_ACTIVE`. Set it to `0` to collect purely by index time.
