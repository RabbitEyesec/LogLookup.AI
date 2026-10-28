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

New alert **revisions** are stored and inspectable in the evidence view. The correlator keeps its first view of an alert within a chain; the newer payload does not re-score an existing chain.

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

A connector acquires **unaltered vendor records** and says how to identify them. It does no correlation. `PageResult` carries `records`, `next_cursor`, `window_complete` and `source_warnings`. A full page returns `window_complete=False` with a continuation cursor, so results above a cap continue on the next call instead of being dropped.

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
| Sentinel | Azure Monitor Logs query API, versioned KQL template `security-alert-v1` (`arg_max` by `SystemAlertId`) | `TimeGenerated`, bounded overlap | `SystemAlertId` + workspace |
| Splunk | `/services/search/v2/jobs/export` or `/jobs` + paged `/results` | `_indextime` (event time stays `_time`) | `event_id`, else `index:_cd`, else content hash |
| Defender XDR | Graph `security/alerts_v2`, `security/incidents` | `lastUpdateDateTime`, `@odata.nextLink` | Graph `id` + tenant |
| Entra ID | Graph `auditLogs/signIns` (`createdDateTime`), `directoryAudits` (`activityDateTime`) | bounded overlap | Graph `id` + tenant |

Splunk windows on index time deliberately: a late-indexed event is still collected without relabelling its event-time position.
