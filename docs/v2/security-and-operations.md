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

## Metrics

`GET /api/v2/metrics` and `GET /api/v2/sources/health`: per-source status, last receipt, committed and quarantined counts, outbox backlog, `reconciliation_required` count, active investigations, AI availability, schema version.

## Service

`deploy/systemd/loglookup.service` runs with `ProtectSystem=strict`, private devices/tmp, restricted address families and namespaces, `UMask=0077`, `Type=notify` and a watchdog. Shutdown order: stop accepting requests, cancel source workers (clients closed), stop the dispatcher (an in-flight send is not retried), checkpoint WAL.

## Operating checklist

1. Create an auth profile and the least-privilege grant listed in [provider-configuration.md](provider-configuration.md).
2. Add the connection (it saves disabled), then enable it; watch its card turn `healthy`.
3. Confirm `GET /api/v2/investigations` shows the source badge you expect.
4. Create tokens for people other than the local owner.
5. Enable the response channel only after the approval roles are in place ([logic-apps-contract.md](logic-apps-contract.md)).
