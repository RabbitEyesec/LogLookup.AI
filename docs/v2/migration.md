# Migration to v2.0.0 / v2.0.1

## Upgrading v2.0.0 to v2.0.1

1. **Snapshot** the store first: `loglookup snapshot /safe/place/pre-2.0.1.sqlite3`, and back up `config.yaml`, `secrets.key`, `secrets.enc` as above.
2. Stop the service, install 2.0.1, start it. **Migration 2 is additive** and applies automatically: it adds `source_event_revisions` (and copies one row per revision already stored) and `ingest_work_items`. Nothing is deleted or rewritten; existing evidence, cursors, investigations, actions and audit entries are untouched.
3. **Cursors**: Sentinel and Splunk timestamp-only cursors migrate on first poll by re-reading a bounded overlap (`lookback_seconds`) before the last committed window. The ledger drops what is already stored. Sources show `CURSOR_MIGRATED_FROM_V1` once.
4. **Splunk**: `search_mode: export` keeps working but runs as snapshot jobs (`EXPORT_MODE_RETIRED`); switch your config to `jobs`. Check `max_event_age_seconds` (see provider configuration).
5. **If a tie group may have been skipped under 2.0.0**, run a bounded backfill over the affected UTC interval per connection and stream (see security-and-operations). Do not run an unbounded historical backfill.
6. **Changing a connection's workspace, indexes or query template** stops that connection's scan (`CURSOR_CONFIG_CHANGED`). The saved cursor is preserved. An administrator confirms a new scan or runs a bounded backfill; the decision is audited and the replaced cursor is kept in `source_cursor_history`.
7. Existing API payloads are unchanged; new health fields are additive.

### Rollback from 2.0.1

Stop the service, restore the **pre-upgrade snapshot** and the 2.0.0 build. Never downgrade by editing rows in place: migration 2 tables are left for 2.0.1 to read again. Before restoring, export anything created after the snapshot (actions, audit entries, evidence) for operator reconciliation, because the restore discards it. Rolling back never repeats an acknowledged action; actions in `reconciliation_required` stay recorded and are resolved by a person.

## What stays the same

OCSF Detection Finding (`class_uid` 2004); correlation and risk before AI; `CHAIN-YYYY-MM-DD-<entity>-NNN` ids; Elasticsearch result documents and `/incident/<cluster_id>` links; the existing routes (`/api/status`, `/api/clusters...`, `/api/attack/techniques`, `/api/settings/ai`); the `loglookup serve|open|status|version` commands. v2 fields on result documents are additive (`schema_version`, `chain.sources`, `chain.risk_breakdown`).

## Upgrade

1. **Back up** the application home (`~/.config/loglookup` or `$LOGLOOKUP_HOME`): `config.yaml`, `state.json`, `secrets.key`, `secrets.enc`. Keep the backup access-restricted.
2. Install v2.0.0 (`bash deploy/install.sh` or `pip install -c deploy/requirements-lock.txt .`).
3. Start it. The store is created at `<home>/var/loglookup-v2.sqlite3` and its schema migrated automatically (idempotent, versioned in `schema_migrations`).
4. The existing `siem` configuration appears as connection **`elastic-default`** and keeps polling from `state.json` exactly as before. Nothing is rewritten.
5. Add Sentinel, Splunk, Defender XDR and Entra ID connections one by one. They are created disabled.
6. Leave `outputs.logic_apps.enabled: false` until approval roles exist.

Previous investigations are not touched: existing Elastic documents keep their ids and are read as before. v2 does not rewrite history to look v2-native.

## Schema

| Item | Value |
|---|---|
| Store schema version | 3 |
| Location | `<home>/var/loglookup-v2.sqlite3` (`storage.db_path`, relative to the home) |
| Tables | source_cursor_history, investigation_review_flags (migration 3, plus `remote_status`, `remote_status_at`, `remote_run_json`, `downstream_effect` on `response_actions`); source_event_revisions, ingest_work_items (migration 2); connections, source_cursors, source_events, source_aliases, processed_observations, context_observations, investigations, investigation_events, investigation_revisions, cluster_aliases, incident_links, analyst_notes, response_actions, outbox, audit_events, api_tokens, source_errors |

## Rollback

1. Stop the service. Take `loglookup snapshot <path>` first if you want a consistent copy.
2. Disable new connections and the response dispatcher (`enabled: false`).
3. Restore the previous release and the backed-up home. The v2 store, ledger, cursors and outbox are left in place, not deleted.

Rolling back never repeats an acknowledged remote action: actions already acknowledged or in `reconciliation_required` stay recorded, and the dispatcher only sends `queued` items it has not claimed.

## Configuration changes

New optional sections: `app.scope_id`, `storage`, `sources`, `outputs.logic_apps`, `access`, and `correlation.risk.independent_source_weight`. See `config.example.yaml`. Safety switches that cannot be configured off: `storage.evidence_encryption`, `outputs.logic_apps.require_explicit_approval`, and `unknown_delivery_policy: reconcile`.

## Single-writer boundary

One LogLookup v2 process per application home. A clustered or multi-writer deployment needs a database service and a separate design.
