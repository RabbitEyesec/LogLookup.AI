# Provider configuration

Every source starts **disabled**. Enable one at a time, after its credential and permissions exist. Configure in the UI (Sources -> Add a connection) or under `sources:` in `config.yaml`. Secrets never go in YAML.

## Credentials

A connection references an **auth profile** by id. The profile's secret value is stored AES-256-GCM encrypted in the local secret store (`secrets.enc`); the API accepts it write-only and never returns it. Rotating a credential replaces the secret and keeps the connection's cursor and history.

Config-file deployments can supply a profile without the UI through an environment variable: `LOGLOOKUP_AUTH_<PROFILE_ID>` (upper-case, non-alphanumerics as `_`).

| Provider | Profile value |
|---|---|
| Elastic | `{"kind":"api_key","api_key":"..."}` or the bare key |
| Splunk | `{"kind":"token","token":"..."}` or the bare token |
| Microsoft (Sentinel, Defender XDR, Entra ID) | `{"kind":"client_secret","client_id":"...","client_secret":"..."}`, `{"kind":"certificate","client_id":"...","certificate_pem":"..."}` or `{"kind":"managed_identity"}` |

Microsoft tokens are acquired per **audience** and cached per tenant/audience/profile. A Graph grant does not give Azure Monitor workspace access, and the two are never mixed.

## Elastic Security

```yaml
- id: elastic-prod
  provider: elastic
  auth_profile_id: elastic-prod-key
  options: { host: "https://elastic.example:9200", alert_index: ".alerts-security" }
```

Needs an API key with read on the alert index. The original single-cluster `siem:` block keeps working and appears as connection `elastic-default` (polled by the original path). Additional clusters run through the connection supervisor.

## Microsoft Sentinel (KQL)

```yaml
- id: sentinel-main
  provider: sentinel
  auth_profile_id: azure-reader
  options:
    tenant_id: <guid>
    workspace_id: <guid>
    cloud_environment: public        # public | usgov | china
    enabled_tables: [SecurityAlert]
    max_rows: 500
```

Requires **Log Analytics Reader** on the workspace (Azure RBAC). Only tables with a reviewed KQL template are accepted; KQL is built from stored templates with typed window parameters, never from free text.

## Splunk Enterprise / Enterprise Security (SPL)

```yaml
- id: splunk-es
  provider: splunk
  auth_profile_id: splunk-reader
  options:
    management_url: https://splunk.example:8089
    indexes: [notable]               # allowlisted names only
    search_mode: jobs                # snapshot search job (export is retired and runs as jobs)
    api_namespace: { owner: nobody, app: SplunkEnterpriseSecuritySuite }  # optional
    max_event_age_seconds: 86400     # 0 = no event-time floor (collect purely by index time)
    max_results: 500                 # results fetched per page from the snapshot job
```

Needs a Splunk authentication token whose role may search the listed indexes and read search jobs it created. `max_event_age_seconds` is an explicit event-time floor (reported as `EVENT_TIME_FILTER_ACTIVE` and shown on the source card); an event indexed today whose `_time` is older than the floor is excluded by design. `0` removes the floor (`FULL_INDEX_TIME_COLLECTION`): complete by index time, but slower and costlier on large indexes. A controlled backfill can set its own floor without touching this setting. Index names are validated against a strict pattern, so `main | delete` cannot reach SPL. TLS is verified; supply a private CA with `tls.ca_bundle_path` rather than disabling verification. Site-specific field names are mapped with the adapter's `field_aliases`.

## Microsoft Defender XDR

```yaml
- id: defender-xdr
  provider: defender_xdr
  auth_profile_id: graph-reader
  options: { tenant_id: <guid>, streams: [alerts, incidents] }
```

Graph application permissions `SecurityAlert.Read.All` and `SecurityIncident.Read.All` with admin consent. `providerAlertId` and `serviceSource` are first-class provenance.

## Microsoft Entra ID

```yaml
- id: entra-id
  provider: entra_id
  auth_profile_id: graph-reader
  options: { tenant_id: <guid>, streams: [signins, directory_audits] }
```

Graph application permission `AuditLog.Read.All`. Sign-in logs require Entra ID P1/P2 licensing; a licence gap shows as `limited_by_license`. Conditional Access policy detail and risk data that the tenant does not return are recorded as *unavailable*, never inferred.

## Common options

`poll_seconds` (>= 5), `lookback_seconds` (initial look-back and overlap), `max_page_size` (1-5000), `tls.verify`, `tls.ca_bundle_path`, `scope_id`.

## Network boundaries

Connector targets are validated before any request: HTTPS required, link-local/cloud-metadata addresses refused, loopback refused except for a locally hosted Elastic/Splunk, and a server-supplied `@odata.nextLink` may only point back to the configured Graph host.
