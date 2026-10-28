# Azure Logic Apps response contract

LogLookup **prepares and authorises** response work; Azure Logic Apps **executes** it. The channel is off by default and nothing is dispatched without a recorded human approval.

## Built-in workflows

| `workflow_id` | Operation | Separation of duties | Payload fields |
|---|---|---|---|
| `notify-soc-v1` | `notify_analyst` | no | `message`, `severity` |
| `create-incident-v1` | `create_or_update_incident` | **yes** | `title`, `severity`, `summary?` |
| `request-enrichment-v1` | `request_enrichment` | no | `entity_type` (`user`/`device`/`ip`), `entity_value` |
| `handoff-escalation-v1` | `hand_off_escalation` | **yes** | `team`, `summary` |

Only workflows named in `outputs.logic_apps.allowed_workflows` can be proposed. Payload fields are typed, length-bounded and enum-checked; unknown fields are rejected. There is no containment workflow (isolate host, disable account, reset credentials); those require a separately designed, permissioned and approved addition.

## Contract sent to the workflow

```json
{
  "schema_version": "2.0",
  "workflow_id": "notify-soc-v1",
  "action_id": "uuid",
  "idempotency_key": "sha256(scope|logic_apps|workflow|cluster|revision|payload hash)",
  "cluster_id": "CHAIN-2026-10-28-WS01-001",
  "investigation_revision": 4,
  "scope_id": "org-local",
  "requested_by": "ann",
  "approved_by": ["rob"],
  "approved_at": "2026-10-28T01:00:00Z",
  "evidence_refs": ["SRC:sentinel-main:alert:..."],
  "requested_operation": "notify_analyst",
  "payload": {"message": "...", "severity": "high"}
}
```

HTTP headers: `Idempotency-Key`, `X-LogLookup-Action-Id`. The workflow should de-duplicate on `idempotency_key`.

## State machine

```text
proposed -> approval_required -> approved -> queued -> dispatching -> acknowledged -> completed
                  |                                        |-> failed_without_effect
                  |-> rejected / expired / cancelled       '-> reconciliation_required
```

`reconciliation_required` resolves only to `acknowledged` or `failed_without_effect`. Terminal states cannot be revived; a rejected proposal frees its idempotency key so it can be proposed again as a **new** action.

## Delivery classification (never blind retries)

| Observation | Result |
|---|---|
| 2xx | `accepted`: `acknowledged`, run reference kept |
| HTTP 4xx / 429, connection never established, token failure | `rejected`: `failed_without_effect` |
| 5xx, timeout after send, protocol error | `unknown`: `reconciliation_required` |
| Process stopped mid-send | `reconciliation_required` on restart |

An ambiguous delivery is **never** resent automatically. An authorised responder checks the original run (by `action_id` / run reference) and records the outcome with `POST /api/v2/actions/{id}/reconcile` (`delivered` | `not_delivered`).

A claimed outbox item whose `dispatching` state was never recorded cannot have been sent, so it is safely re-queued.

## Three separate statuses

Every action reports (`status_layers`): LogLookup dispatch state, workflow-run reference, and downstream effect. A `202` proves the workflow accepted the request - it does not prove an endpoint was isolated or an account changed, and the UI says so.

## Authentication

Prefer an Entra-protected Request trigger (`auth: entra`, audience `https://management.core.windows.net/` by default, a token from the profile's Microsoft credential). A SAS callback URL (`auth: sas`) is accepted but is a bearer secret: it lives only in the encrypted profile and is never logged or shown. The URL must be HTTPS on `*.logic.azure.com`, `.us`, `.cn` or `*.azurewebsites.net`.

Profile (stored encrypted under `outputs.logic_apps.auth_profile_id`):

```json
{"kind":"logic_app","auth":"entra","url":"https://....logic.azure.com/...","tenant_id":"<guid>",
 "credential":{"kind":"client_secret","client_id":"...","client_secret":"..."}}
```

## Approval rules

- Proposing needs `analyst`; approving/rejecting needs `responder`.
- Workflows with separation of duties refuse approval by the requester.
- One approver cannot approve twice; time-to-live (default 1 h) expires unapproved actions.
- Stale revisions are refused with `409`; evidence references must belong to the investigation.
