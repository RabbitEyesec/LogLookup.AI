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

### Atomic settlement and restart recovery

- **Claim**: the dispatcher takes the next queued item and moves its action `queued -> dispatching` in **one transaction**, compare-and-set on both rows. A cancel that lands first wins: the item is marked `cancelled` and nothing is sent.
- **Settle**: the action's new state, the outbox delivery state and the audit entry commit together, compare-and-set on the action's current state. There is no window where an action is final but its outbox row is not.
- **Recovery on start** inspects every open outbox row against the action's real persisted state and never resends:

| Action state | Recovery |
|---|---|
| `queued` | outbox returns to `queued` (nothing was sent) |
| `dispatching` | action -> `reconciliation_required` (delivery unknown) |
| `acknowledged` / `completed` / `failed_without_effect` / `expired` / `cancelled` / `rejected` | the outbox label is repaired (`delivered`, `failed`, `expired`, `cancelled`); the action is left alone |
| `reconciliation_required` | outbox mirrors it |
| anything else, or no action | outbox marked `inconsistent`, surfaced for an operator; not sent |

## Remote status lookup (read-only)

`POST /api/v2/actions/{id}/check-status` (responder, audited, also a **Check remote status** button on the action card) asks Azure Resource Manager about the workflow run. It only ever sends `GET`; the original request is never sent again, by a lookup, by recovery or by reconciliation.

The Logic App auth profile gains an `arm` block (the credential needs a role that can read workflow runs, for example *Logic App Operator*, on that workflow or resource group - nothing that can run or change it):

```json
{"kind":"logic_app","auth":"entra","url":"https://....logic.azure.com/...","tenant_id":"<guid>",
 "credential":{"kind":"managed_identity"},
 "arm":{"plan":"consumption","subscription_id":"<guid>","resource_group":"rg1",
        "workflow_name":"notify","cloud":"public"}}
```

For **Standard** set `"plan":"standard"` and add `"site_name":"<Logic App (Standard) resource>"`. Consumption uses `Microsoft.Logic/workflows/{name}/runs` (api-version `2016-06-01`); Standard uses `Microsoft.Web/sites/{site}/hostruntime/runtime/webhooks/workflow/api/management/workflows/{name}/runs` (`2018-11-01`).

LogLookup sends its action id as `x-ms-client-tracking-id` with every request, so the run can be found again without guessing.

**How a run is chosen** - only two exact ways: the run id Azure returned, or the client tracking id. A run id that belongs to some other request is rejected. A list filter only narrows the search; every run is re-checked locally. **Zero or several matches select nothing** and the action stays `reconciliation_required`. A run is never chosen for being close in time or for its workflow name.

**What is stored** is Azure's own status (`Running`, `Waiting`, `Succeeded`, `Failed`, `Cancelled`, `TimedOut`), start/end time and error code/message (scrubbed, truncated), in `remote_status` / `remote_run` - separate from LogLookup's action state and from `downstream_effect`.

**What it may change** - one thing: an action in `reconciliation_required` becomes `acknowledged` when exactly one run with its tracking id exists and is Running, Waiting or Succeeded. That proves the request arrived. It does not prove the workflow did the right thing, so `downstream_effect` stays `not_observed`. A `Succeeded` run is never treated as proof of the downstream action. `Failed`, `TimedOut` and `Cancelled` runs may have done part of their work, so they never become `failed_without_effect` automatically, and a missing run proves nothing: both stay with a person. `downstream_effect` is only ever set by a person (`downstream_effect: "confirmed" | "absent"` on `/reconcile`).

## Revisions and pending proposals

A proposal is bound to the investigation revision it was made on. If the investigation changes (for example an alert is revised and the chain is re-scored) a **pending** proposal can no longer be approved, and an approved-but-unsent one is not dispatched: it expires with an audit entry (`action.superseded`) and must be proposed again against the current evidence. An action already dispatching or acknowledged is never touched.

## Three separate statuses

Every action reports (`status_layers`): LogLookup dispatch state, the workflow run (Azure's last reported status once checked, else the run reference), and the downstream effect (`not_observed` until a person records it). A `202` proves the workflow accepted the request - it does not prove an endpoint was isolated or an account changed, and the UI says so.

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
