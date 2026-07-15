# Architecture

## 1. Overview

LogLookup AI is a staged investigation pipeline that runs alongside Elastic Security. Each stage consumes structured output from the previous stage. Deterministic stages form and score an attack chain before the optional AI stage evaluates it.

```text
Elastic Security
  -> Elastic connector
  -> source adapter
  -> OCSF Detection Finding
  -> deterministic pre-filter
  -> entity resolution
  -> attack-chain correlation
  -> risk scoring
  -> ATT&CK retrieval and optional AI triage
  -> grounding validation and report generation
  -> Elasticsearch result write-back
  -> Kibana and LogLookup AI dashboard
```

![Elastic alerts entering the pipeline](images/elastic-alerts-overview.png)

*Figure 1. Elastic Security alerts are the source records for the investigation pipeline.*

## 2. Architectural Contracts

The implementation depends on four stable contracts:

- OCSF Detection Finding (`class_uid` 2004) is the canonical normalized schema.
- Correlation and risk scoring run before AI reasoning.
- Chain identifiers use `CHAIN-YYYY-MM-DD-<entity>-NNN`.
- Elasticsearch is the durable result store; dashboard deep links use `/incident/<cluster_id>`.

Changing one of these contracts affects stored results, tests, API consumers, or deep links and should be treated as an architectural change.

## 3. Processing Components

### 3.1 Ingestion and Elastic connector

`engine/connectors/elastic.py` performs authenticated HTTP operations against Elasticsearch. It supports bounded reads, continuous polling, index discovery, connection checks, and result-index operations. `engine/ingest.py` converts file or Elastic input into `RawRecord` values.

Polling advances a persisted cursor in managed mode. On restart, the service resumes from that cursor instead of starting at the current time. Alert UID deduplication and idempotent write-back make overlap safe.

### 3.2 Source adapters and OCSF normalization

Adapters in `engine/normalize/adapters/` map source fields into the internal OCSF representation. The Elastic adapter is the supported live path. File input is used by fixtures and offline runs.

Normalization handles:

- event and ingestion timestamps;
- severity labels and numeric identifiers;
- rule, action, category, and message fields;
- hosts, users, processes, IP addresses, domains, and files; and
- retention of raw source evidence and parse flags.

### 3.3 Deterministic pre-filter

`engine/prefilter/rules.py` evaluates explicit allowlists for trusted IP ranges, expected service accounts, and approved scanner hosts. Suppressed records do not reach correlation or AI. This is a configured rule decision, not a model judgment.

### 3.4 Entity resolution

`engine/correlate/entities.py` resolves observations into investigation entities using configured precedence such as process GUID, user principal name, MAC address, and IP address. Resolution is time-aware so later state does not overwrite the entity attribution of an earlier event.

### 3.5 Correlation

`engine/correlate/engine.py` and `engine/correlate/chains.py` group related events within the configured window. Correlation considers shared entities, event order, and time. A watermark provides tolerance for out-of-order arrivals, and old chains are pruned from live memory after the retention interval.

![Structured correlation evidence](images/correlation-evidence.png)

*Figure 2. Correlation output records the stable chain identifier, event window, deterministic disposition, risk, and primary entity.*

### 3.6 Risk scoring

`engine/correlate/risk.py` accumulates configured severity weights on resolved entities. A chain becomes surfaced when an entity crosses `surface_threshold`. A configurable downgrade can reduce risk for logically conflicting ATT&CK tactic sequences.

### 3.7 ATT&CK retrieval and AI triage

The AI path runs only for chains selected by `ai.triage_scope` and only when its dependencies are available.

1. `engine/ai/payload.py` flattens and bounds the chain evidence.
2. `engine/ai/retriever.py` selects ATT&CK candidates using lexical BM25 or an optional FAISS embedding index.
3. `engine/ai/provider.py` calls the configured local or cloud provider through LiteLLM.
4. `engine/ai/reasoner.py` requests the validated verdict schema.
5. `engine/ai/validator.py` checks technique and cited-field grounding.
6. `engine/ai/report.py` produces the investigation report.

Cloud providers can use tokenized evidence through `engine/redact/redactor.py`. When a provider, model, or knowledge base is unavailable, the service records that state instead of fabricating a verdict.

![Investigation pipeline result](images/investigation-workspace.png)

*Figure 3. The dashboard presents deterministic events, graph relationships, AI output, raw evidence, and entity context without recomputing the stored result.*

### 3.8 Result write-back

`engine/connectors/writeback.py` builds the result document and writes it to the configured `output.results_index`. The document includes `cluster_id` and `dashboard_url`; using the chain identifier as the idempotency key prevents duplicate results for the same chain.

![Elastic case after investigation](images/elastic-case-writeback.png)

*Figure 4. Elastic remains part of the analyst workflow after correlation and reporting.*

## 4. Runtime Modes

### Managed application

`loglookup serve` uses `engine/app.py` and `ManagedSettings`. Configuration lives under the XDG-aware application home, first-run setup gates polling, credentials are injected from the encrypted store, and UI changes are applied without restarting the process. The installer can run this mode as a systemd user service.

### Development server

`python -m engine.server` reads `config.yaml`, optionally ingests a fixture or polls Elastic, and serves the API and dashboard in the same process.

### Headless pipeline

`python -m engine.pipeline` runs file, batch, or poll ingestion without the dashboard. AI triage and write-back are opt-in flags.

## 5. API and Presentation Layer

`engine/api/server.py` exposes status, cluster, timeline, graph, ATT&CK, and AI settings endpoints. `engine/api/setup.py` contains onboarding, SIEM validation, local-model management, provider validation, and SIEM settings routes.

The browser interface is served from `engine/dashboard/static/`. It renders stored chain documents and view models from `engine/api/views.py`; it does not re-run correlation or AI analysis for display. Re-triage is a distinct API operation against a chain held by the live engine.

## 6. Configuration and State

`engine/config.py` defines typed sections for SIEM, engine, correlation, pre-filter, AI, retrieval, and output settings. In development mode, `${ENV_VAR}` references in YAML are expanded at load time.

Managed mode stores:

- non-secret settings in `config.yaml`;
- a polling cursor in `state.json`;
- the generated secret-store key and encrypted credential blob in owner-only files;
- an uploaded Elastic CA certificate when configured; and
- ATT&CK knowledge-base and retrieval data under the application home.

These runtime files are local state and are excluded by repository ignore rules.

## 7. Failure Behavior

- Parse problems are flagged on normalized events instead of silently discarded.
- Connection and provider failures are surfaced through status and error responses.
- A missing AI dependency leaves deterministic chain data available.
- A missing historical result returns `404`; the API can fall back to the Elasticsearch results index when a reader is configured.
- Poll cursor read failures degrade to an unset cursor and are logged.
- Write-back uses stable identifiers so retries do not create a second chain document.

## 8. Trust Boundaries

Elastic credentials and cloud provider keys cross the onboarding/API boundary as write-only values. Managed settings divert them to the encrypted secret store and omit them from YAML and settings responses. The Elastic connector and AI provider are the outbound network boundaries. The dashboard should therefore be deployed with host access controls appropriate to the environment; the repository does not add an external identity provider or reverse-proxy policy.

