# Developer Guide

## 1. Scope

This guide covers local development, configuration, module boundaries, API routes, tests, and release checks for LogLookup AI. The architectural contracts are documented in [architecture.md](architecture.md); changes to those contracts are outside a routine contribution.

## 2. Requirements

- Python 3.11, 3.12, or 3.13
- Git
- Linux for installer and systemd validation
- Elasticsearch and Kibana for live connector testing
- Ollama or a supported cloud provider only when testing AI triage

The unit suite uses fixtures and test doubles for most external dependencies. A live Elastic or AI service is not required for the standard test run.

## 3. Repository Layout

```text
deploy/
  install.sh                 per-user Linux installer
  uninstall.sh               per-user uninstaller
  requirements-lock.txt      release dependency constraints
  systemd/                   user-service unit
  icons/                     desktop icon
engine/
  ai/                        ATT&CK KB, retrieval, providers, reasoning, validation
  api/                       FastAPI routes and dashboard view models
  connectors/                Elastic read and write-back clients
  correlate/                 entities, chains, risk, and correlation state
  dashboard/static/          HTML, CSS, JavaScript, and vendored graph library
  normalize/adapters/        source adapters and mapping files
  prefilter/                 deterministic allowlist rules
  redact/                    context-preserving cloud redaction
  secure/                    encrypted local secret store
  app.py                     managed application CLI
  config.py                  typed configuration
  ingest.py                  file and Elastic record acquisition
  pipeline.py                deterministic pipeline CLI
  server.py                  development server CLI
docs/                        product, architecture, user, and developer guides
tests/                       unit, integration-style, and acceptance tests
config.example.yaml          development configuration template
preview_ui.py                isolated dashboard preview server
pyproject.toml               package metadata and dependencies
```

## 4. Local Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp config.example.yaml config.yaml
```

For embedding-based ATT&CK retrieval, install the optional dependency group:

```bash
.venv/bin/pip install -e '.[rag]'
```

The `rag` extra downloads a larger machine-learning dependency set. Without it, `backend: auto` falls back to the deterministic lexical retriever.

Set secrets in the shell used to launch config-file mode:

```bash
export LOGLOOKUP_SIEM_KEY='YOUR_API_KEY'
export LOGLOOKUP_AI_KEY='YOUR_AI_API_KEY'  # cloud providers only
```

Do not add credentials to `config.yaml`, test fixtures, screenshots, or shell-history examples.

## 5. Running the Application

### UI-only preview

```bash
python3 preview_ui.py
```

Open `http://127.0.0.1:4173/?preview=1`. The preview does not start the engine, read credentials, contact Elastic, or call an AI provider.

### Fixture-backed development server

```bash
.venv/bin/python -m engine.server \
  --config config.yaml \
  --input tests/fixtures/attack_chain.ndjson
```

Open `http://localhost:8080`.

### Continuous Elastic polling

```bash
.venv/bin/python -m engine.server \
  --config config.yaml \
  --mode poll \
  --writeback
```

Use `--no-ai` to validate the deterministic server path without triage. For a bounded Elastic read, use `--mode batch --since <time> --until <time>`.

### Headless pipeline

```bash
.venv/bin/python -m engine.pipeline \
  --config config.yaml \
  --input tests/fixtures/attack_chain.ndjson \
  --triage
```

The pipeline requires either `--input`, `--mode batch`, or `--mode poll`. `--writeback` is independent of `--triage`.

### Managed application

```bash
bash deploy/install.sh
loglookup serve
```

Managed mode stores settings under the application home and presents onboarding until setup is complete. Use `LOGLOOKUP_HOME` to override that directory during isolated testing.

![First-run setup](images/setuppage.png)

*Figure 1. Managed mode redirects an unconfigured installation to the onboarding wizard.*

## 6. Configuration

`config.example.yaml` is the reference for development mode. The main sections are:

- `siem`: Elastic endpoint, key interpolation, alert index, polling, severity floor, and TLS settings;
- `correlation`: window, evaluation cadence, watermark, retention, entity precedence, and risk weights;
- `prefilter`: explicit trusted IP, service-account, and scanner allowlists;
- `ai`: provider, model, evidence limits, redaction, ZDR acknowledgement, and triage scope;
- `ai.rag`: knowledge-base paths and lexical/vector retrieval settings; and
- `output`: Elasticsearch results index and dashboard base URL.

Managed mode persists non-secret settings through `engine/settings.py`. SIEM and cloud keys are removed from the settings document and written to `engine/secure/store.py` instead.

![Elastic connection setup](images/setupconnect.png)

*Figure 2. SIEM onboarding validates the endpoint, masked API key, alert index, polling interval, and TLS policy.*

![AI provider setup](images/configai.png)

*Figure 3. AI onboarding supports local and cloud providers and performs an explicit provider validation.*

## 7. Pipeline Responsibilities

`engine/pipeline.py` owns the deterministic sequence:

```text
RawRecord
  -> adapter.parse
  -> OCSF Detection Finding
  -> PreFilter.evaluate
  -> CorrelationEngine.add
  -> CorrelationEngine.evaluate
  -> surfaced chains
```

`engine/server.py` composes that pipeline with `TriageService`, `ResultWriter`, and the FastAPI application. `engine/app.py` adds first-run gating, managed state, live reconfiguration, persisted poll cursor, and systemd notifications.

Keep source-specific field handling inside adapters. Keep entity and chain decisions deterministic. AI modules should consume the formed chain rather than mutate correlation state.

## 8. Dashboard and Evidence Views

The frontend is plain HTML, CSS, and JavaScript under `engine/dashboard/static/`. It fetches stored results and purpose-built timeline/graph views. It does not perform correlation in the browser.

![Investigation dashboard](images/investigation-workspace.png)

*Figure 4. The dashboard combines the incident event table with graph, verdict, evidence, and entity panes.*

The evidence tabs deliberately separate source data from derived results:

- **Raw JSON**: normalized alert fields and retained evidence;
- **Correlation**: chain identifier, time window, risk, and resolved entities;
- **AI Verdict**: provider result and grounding-related fields; and
- **Case Report**: formatted investigation output.

![Raw JSON evidence](images/raw-evidence.png)

*Figure 5. Raw event evidence remains available beside correlation and AI-derived views.*

## 9. HTTP API

FastAPI documentation is available at `/api/docs` while the server is running.

Core routes include:

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/status` | Engine, SIEM, AI, and ATT&CK status |
| `GET` | `/api/clusters` | List result summaries |
| `GET` | `/api/clusters/{cluster_id}` | Read a chain document |
| `POST` | `/api/clusters/{cluster_id}/triage` | Re-triage a chain in the live engine |
| `GET` | `/api/clusters/{cluster_id}/timeline` | Timeline view model |
| `GET` | `/api/clusters/{cluster_id}/graph` | Graph view model |
| `GET` | `/api/attack/techniques` | ATT&CK metadata for requested IDs |
| `GET`, `PUT` | `/api/settings/ai` | Read safe provider state or update AI settings |
| `GET` | `/api/setup` | First-run setup state |
| `POST` | `/api/setup/siem/test` | Validate SIEM access and detect indices |
| `POST` | `/api/setup/complete` | Persist setup and start managed polling |
| `GET`, `POST` | `/api/ai/local`, `/api/ai/local/pull` | Inspect Ollama or manage a model pull |
| `POST` | `/api/ai/validate` | Run explicit provider validation |
| `PUT` | `/api/settings/siem` | Update the managed SIEM connection |

API key fields are write-only. Avoid adding secret values to response models, exceptions, or logging arguments.

## 10. Tests

Run the complete suite:

```bash
.venv/bin/python -m pytest
```

Run a focused file or test during development:

```bash
.venv/bin/python -m pytest tests/test_correlation.py
.venv/bin/python -m pytest tests/test_setup_api.py -k siem
```

Tests cover input parsing, normalization, OCSF mapping, pre-filtering, entity resolution, correlation boundaries, risk, ATT&CK retrieval, providers, grounding, redaction, reports, write-back, API behavior, setup, secure storage, and runtime hardening.

When a change affects a pipeline contract, add a focused regression test and run the full suite before release.

## 11. Common Extension Points

### Source adapter

Add source-specific parsing under `engine/normalize/adapters/`, register it through the adapter package, and provide mapping and normalization tests. Do not claim a live integration is supported until its connector and deployment path are implemented and validated.

### Correlation or risk logic

Change deterministic logic under `engine/correlate/` and preserve event-time semantics, stable identifiers, deduplication, and existing boundary tests.

### AI provider behavior

Keep provider-specific calls behind `AIProvider`. New output must satisfy the validated schema and grounding path. Cloud handling must maintain ZDR acknowledgement, redaction, and secret non-disclosure behavior.

### Dashboard view

Prefer extending view models in `engine/api/views.py` over recomputing security logic in JavaScript. Preserve deep links and empty/error states.

## 12. Troubleshooting

### Configuration file not found

Copy `config.example.yaml` to `config.yaml`, or pass an explicit path with `--config`.

### Elastic connection fails

Confirm the URL includes `http://` or `https://`, the API key has access to the alert index, and TLS settings match the cluster. Supply the CA certificate instead of disabling verification outside an isolated lab.

### AI triage is unavailable

Check `/api/status`, build the ATT&CK knowledge base, confirm the selected model is installed or reachable, and use the explicit validation action. The deterministic pipeline can still be tested with `--no-ai`.

### No chains are surfaced

Inspect ingestion and normalization counts, the configured severity floor, pre-filter allowlists, entity fields, correlation window, and risk threshold. Use the raw and correlation views before changing rules.

## 13. Release Checklist

1. Confirm `pyproject.toml` and release metadata agree on the version.
2. Run the complete test suite on a supported Python version.
3. Validate the installer on Linux when installer or service files changed.
4. Test fixture mode and, when relevant, a live Elastic read/write-back cycle.
5. Verify onboarding, status, incident deep links, exports, and secret non-disclosure.
6. Check Markdown links, screenshot paths, and repository privacy scans.
7. Review `git status` and the final diff; do not include caches, local config, runtime state, logs, or generated test output.

