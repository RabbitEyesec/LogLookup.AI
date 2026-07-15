# LogLookup AI
LogLookup AI turns Elastic Security alerts into evidence-backed attack-chain investigations. It normalizes alerts to OCSF, correlates related activity deterministically, scores entity risk, optionally asks an AI provider to reason over the formed chain, and writes the result back to Elasticsearch.

![LogLookup AI investigation workspace](docs/images/investigation-workspace.png)

*Figure 1. Investigation workspace combining the event stream, attack graph, AI verdict, raw evidence, and entity context.*

## The Problem

Security analysts often need to reconstruct one incident from many alerts spread across hosts, users, processes, and time. LogLookup AI performs that correlation before AI analysis and keeps the original evidence available for review. Elastic remains the source of alerts and investigation results; LogLookup AI adds the attack-chain view and grounded triage workflow.

## What Makes LogLookup AI Different

- **Deterministic correlation before AI.** Shared entities, timing, and event relationships form reproducible chains before a model is called.
- **OCSF normalization.** Elastic alerts are converted to OCSF Detection Finding events so downstream processing uses one schema.
- **Evidence-grounded AI.** The model receives a bounded evidence payload and retrieved MITRE ATT&CK candidates; a validator checks cited fields and technique identifiers.
- **Attack-chain investigation.** Analysts can review the correlated timeline, entity relationships, risk score, verdict, and report in one workspace.
- **Elastic write-back.** Results are stored in the configured Elasticsearch results index using an idempotent `cluster_id`.
- **Raw evidence visibility.** Normalized records, correlation output, and raw event JSON remain visible beside the AI assessment.

## Key Capabilities

- Elastic Security polling, batch ingestion, and result write-back
- OCSF Detection Finding (`class_uid` 2004) normalization
- Deterministic pre-filtering, entity resolution, chain correlation, and risk-based surfacing
- Local Ollama, Anthropic, and OpenAI provider support through LiteLLM
- MITRE ATT&CK retrieval with lexical or optional embedding-based search
- Post-generation grounding checks and explicit `ai_unavailable` outcomes
- Deep-linked incident pages with timeline, 2D/3D graph, evidence, verdict, and report views
- First-run onboarding with encrypted local credential storage

## How It Works

```text
Elastic Security alerts
  -> ingest
  -> normalize to OCSF
  -> deterministic pre-filter and entity resolution
  -> correlate attack chains and score risk
  -> optional AI triage and grounding validation
  -> report and Elastic write-back
  -> Kibana and the LogLookup AI investigation workspace
```

![Elastic Security alerts selected for investigation](docs/images/elastic-alerts-overview.png)

*Figure 2. Elastic Security alerts for a single endpoint before LogLookup AI groups them into an investigation.*

## Installation

LogLookup AI supports Linux with Python 3.11, 3.12, or 3.13. From a source checkout:

```bash
bash deploy/install.sh
loglookup open
```

The per-user installer creates an isolated environment, installs the launcher and desktop entry, configures a systemd user service when available, and attempts to build the MITRE ATT&CK knowledge base. Use `--skip-kb` or `--skip-service` when those steps are not appropriate for the host.

## Quick Start for Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp config.example.yaml config.yaml

# Set credentials for config-file mode; do not write them into config.yaml.
export LOGLOOKUP_SIEM_KEY='YOUR_API_KEY'
export LOGLOOKUP_AI_KEY='YOUR_AI_API_KEY'  # only for a cloud provider

# Build the ATT&CK knowledge base. This downloads the official STIX bundle.
.venv/bin/python -m engine.ai.kb --build

# Run the dashboard against the included fixture.
.venv/bin/python -m engine.server \
  --config config.yaml \
  --input tests/fixtures/attack_chain.ndjson
```

Open `http://localhost:8080`. For a UI-only preview that does not contact a SIEM or AI provider, run `python3 preview_ui.py` and open `http://127.0.0.1:4173/?preview=1`.

For continuous Elastic polling with AI triage and write-back:

```bash
.venv/bin/python -m engine.server \
  --config config.yaml \
  --mode poll \
  --writeback
```

## Analyst Workflow

1. Complete onboarding and validate the Elastic connection.
2. Select a local or cloud AI provider. AI is optional; deterministic results remain available if it is disabled or unavailable.
3. Allow the service to poll Elastic Security and form attack chains.
4. Open a surfaced incident to review its timeline, graph, entities, correlation JSON, raw evidence, and AI verdict.
5. Continue the investigation in Kibana using the written-back result and dashboard deep link.

![Elastic case containing the correlated activity](docs/images/elastic-case-writeback.png)

*Figure 3. A simulated attack-chain case in Elastic after the investigation workflow.*

## Configuration and Secrets

Managed installs collect credentials in onboarding and store them in an AES-256-GCM encrypted local store with owner-only permissions. Config-file development uses `LOGLOOKUP_SIEM_KEY` and `LOGLOOKUP_AI_KEY` interpolation from `config.example.yaml`.

For a private or self-signed Elasticsearch CA, provide the CA certificate during onboarding or set `siem.ca_cert_path`. Disabling TLS verification is intended only for isolated lab use.

Cloud AI calls are blocked unless zero-data-retention acknowledgement is enabled. When redaction is enabled, recognized sensitive values are tokenized before the cloud request and restored in the returned assessment.

## Documentation

For the complete practical implementation—from lab deployment and Elastic
configuration through endpoint telemetry, detection validation, and the final
end-to-end investigation—read the [Project Execution Report](docs/LogLookup-AI-Project-Execution-Report.docx).

- [Product overview](docs/product.md)
- [Architecture](docs/architecture.md)
- [Developer guide](docs/Developerguide.md)
- [User guide](docs/User%20guide.md)
- [Example configuration](config.example.yaml)

## Development and Validation

```bash
.venv/bin/python -m pytest
```

The test suite covers configuration, ingestion, normalization, correlation, entity resolution, risk scoring, AI provider behavior, grounding, redaction, reporting, write-back, API endpoints, and managed setup.

The package version is defined in `pyproject.toml`. The repository includes the implemented engine, dashboard, installer, documentation, and tests; release publication and operational validation remain deployment-specific.
