"""AI analysis layer  invoked only after deterministic correlation.

Deterministic first, AI reasons last: this package never correlates,
searches, or supplies uninjected security facts. It grounds MITRE mapping
in the real ATT&CK framework (RAG), reasons over a bounded evidence payload
with a CoT-first schema, validates every claim against the injected context,
and assembles a report-ready case.
"""
