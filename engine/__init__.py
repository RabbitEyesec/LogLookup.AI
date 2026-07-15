"""LogLookup AI engine.

Deterministic pipeline: ingest -> normalize (OCSF) -> pre-filter ->
entity resolution -> correlate (attack chains + cluster_id) -> risk scoring.

AI reasoning, RAG, write-back, and UI belong to later phases and are not
part of this package yet.
"""

__version__ = "0.1.0"
