"""Source envelope: provenance wrapper carried by every v2 source record.

The envelope separates *what the vendor said* (the untouched payload,
identified by ``raw_sha256``) from *how LogLookup learned it* (connection,
scope, revision, timestamps). Canonical identity is deterministic and
scope/connection-bound, so the same vendor id seen through two workspaces
never collapses into one event, while a re-poll of the same record always
resolves to the same ``canonical_event_id``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "2.0"

#: record kinds
KIND_ALERT = "alert"
KIND_INCIDENT = "incident"
KIND_SIGNIN = "signin"
KIND_DIRECTORY_AUDIT = "directory_audit"

#: kinds that become OCSF Detection Findings; everything else is context or
#: an external-case link and is never counted as a detection.
DETECTION_KINDS = frozenset({KIND_ALERT})
CONTEXT_KINDS = frozenset({KIND_SIGNIN, KIND_DIRECTORY_AUDIT})


def canonical_json(payload: Any) -> bytes:
    """Stable byte form of a payload for hashing (sorted keys, no spaces)."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, default=str,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_event_id(
    scope_id: str,
    provider: str,
    namespace: str,
    source_event_id: str,
    record_kind: str,
    connection_id: str = "",
) -> str:
    """Deterministic, scope- and connection-bound identity of one record.

    ``namespace`` is the provider-side uniqueness domain (workspace id,
    tenant id, Splunk server, Elastic cluster). ``connection_id`` is mixed in
    as well because vendor ids carry no cross-deployment uniqueness
    guarantee.
    """
    parts = [scope_id, provider, namespace, connection_id, record_kind,
             source_event_id]
    return sha256_hex("\x1f".join(parts).encode("utf-8"))


@dataclass(frozen=True)
class SourceEnvelope:
    scope_id: str
    connection_id: str
    provider: str
    record_kind: str
    source_event_id: str
    canonical_event_id: str
    event_time: str | None
    observed_at: str
    raw_sha256: str
    schema_version: str = SCHEMA_VERSION
    source_incident_id: str | None = None
    source_url: str | None = None
    source_updated_at: str | None = None
    raw_payload_ref: str | None = None
    revision: int = 1
    cursor_fragment: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    #: ``(scheme, value)`` pairs identifying the same underlying event as
    #: represented by other APIs (see ledger ``source_aliases``).
    aliases: tuple[tuple[str, str], ...] = ()

    @property
    def is_detection(self) -> bool:
        return self.record_kind in DETECTION_KINDS

    @property
    def is_context(self) -> bool:
        return self.record_kind in CONTEXT_KINDS

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["aliases"] = [list(a) for a in self.aliases]
        return data

    def provenance_ref(self) -> dict[str, Any]:
        """Compact, non-sensitive provenance stored on a normalised alert."""
        return {
            "scope_id": self.scope_id,
            "connection_id": self.connection_id,
            "provider": self.provider,
            "record_kind": self.record_kind,
            "source_event_id": self.source_event_id,
            "canonical_event_id": self.canonical_event_id,
            "source_incident_id": self.source_incident_id,
            "source_url": self.source_url,
            "raw_sha256": self.raw_sha256,
            "revision": self.revision,
            "evidence_ref": evidence_ref(self),
            **{k: v for k, v in self.provenance.items() if v is not None},
        }


def evidence_ref(envelope: SourceEnvelope) -> str:
    """Addressable citation, e.g. ``SRC:sentinel-prod:alert:abc123``."""
    return (
        f"SRC:{envelope.connection_id}:{envelope.record_kind}:"
        f"{envelope.source_event_id}"
    )
