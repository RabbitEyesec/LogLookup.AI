"""ContextObservation: supporting evidence that is NOT a detection.

Sign-ins, directory changes, cloud audit events and vulnerability findings
enrich an investigation. They are stored and linked by identity but are
never counted as alerts unless a separate explicit rule produced a finding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from engine.envelope import SourceEnvelope, evidence_ref
from engine.normalize.timeutil import coerce_time


@dataclass
class ContextObservation:
    context_id: str
    context_type: str
    scope_id: str
    event_time: str
    event_time_ms: int
    entities: list[dict[str, str]]
    attributes: dict[str, Any]
    source_ref: str
    original_record_ref: str
    principal_key: str | None = None
    warnings: list[str] = field(default_factory=list)

    def row(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "context_type": self.context_type,
            "event_time": self.event_time,
            "event_time_ms": self.event_time_ms,
            "principal_key": self.principal_key,
            "entities": self.entities,
            "attributes": {**self.attributes, "_warnings": self.warnings},
        }


def make_context_id(canonical_event_id: str, principal: str | None) -> str:
    return hashlib.sha256(
        f"{canonical_event_id}\x1f{principal or ''}".encode()
    ).hexdigest()


def event_time_of(value: Any, fallback_iso: str) -> tuple[str, int]:
    try:
        ms, iso = coerce_time(value)
        return iso, ms
    except Exception:
        ms, iso = coerce_time(fallback_iso)
        return iso, ms


def base_context(
    envelope: SourceEnvelope, context_type: str, principal: str | None,
    event_time_raw: Any, entities: list[dict[str, str]],
    attributes: dict[str, Any], warnings: list[str] | None = None,
) -> ContextObservation:
    iso, ms = event_time_of(event_time_raw, envelope.observed_at)
    return ContextObservation(
        context_id=make_context_id(envelope.canonical_event_id, principal),
        context_type=context_type, scope_id=envelope.scope_id,
        event_time=iso, event_time_ms=ms, entities=entities,
        attributes=attributes, source_ref=evidence_ref(envelope),
        original_record_ref=envelope.raw_payload_ref or "",
        principal_key=principal.lower() if principal else None,
        warnings=warnings or [],
    )
