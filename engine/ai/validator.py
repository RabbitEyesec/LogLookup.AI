"""Post-generation grounding validator — belt and braces after the schema.

instructor guarantees the SHAPE of the output; this module checks its
GROUNDING (Build Reference 4.6):

- every returned MITRE technique ID must exist in the retrieved candidate
  payload — invented or out-of-payload IDs are REJECTED (removed, listed);
- every cited evidence field must exist in the raw log evidence — unknown
  citations are kept but FLAGGED and the confidence score is capped low.

The original model output is never rewritten silently: rejected and
unverified items stay on the result so every adjustment is traceable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from engine.ai.kb import normalize_technique_id
from engine.ai.schema import AlertTriageVerdict

#: A verdict citing evidence that does not exist cannot be high-confidence.
LOW_CONFIDENCE_CAP = 40


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of grounding one verdict against its injected context."""

    valid_techniques: list[str] = field(default_factory=list)
    rejected_techniques: list[str] = field(default_factory=list)
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    original_confidence: int = 0
    final_confidence: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def grounded(self) -> bool:
        return not self.rejected_techniques and not self.unverified_fields

    def as_dict(self) -> dict:
        return {
            "valid_techniques": self.valid_techniques,
            "rejected_techniques": self.rejected_techniques,
            "verified_fields": self.verified_fields,
            "unverified_fields": self.unverified_fields,
            "original_confidence": self.original_confidence,
            "final_confidence": self.final_confidence,
            "grounded": self.grounded,
            "notes": self.notes,
        }


def validate_verdict(
    verdict: AlertTriageVerdict,
    candidate_uids: set[str],
    evidence_fields: set[str],
) -> ValidationResult:
    """Ground the verdict in the injected candidates and raw log fields."""
    normalized_candidates = {
        normalized
        for uid in candidate_uids
        if (normalized := normalize_technique_id(uid)) is not None
    }

    valid: list[str] = []
    rejected: list[str] = []
    for returned in verdict.mitre_attack_techniques:
        normalized = normalize_technique_id(returned)
        if normalized is not None and normalized in normalized_candidates:
            if normalized not in valid:
                valid.append(normalized)
        else:
            rejected.append(returned)

    verified: list[str] = []
    unverified: list[str] = []
    for cited in verdict.critical_evidence_fields:
        key = cited.strip()
        if key in evidence_fields:
            if key not in verified:
                verified.append(key)
        else:
            unverified.append(cited)

    notes: list[str] = []
    final_confidence = verdict.confidence_score
    if rejected:
        notes.append(
            "rejected technique id(s) not present in the RAG candidate "
            f"payload: {', '.join(rejected)}"
        )
    if unverified:
        notes.append(
            "cited evidence field(s) not found in the raw logs: "
            f"{', '.join(unverified)}"
        )
        if final_confidence > LOW_CONFIDENCE_CAP:
            notes.append(
                f"confidence capped at {LOW_CONFIDENCE_CAP} "
                f"(was {verdict.confidence_score}) due to unverified citations"
            )
            final_confidence = LOW_CONFIDENCE_CAP

    return ValidationResult(
        valid_techniques=valid,
        rejected_techniques=rejected,
        verified_fields=verified,
        unverified_fields=unverified,
        original_confidence=verdict.confidence_score,
        final_confidence=final_confidence,
        notes=notes,
    )
