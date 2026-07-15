"""CoT-first structured output schema (Master Specification 5.3).

Field ORDER is the design: generation is autoregressive, so the free-form
reasoning fields are declared before the verdict/classification fields —
the model reasons first and classifies conditioned on that reasoning.
Reordering these fields degrades triage accuracy; do not "tidy" them.

Pydantic is used here deliberately ("msgspec in, Pydantic out"): instructor
validates the model's output against this schema and re-prompts with the
exact validation error on failure, preserving reasoning quality vs
constrained decoding.
"""

from __future__ import annotations

from typing import List, Literal

from pydantic import BaseModel, Field

VERDICT_TRUE_POSITIVE = "True Positive"
VERDICT_FALSE_POSITIVE = "False Positive"
VERDICT_NEEDS_ESCALATION = "Needs Escalation"


class AlertTriageVerdict(BaseModel):
    # Phase 1 — reasoning FIRST (scratchpad; must precede classification)
    benign_hypothesis: str = Field(description=(
        "How could this activity be normal admin, automated, or "
        "misconfiguration behavior? Base it strictly on the provided data."
    ))
    malicious_hypothesis: str = Field(description=(
        "How does this activity indicate an actual compromise? Base it "
        "strictly on the provided data."
    ))
    investigation_chain_of_thought: str = Field(description=(
        "Weigh both hypotheses strictly against the provided evidence, "
        "step by step, then conclude."
    ))

    # Phase 2 — classification (conditioned on the reasoning above)
    verdict: Literal["True Positive", "False Positive", "Needs Escalation"]
    confidence_score: int = Field(ge=0, le=100)

    # Phase 3 — grounded evidence & next steps
    mitre_attack_techniques: List[str] = Field(description=(
        "ATT&CK technique IDs, strictly from the provided candidate list. "
        "Never return an ID that is not in the candidates."
    ))
    critical_evidence_fields: List[str] = Field(description=(
        "Log field keys present in the provided evidence (e.g. "
        "process.command_line) that justify the verdict."
    ))
    missing_context: List[str] = Field(description=(
        "Evidence that is missing and should be gathered next. If a fact "
        "(e.g. a CVE) is not in the input, list it here — never invent it."
    ))
    remediation_recommendations: List[str] = Field(description=(
        "Concrete remediation / next investigation steps. Recommendations "
        "only — this tool never executes actions."
    ))
