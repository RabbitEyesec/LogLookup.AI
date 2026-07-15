"""The AI reasoning engine: formed cluster in, grounded verdict out.

Orchestrates the documented flow for ONE cluster (the AI never correlates):

    payload (flatten + XML)  ->  RAG retrieve candidates  ->  instructor
    validation-retry against the CoT-first schema  ->  post-generation
    grounding validator

The LLM call goes through instructor.from_litellm, so the provider remains
runtime-switchable (local Ollama / Anthropic / OpenAI) with one code path.
Tests inject ``create_fn`` to exercise the full flow without a live model —
the injected function must still return a real ``AlertTriageVerdict``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from engine.ai import prompts
from engine.ai.payload import EvidencePayload, build_payload
from engine.ai.provider import ProviderError, ProviderManager
from engine.ai.retriever import AttackRetriever, Candidate
from engine.ai.schema import AlertTriageVerdict
from engine.ai.validator import ValidationResult, validate_verdict
from engine.config import AiConfig
from engine.correlate.engine import Cluster, CorrelationEngine
from engine.normalize.timeutil import now_utc_iso

logger = logging.getLogger(__name__)

#: async (messages, response_model, max_retries, **completion_kwargs) -> verdict
CreateFn = Callable[..., Awaitable[AlertTriageVerdict]]


class TriageError(Exception):
    """Raised when the AI layer cannot produce a verdict for a cluster."""


@dataclass(frozen=True)
class TriageResult:
    """One triaged attack chain: verdict + grounding, fully traceable."""

    cluster_id: str
    verdict: AlertTriageVerdict
    validation: ValidationResult
    candidates: list[Candidate]
    payload: EvidencePayload
    provider: str
    model_id: str
    generated_at: str

    def as_dict(self) -> dict[str, Any]:
        """JSON-safe view (used by the API and the write-back document)."""
        return {
            "cluster_id": self.cluster_id,
            "verdict": self.verdict.verdict,
            "confidence_score": self.validation.final_confidence,
            "benign_hypothesis": self.verdict.benign_hypothesis,
            "malicious_hypothesis": self.verdict.malicious_hypothesis,
            "investigation_chain_of_thought":
                self.verdict.investigation_chain_of_thought,
            "mitre_attack_techniques": self.validation.valid_techniques,
            "critical_evidence_fields": self.validation.verified_fields,
            "missing_context": self.verdict.missing_context,
            "remediation_recommendations":
                self.verdict.remediation_recommendations,
            "validation": self.validation.as_dict(),
            "candidates_offered": [c.uid for c in self.candidates],
            "provider": self.provider,
            "model_id": self.model_id,
            "generated_at": self.generated_at,
        }


class TriageReasoner:
    """Reasons over formed clusters with cited evidence — nothing else."""

    def __init__(
        self,
        provider_manager: ProviderManager,
        retriever: AttackRetriever,
        config: AiConfig,
        *,
        create_fn: Optional[CreateFn] = None,
    ) -> None:
        self._providers = provider_manager
        self._retriever = retriever
        self._config = config
        self._create_fn = create_fn
        self._client = None  # instructor client, built lazily per event loop

    def _structured_create(self) -> CreateFn:
        if self._create_fn is not None:
            return self._create_fn
        if self._client is None:
            import instructor
            import litellm

            litellm.suppress_debug_info = True
            self._client = instructor.from_litellm(litellm.acompletion)

        async def create(*, messages, response_model, max_retries, **kwargs):
            return await self._client.chat.completions.create(
                messages=messages,
                response_model=response_model,
                max_retries=max_retries,
                **kwargs,
            )

        return create

    async def triage(
        self, engine: CorrelationEngine, cluster: Cluster
    ) -> TriageResult:
        """Produce a grounded verdict for one formed attack chain."""
        provider = self._providers.current
        payload = build_payload(
            engine, cluster, max_chars=self._config.max_evidence_chars
        )
        candidates = self._retriever.retrieve(
            payload.rag_query, k=self._config.rag.top_k
        )
        messages = prompts.build_messages(payload.xml, candidates)

        try:
            completion_kwargs = provider.completion_kwargs()
        except ProviderError as exc:
            raise TriageError(str(exc)) from exc

        # Privacy hardening (Master Specification 5.3): before evidence
        # leaves the machine for a cloud provider, tokenize sensitive
        # values; real values are restored in the verdict below. Local
        # mode sends nothing off-machine, so nothing is redacted.
        redactor = None
        if not provider.is_local and self._config.redaction:
            from engine.redact import Redactor

            redactor = Redactor.for_payload(payload)
            messages = redactor.redact_messages(messages)
            logger.info(
                "redaction: %d value(s) tokenized before cloud call for %s",
                redactor.token_count, cluster.cluster_id,
            )

        create = self._structured_create()
        try:
            verdict = await create(
                messages=messages,
                response_model=AlertTriageVerdict,
                max_retries=self._config.max_retries,
                **completion_kwargs,
            )
        except Exception as exc:  # provider/transport/validation-exhausted
            raise TriageError(
                f"AI triage failed for {cluster.cluster_id} via "
                f"{provider.model_id}: {exc}"
            ) from exc
        if not isinstance(verdict, AlertTriageVerdict):
            raise TriageError(
                f"model returned {type(verdict).__name__}, not an "
                f"AlertTriageVerdict"
            )
        if redactor is not None:
            verdict = redactor.restore_verdict(verdict)

        validation = validate_verdict(
            verdict,
            candidate_uids={c.uid for c in candidates},
            evidence_fields=payload.evidence_fields,
        )
        if not validation.grounded:
            logger.warning(
                "verdict for %s required grounding corrections: %s",
                cluster.cluster_id, "; ".join(validation.notes),
            )
        return TriageResult(
            cluster_id=cluster.cluster_id,
            verdict=verdict,
            validation=validation,
            candidates=candidates,
            payload=payload,
            provider=provider.provider,
            model_id=provider.model_id,
            generated_at=now_utc_iso(),
        )
