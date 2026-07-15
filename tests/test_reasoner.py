"""Phase 12 acceptance (Build Plan AI-layer checklist):

- output always validates against the CoT-first schema (reasoning fields
  declared before classification);
- a MITRE ID not in the RAG payload is rejected by the validator;
- a cited field not in the raw logs is flagged low-confidence;
- no real CVE in the input -> nothing invented (missing_context instead,
  by prompt contract; enforced here as: the reasoner passes ONLY injected
  evidence and candidates to the model);
- provider failure surfaces as an honest TriageError, never a fake verdict.
"""

from __future__ import annotations

import pytest

from engine.ai.payload import build_payload, flatten
from engine.ai.prompts import build_messages, render_candidates
from engine.ai.provider import ProviderManager
from engine.ai.reasoner import TriageError, TriageReasoner
from engine.ai.retriever import LexicalRetriever
from engine.ai.schema import AlertTriageVerdict
from engine.ai.validator import LOW_CONFIDENCE_CAP, validate_verdict
from engine.config import AiConfig


def _surfaced_cluster(correlated_pipeline):
    pipeline, result = correlated_pipeline
    return pipeline.correlator, result.surfaced[0]


def make_verdict(**overrides) -> AlertTriageVerdict:
    base = dict(
        benign_hypothesis="Could be an admin password reset burst.",
        malicious_hypothesis="Brute force followed by credential dumping.",
        investigation_chain_of_thought="Weighing both against evidence...",
        verdict="True Positive",
        confidence_score=88,
        mitre_attack_techniques=["T1110", "T1003"],
        critical_evidence_fields=["rule.name", "user.name"],
        missing_context=["EDR process tree for hostA"],
        remediation_recommendations=["Reset jdoe credentials."],
    )
    base.update(overrides)
    return AlertTriageVerdict(**base)


# -- schema ------------------------------------------------------------------

def test_schema_orders_reasoning_before_classification():
    fields = list(AlertTriageVerdict.model_fields)
    assert fields.index("benign_hypothesis") < fields.index("verdict")
    assert fields.index("malicious_hypothesis") < fields.index("verdict")
    assert (fields.index("investigation_chain_of_thought")
            < fields.index("verdict"))
    assert fields.index("verdict") < fields.index("mitre_attack_techniques")


def test_schema_rejects_out_of_range_confidence():
    with pytest.raises(Exception):
        make_verdict(confidence_score=140)
    with pytest.raises(Exception):
        make_verdict(verdict="Probably Fine")


# -- payload -----------------------------------------------------------------

def test_payload_is_xml_delimited_and_flattened(correlated_pipeline):
    engine, cluster = _surfaced_cluster(correlated_pipeline)
    payload = build_payload(engine, cluster)
    for tag in ("<alert_cluster>", "</alert_cluster>",
                "<threat_intelligence_enrichment>", "<asset_context>"):
        assert tag in payload.xml
    # Real raw-log keys are indexed for the validator, values preserved.
    assert "rule.name" in payload.evidence_fields
    assert "user.name" in payload.evidence_fields
    assert ("evt-004", "mimikatz.exe") in payload.field_values["process.name"]
    # Pre-tagged ATT&CK metadata is surfaced as injected ground truth.
    assert "Credential Access" in payload.xml
    assert cluster.cluster_id in payload.xml


def test_payload_rag_query_carries_indicators(correlated_pipeline):
    engine, cluster = _surfaced_cluster(correlated_pipeline)
    payload = build_payload(engine, cluster)
    assert "SSH brute force attempts" in payload.rag_query
    assert "mimikatz.exe" in payload.rag_query


def test_payload_is_bounded(correlated_pipeline):
    engine, cluster = _surfaced_cluster(correlated_pipeline)
    payload = build_payload(engine, cluster, max_chars=500)
    assert payload.truncated is True
    assert payload.char_count <= 500


def test_flatten_dotted_keys():
    flat = flatten({"a": {"b": 1}, "c": ["x", "y"], "d": [{"e": 2}]})
    assert flat == {"a.b": "1", "c": "x, y", "d[0].e": "2"}


# -- validator ---------------------------------------------------------------

def test_invented_technique_id_is_rejected():
    verdict = make_verdict(mitre_attack_techniques=["T1110", "T1566"])
    result = validate_verdict(verdict, {"T1110", "T1003"},
                              {"rule.name", "user.name"})
    assert result.valid_techniques == ["T1110"]
    assert result.rejected_techniques == ["T1566"]
    assert not result.grounded
    assert result.final_confidence == verdict.confidence_score  # ids removed,
    # confidence untouched: rejection is the remedy for invented ids


def test_uncited_field_flags_low_confidence():
    verdict = make_verdict(
        critical_evidence_fields=["rule.name", "registry.hive"],
        confidence_score=95,
    )
    result = validate_verdict(verdict, {"T1110", "T1003"}, {"rule.name"})
    assert result.unverified_fields == ["registry.hive"]
    assert result.final_confidence == LOW_CONFIDENCE_CAP
    assert any("capped" in note for note in result.notes)


def test_grounded_verdict_passes_untouched():
    verdict = make_verdict()
    result = validate_verdict(verdict, {"T1110", "T1003"},
                              {"rule.name", "user.name"})
    assert result.grounded
    assert result.valid_techniques == ["T1110", "T1003"]
    assert result.final_confidence == 88
    assert result.notes == []


def test_validator_normalizes_case():
    verdict = make_verdict(mitre_attack_techniques=["t1110"])
    result = validate_verdict(verdict, {"T1110"}, set())
    assert result.valid_techniques == ["T1110"]


# -- prompts -----------------------------------------------------------------

def test_candidates_rendered_with_strict_definitions(fixture_kb):
    retriever = LexicalRetriever(fixture_kb)
    candidates = retriever.retrieve("brute force credential dumping", k=3)
    rendered = render_candidates(candidates)
    assert "<attack_technique_candidates>" in rendered
    assert 'id="T1110"' in rendered
    messages = build_messages("<alert_cluster>x</alert_cluster>", candidates)
    assert messages[0]["role"] == "system"
    assert "Tier 3 SOC analyst" in messages[0]["content"]
    assert "Do NOT invent" in messages[0]["content"]
    assert "mimikatz" in messages[0]["content"]  # few-shot TP-vs-FP contrast
    assert "<alert_cluster>" in messages[1]["content"]


# -- reasoner ----------------------------------------------------------------

async def test_reasoner_end_to_end_with_injected_model(
    correlated_pipeline, fixture_kb
):
    engine, cluster = _surfaced_cluster(correlated_pipeline)
    seen = {}

    async def fake_create(*, messages, response_model, max_retries, **kwargs):
        seen["messages"] = messages
        seen["kwargs"] = kwargs
        assert response_model is AlertTriageVerdict
        # Model returns one invented technique and one uncited field: the
        # reasoner must ground the result, not pass it through.
        return make_verdict(
            mitre_attack_techniques=["T1110", "T1003", "T1999"],
            critical_evidence_fields=["rule.name", "no.such.field"],
            confidence_score=90,
        )

    reasoner = TriageReasoner(
        ProviderManager(AiConfig(provider="local")),
        LexicalRetriever(fixture_kb),
        AiConfig(provider="local"),
        create_fn=fake_create,
    )
    result = await reasoner.triage(engine, cluster)

    assert result.cluster_id == cluster.cluster_id
    assert result.model_id == "ollama/foundation-sec-8b"
    assert seen["kwargs"]["model"] == "ollama/foundation-sec-8b"
    # The model saw only injected evidence + candidates.
    user_message = seen["messages"][1]["content"]
    assert "<alert_cluster>" in user_message
    assert "<attack_technique_candidates>" in user_message
    # Grounding: invented id rejected, uncited field capped the confidence.
    assert "T1999" in result.validation.rejected_techniques
    assert result.validation.valid_techniques == ["T1110", "T1003"]
    assert result.validation.final_confidence == LOW_CONFIDENCE_CAP
    as_dict = result.as_dict()
    assert as_dict["confidence_score"] == LOW_CONFIDENCE_CAP
    assert as_dict["mitre_attack_techniques"] == ["T1110", "T1003"]
    assert as_dict["generated_at"].endswith("Z")


async def test_reasoner_provider_failure_is_honest(
    correlated_pipeline, fixture_kb
):
    engine, cluster = _surfaced_cluster(correlated_pipeline)
    # Cloud provider without a key: completion_kwargs refuses, and the
    # reasoner must surface that as TriageError — never a fabricated verdict.
    manager = ProviderManager(AiConfig(provider="local"))
    manager.switch(provider="anthropic")  # no key set

    async def should_not_be_called(**_kwargs):  # pragma: no cover
        raise AssertionError("model must not be called without credentials")

    reasoner = TriageReasoner(
        manager, LexicalRetriever(fixture_kb), AiConfig(provider="local"),
        create_fn=should_not_be_called,
    )
    with pytest.raises(TriageError, match="cloud_api_key"):
        await reasoner.triage(engine, cluster)


async def test_reasoner_wraps_model_errors(correlated_pipeline, fixture_kb):
    engine, cluster = _surfaced_cluster(correlated_pipeline)

    async def broken_model(**_kwargs):
        raise RuntimeError("connection refused")

    reasoner = TriageReasoner(
        ProviderManager(AiConfig(provider="local")),
        LexicalRetriever(fixture_kb),
        AiConfig(provider="local"),
        create_fn=broken_model,
    )
    with pytest.raises(TriageError, match="connection refused"):
        await reasoner.triage(engine, cluster)
