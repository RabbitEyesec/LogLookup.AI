"""Privacy hardening acceptance (Master Specification 9.2 — Privacy).

- Redaction on + cloud provider: no raw internal IP / username in what
  leaves the process; tokens go out, real values are restored on return.
- Local mode: nothing is redacted and no cloud path is used.
- ZDR routing rule: cloud calls are blocked when Zero Data Retention has
  not been acknowledged.
"""

from __future__ import annotations

import dataclasses

import pytest

from engine.ai.provider import ProviderError, ProviderManager
from engine.ai.reasoner import TriageError, TriageReasoner
from engine.ai.retriever import build_retriever
from engine.redact import Redactor
from tests.test_reasoner import make_verdict

# -- unit: the tokenizer ------------------------------------------------------


def test_ip_classification_and_consistency():
    r = Redactor()
    text = ("brute force from 203.0.113.9 against 192.168.1.50, "
            "then 192.168.1.50 authenticated to 10.0.0.7")
    out = r.redact(text)
    assert "192.168.1.50" not in out and "10.0.0.7" not in out
    assert "203.0.113.9" not in out
    assert out.count("[IP_INTERNAL_1]") == 2  # same value -> same token
    assert "[IP_INTERNAL_2]" in out
    assert "[IP_EXTERNAL_1]" in out


def test_email_and_exact_values():
    r = Redactor({"jdoe": "USER", "hostA": "HOST"})
    out = r.redact("user jdoe (jdoe@corp.example) logged into hostA")
    assert "jdoe" not in out and "hostA" not in out
    assert "[EMAIL_1]" in out and "[USER_1]" in out and "[HOST_1]" in out


def test_restore_roundtrip():
    r = Redactor({"jdoe": "USER"})
    redacted = r.redact("jdoe from 192.168.1.50")
    restored = r.restore(redacted.replace("from", "attacked from"))
    assert "jdoe" in restored and "192.168.1.50" in restored


def test_invalid_ip_like_strings_left_alone():
    r = Redactor()
    assert r.redact("version 999.999.999.999") == "version 999.999.999.999"


def test_restore_verdict_walks_all_string_fields():
    r = Redactor({"jdoe": "USER"})
    token = r.redact("jdoe")
    verdict = make_verdict(
        investigation_chain_of_thought=f"activity by {token}",
        remediation_recommendations=[f"Reset {token} credentials."],
    )
    restored = r.restore_verdict(verdict)
    assert "jdoe" in restored.investigation_chain_of_thought
    assert restored.remediation_recommendations == ["Reset jdoe credentials."]


# -- integration: the reasoner seam --------------------------------------------


def make_reasoner(engine_config, fixture_kb, *, provider, redaction=True,
                  zdr=True, captured=None):
    ai = dataclasses.replace(
        engine_config.ai,
        provider=provider,
        cloud_api_key="test-key" if provider != "local" else "",
        redaction=redaction,
        zero_data_retention=zdr,
    )
    manager = ProviderManager(ai)
    retriever = build_retriever(fixture_kb, ai.rag)

    async def fake_create(**kwargs):
        if captured is not None:
            captured.append(kwargs)
        return make_verdict(critical_evidence_fields=["rule.name"])

    return TriageReasoner(manager, retriever, ai, create_fn=fake_create)


def payload_text(kwargs) -> str:
    return "\n".join(
        m["content"] for m in kwargs["messages"] if m["role"] == "user"
    )


async def test_cloud_call_is_tokenized_and_restored(
    correlated_pipeline, fixture_kb, engine_config
):
    pipeline, result = correlated_pipeline
    cluster = next(c for c in result.clusters if c.surfaced)
    captured: list = []
    reasoner = make_reasoner(
        engine_config, fixture_kb, provider="anthropic", captured=captured
    )
    triage = await reasoner.triage(pipeline.correlator, cluster)

    sent = payload_text(captured[0])
    # The fixture scenario's real identifiers must not leave the process.
    assert "jdoe" not in sent
    assert "hostA" not in sent
    assert "203.0.113.7" not in sent  # attacker source IP in the fixture
    assert "[USER_" in sent and "[IP_EXTERNAL_" in sent
    # Raw values still exist locally for the report/write-back.
    assert "203.0.113.7" in triage.payload.xml


async def test_local_mode_sends_unredacted_and_stays_local(
    correlated_pipeline, fixture_kb, engine_config
):
    pipeline, result = correlated_pipeline
    cluster = next(c for c in result.clusters if c.surfaced)
    captured: list = []
    reasoner = make_reasoner(
        engine_config, fixture_kb, provider="local", captured=captured
    )
    await reasoner.triage(pipeline.correlator, cluster)
    kwargs = captured[0]
    # Local provider: full-fidelity payload, ollama transport, no API key.
    assert "jdoe" in payload_text(kwargs)
    assert kwargs["model"].startswith("ollama/")
    assert "api_key" not in kwargs
    assert kwargs["api_base"].startswith("http://localhost")


async def test_redaction_off_sends_raw_to_cloud(
    correlated_pipeline, fixture_kb, engine_config
):
    pipeline, result = correlated_pipeline
    cluster = next(c for c in result.clusters if c.surfaced)
    captured: list = []
    reasoner = make_reasoner(
        engine_config, fixture_kb, provider="anthropic",
        redaction=False, captured=captured,
    )
    await reasoner.triage(pipeline.correlator, cluster)
    assert "jdoe" in payload_text(captured[0])


async def test_zdr_routing_rule_blocks_cloud(
    correlated_pipeline, fixture_kb, engine_config
):
    pipeline, result = correlated_pipeline
    cluster = next(c for c in result.clusters if c.surfaced)
    reasoner = make_reasoner(
        engine_config, fixture_kb, provider="openai", zdr=False
    )
    with pytest.raises(TriageError, match="zero_data_retention"):
        await reasoner.triage(pipeline.correlator, cluster)


def test_zdr_never_blocks_local(engine_config):
    ai = dataclasses.replace(engine_config.ai, zero_data_retention=False)
    manager = ProviderManager(ai)
    kwargs = manager.current.completion_kwargs()  # must not raise
    assert kwargs["model"].startswith("ollama/")


def test_cloud_without_key_still_blocked(engine_config):
    ai = dataclasses.replace(
        engine_config.ai, provider="anthropic", cloud_api_key=""
    )
    with pytest.raises(ProviderError, match="cloud_api_key"):
        ProviderManager(ai).current.completion_kwargs()
