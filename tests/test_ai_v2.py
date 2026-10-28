"""Source-aware AI evidence: refs, coverage, fair budgets, grounding."""

from __future__ import annotations

from engine.ai.payload import MIN_FIELDS_PER_ALERT, build_payload
from engine.ai.report import build_report
from engine.ai.schema import AlertTriageVerdict
from engine.ai.validator import LOW_CONFIDENCE_CAP, validate_verdict
from tests.v2_helpers import (
    DEFENDER_SRC, ENTRA_SRC, SENTINEL_SRC, MockVendors, build_runtime, settle,
)


def verdict(**kw):
    base = dict(benign_hypothesis="b", malicious_hypothesis="m",
                investigation_chain_of_thought="c", verdict="True Positive",
                confidence_score=90, mitre_attack_techniques=[],
                critical_evidence_fields=[], missing_context=[],
                remediation_recommendations=[])
    return AlertTriageVerdict(**{**base, **kw})


async def chain(tmp_path, sources, vendors=None):
    vendors = vendors or MockVendors()
    rt = await build_runtime(tmp_path, sources, vendors)
    await settle(rt, 3)
    rt.pipeline.evaluate(flush=True)
    corr = rt.pipeline.correlator
    return rt, corr, corr.clusters()[0]


async def test_payload_carries_refs_coverage_and_identity_context(tmp_path):
    rt, corr, cluster = await chain(tmp_path, [SENTINEL_SRC, DEFENDER_SRC, ENTRA_SRC])
    try:
        await rt.evaluate_now()
        summary = corr.cluster_summary(cluster)
        ctx = {"identity": await rt.context_for(summary)}
        payload = build_payload(corr, cluster, context=ctx)
        assert 'evidence_ref="SRC:sentinel-main:alert:sent-alert-1"' in payload.xml
        assert "<source_coverage>" in payload.xml
        assert 'provider="defender_xdr"' in payload.xml
        assert "supporting observations, not detections" in payload.xml
        assert "SRC:sentinel-main:alert:sent-alert-1" in payload.evidence_refs
        assert any(r.startswith("SRC:entra-id:signin:") for r in payload.evidence_refs)
    finally:
        await rt.stop()


async def test_budget_is_cut_from_the_noisiest_source_first(tmp_path):
    vendors = MockVendors()
    noisy = dict(vendors.sentinel_rows[0])
    noisy.update({f"Extra{i:02d}": "x" * 250 for i in range(60)})
    vendors.sentinel_rows = [noisy]
    rt, corr, cluster = await chain(tmp_path, [SENTINEL_SRC, DEFENDER_SRC], vendors)
    try:
        small = build_payload(corr, cluster, max_chars=9000)
        # the noisy Sentinel record gave up detail; Defender's alert is intact
        assert "sentinel" in small.source_field_caps
        assert "defender_xdr" not in small.source_field_caps
        assert 'evidence_ref="SRC:defender-xdr:alert:gr-1"' in small.xml
        assert small.source_field_caps["sentinel"] >= MIN_FIELDS_PER_ALERT
        assert len(small.xml) <= 9000
    finally:
        await rt.stop()


def test_validator_flags_refs_that_were_never_supplied():
    supplied = {"SRC:a:alert:1"}
    good = validate_verdict(verdict(evidence_refs=["SRC:a:alert:1"]), set(), set(), supplied)
    assert good.verified_refs == ["SRC:a:alert:1"] and good.grounded
    bad = validate_verdict(verdict(evidence_refs=["SRC:a:alert:1", "SRC:fake:alert:9"]),
                           set(), set(), supplied)
    assert bad.unverified_refs == ["SRC:fake:alert:9"] and not bad.grounded
    assert bad.final_confidence == LOW_CONFIDENCE_CAP        # same treatment as fields
    # callers that do not supply refs (legacy) are unaffected
    legacy = validate_verdict(verdict(evidence_refs=["SRC:fake:alert:9"]), set(), set())
    assert legacy.grounded


async def test_report_lists_sources_risk_rationale_evidence_and_response(tmp_path):
    rt, corr, cluster = await chain(tmp_path, [SENTINEL_SRC, DEFENDER_SRC])
    try:
        summary = corr.cluster_summary(cluster)
        actions = [{"workflow_id": "notify-soc-v1", "state": "acknowledged",
                    "requested_by": "ann", "approvals": [{"by": "rob"}]}]
        md = build_report(summary, None, context={"actions": actions})
        assert "## Sources" in md and "| sentinel | sentinel-main | 1 |" in md
        assert "Independent source confirmation: 4.0" in md
        assert "## Evidence appendix" in md and "SRC:defender-xdr:alert:gr-1" in md
        assert "| notify-soc-v1 | acknowledged | ann | rob |" in md
        assert "not proof of a downstream effect" in md
    finally:
        await rt.stop()


async def test_prompt_declares_source_text_untrusted():
    from engine.ai.prompts import SYSTEM_PROMPT
    assert "UNTRUSTED DATA" in SYSTEM_PROMPT and "evidence_refs" in SYSTEM_PROMPT
