"""Phase 13 acceptance: report-ready case per attack chain."""

from __future__ import annotations

from engine.ai.payload import build_payload
from engine.ai.report import AI_DISCLAIMER, build_report, technique_label
from engine.ai.reasoner import TriageResult
from engine.ai.retriever import LexicalRetriever
from engine.ai.validator import validate_verdict
from tests.test_reasoner import make_verdict


def _triage_result(engine, cluster, fixture_kb, verdict) -> TriageResult:
    payload = build_payload(engine, cluster)
    candidates = LexicalRetriever(fixture_kb).retrieve(payload.rag_query, k=6)
    validation = validate_verdict(
        verdict, {c.uid for c in candidates}, payload.evidence_fields
    )
    return TriageResult(
        cluster_id=cluster.cluster_id,
        verdict=verdict,
        validation=validation,
        candidates=candidates,
        payload=payload,
        provider="local",
        model_id="ollama/foundation-sec-8b",
        generated_at="2026-07-12T00:00:00.000Z",
    )


def test_report_contains_all_case_sections(correlated_pipeline, fixture_kb):
    pipeline, result = correlated_pipeline
    engine, cluster = pipeline.correlator, result.surfaced[0]
    triage = _triage_result(
        engine, cluster, fixture_kb,
        make_verdict(critical_evidence_fields=["rule.name", "process.name"]),
    )
    report = build_report(
        engine.cluster_summary(cluster), triage, kb=fixture_kb,
        dashboard_url="http://localhost:8080/incident/" + cluster.cluster_id,
    )
    assert f"# Attack Chain {cluster.cluster_id}" in report
    assert "**Verdict:** True Positive" in report
    assert "## Timeline" in report
    assert "SSH brute force attempts" in report
    assert "Credential Access → Credential Access → Lateral Movement" in report
    assert "- T1110 Brute Force (credential access)" in report
    assert "- T1003 OS Credential Dumping (credential access)" in report
    assert f"## Analysis ({AI_DISCLAIMER})" in report
    assert "**Benign hypothesis.**" in report
    # Cited evidence rendered with the actual raw-log values.
    assert "`evt-004` → mimikatz.exe" in report
    assert "## Recommended remediation" in report
    assert "never executes response actions" in report
    assert "ollama/foundation-sec-8b" in report
    assert "/incident/CHAIN-2026-07-11-hostA-001" in report


def test_report_shows_rejected_and_unverified_claims(
    correlated_pipeline, fixture_kb
):
    pipeline, result = correlated_pipeline
    engine, cluster = pipeline.correlator, result.surfaced[0]
    triage = _triage_result(
        engine, cluster, fixture_kb,
        make_verdict(
            mitre_attack_techniques=["T1110", "T1999"],
            critical_evidence_fields=["rule.name", "registry.hive"],
            confidence_score=95,
        ),
    )
    report = build_report(engine.cluster_summary(cluster), triage,
                          kb=fixture_kb)
    assert "Rejected by the grounding validator" in report
    assert "T1999" in report
    assert "NOT found in the raw logs" in report
    assert "registry.hive" in report
    assert "adjusted by the grounding validator" in report


def test_report_without_ai_is_honest(correlated_pipeline):
    pipeline, result = correlated_pipeline
    engine, cluster = pipeline.correlator, result.surfaced[0]
    report = build_report(engine.cluster_summary(cluster), None)
    assert "pending. AI triage was not available" in report
    assert "## Timeline" in report
    assert AI_DISCLAIMER not in report  # nothing AI-authored to label
    assert "True Positive" not in report  # no fabricated verdict


def test_technique_label_falls_back_to_uid(fixture_kb):
    assert technique_label("T1110", fixture_kb).startswith("T1110 Brute Force")
    assert technique_label("T4242", fixture_kb) == "T4242"
    assert technique_label("T1110", None) == "T1110"
