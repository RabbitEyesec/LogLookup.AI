"""End-to-end v2: mocked vendor APIs -> ledger -> correlation -> investigations."""

from __future__ import annotations

import pytest

from tests.v2_helpers import (
    DEFENDER_SRC, ENTRA_SRC, SENTINEL_SRC, SPLUNK_SRC, MockVendors,
    build_runtime, graph_alert, settle,
)


async def _chains(rt):
    rt.pipeline.evaluate(flush=True)
    await rt.evaluate_now()
    return rt.pipeline.correlator.clusters()


async def test_cross_source_chain_with_provenance_and_independent_confirmation(tmp_path):
    vendors = MockVendors()
    rt = await build_runtime(tmp_path, [SENTINEL_SRC, DEFENDER_SRC], vendors)
    try:
        # sentinel alert + graph alert + graph incident
        await settle(rt, 3)
        clusters = await _chains(rt)
        assert len(clusters) == 1
        cluster = clusters[0]
        assert cluster.alert_count == 2
        summary = rt.pipeline.correlator.cluster_summary(cluster)
        providers = {s["provider"] for s in summary["sources"]}
        assert providers == {"sentinel", "defender_xdr"}
        # Microsoft CamelCase tactics are canonicalised, so the two sources
        # chain as a genuine progression Execution -> Credential Access.
        assert summary["tactic_sequence"] == ["Execution", "Credential Access"]
        assert summary["disposition"] == "progressing"
        bd = summary["risk_breakdown"]
        assert bd["independent_source_confirmation"] == 4.0
        assert bd["total"] == summary["risk_score"] == 20.0
        # provenance rides on every alert, with a citable evidence ref
        refs = {a["source"]["evidence_ref"] for a in summary["alerts"]}
        assert "SRC:sentinel-main:alert:sent-alert-1" in refs
        # the incident is a link, never a detection
        links = await rt.db.fetchall("SELECT * FROM incident_links")
        assert any(l["external_incident_id"] == "inc-1" for l in links)
        assert not any(a["title"] == "Multi-stage incident" for a in summary["alerts"])
    finally:
        await rt.stop()


async def test_sentinel_origin_graph_alert_counts_once(tmp_path):
    vendors = MockVendors()
    # Graph exposes the SAME alert Sentinel already delivered.
    vendors.graph_alerts = [graph_alert(
        alert_id="gr-dup", provider_id="sent-alert-1", service="microsoftSentinel")]
    rt = await build_runtime(tmp_path, [SENTINEL_SRC, DEFENDER_SRC], vendors)
    try:
        await settle(rt, 3)
        clusters = await _chains(rt)
        assert sum(c.alert_count for c in clusters) == 1
        dup = await rt.db.fetchall(
            "SELECT duplicate_of FROM source_events WHERE record_kind='alert'")
        assert sorted(bool(d["duplicate_of"]) for d in dup) == [False, True]
    finally:
        await rt.stop()


async def test_entra_context_is_not_a_detection_but_enriches(tmp_path):
    vendors = MockVendors()
    rt = await build_runtime(tmp_path, [DEFENDER_SRC, ENTRA_SRC], vendors)
    try:
        await settle(rt, 3)  # alert + incident + signin
        clusters = await _chains(rt)
        assert clusters[0].alert_count == 1  # the sign-in did not become an alert
        summary = rt.pipeline.correlator.cluster_summary(clusters[0])
        ctx = await rt.context_for(summary)
        assert ctx["principals"] == ["alice@corp.com"]
        assert [o["type"] for o in ctx["observations"]] == ["signin"]
        assert ctx["note"] == "context observations are not detections"
    finally:
        await rt.stop()


async def test_splunk_notable_flows_through_export(tmp_path):
    vendors = MockVendors()
    vendors.splunk_rows = [{
        "_time": "2026-10-28T00:00:00.000+00:00", "_indextime": "1761609700",
        "_cd": "4:77", "index": "notable", "event_id": "notable-1",
        "rule_name": ["Brute Force"], "urgency": "high", "dest": "srv-db",
        "user": "bob", "splunk_server": "splunk-1"}]
    rt = await build_runtime(tmp_path, [SPLUNK_SRC], vendors)
    try:
        await settle(rt, 1)
        rt.pipeline.evaluate(flush=True)
        alerts = [a for c in rt.pipeline.correlator.clusters()
                  for a in rt.pipeline.correlator.alerts_of(c)]
        assert alerts[0].finding_info.title == "Brute Force"
        assert alerts[0].unmapped["source"]["provider"] == "splunk"
        assert alerts[0].finding_info.uid == "splunk-es:notable-1"
    finally:
        await rt.stop()


async def test_cursor_dedup_and_investigation_ids_survive_restart(tmp_path):
    vendors = MockVendors()
    rt = await build_runtime(tmp_path, [SENTINEL_SRC, DEFENDER_SRC], vendors)
    await settle(rt, 3)
    first_ids = {c.cluster_id for c in await _chains(rt)}
    row = await rt.db.fetchone("SELECT COUNT(*) AS n FROM source_events")
    stored = row["n"]
    await rt.stop()

    # Restart on the same home: same vendor data is re-delivered (overlap)...
    rt2 = await build_runtime(tmp_path, [SENTINEL_SRC, DEFENDER_SRC], vendors)
    try:
        await settle(rt2, stored)
        again = {c.cluster_id for c in await _chains(rt2)}
        # ...the ledger collapses it, and the chain keeps its original id.
        row = await rt2.db.fetchone("SELECT COUNT(*) AS n FROM source_events")
        assert row["n"] == stored
        assert again == first_ids
        inv = await rt2.investigations.list()
        assert {i["cluster_id"] for i in inv} == first_ids
    finally:
        await rt2.stop()


async def test_changed_payload_is_a_new_revision_not_a_new_event(tmp_path):
    vendors = MockVendors()
    rt = await build_runtime(tmp_path, [SENTINEL_SRC], vendors)
    try:
        await settle(rt, 1)
        vendors.sentinel_rows = [dict(vendors.sentinel_rows[0],
                                      Description="updated", TimeGenerated="2026-10-28T00:09:00Z")]
        worker = rt.supervisor.workers["sentinel-main"]
        connector = rt._make_connector(worker.conn)
        await connector.open()
        await worker._poll_once(connector)
        await connector.close()
        rows = await rt.db.fetchall(
            "SELECT revision FROM source_events WHERE record_kind='alert'")
        assert [r["revision"] for r in rows] == [2]
        ev = await rt.ledger.get_event(
            (await rt.db.fetchone("SELECT canonical_event_id AS c FROM source_events"))["c"],
            include_raw=True)
        assert ev["raw"]["Description"] == "updated"
    finally:
        await rt.stop()


async def test_failing_source_does_not_stop_the_others(tmp_path):
    vendors = MockVendors()
    vendors.fail_next["loganalytics"] = 100  # sentinel throttled forever
    rt = await build_runtime(tmp_path, [SENTINEL_SRC, DEFENDER_SRC], vendors)
    try:
        await settle(rt, 2)  # defender alert + incident still arrive
        health = rt.supervisor.health()
        assert health["defender-xdr"]["status"] == "healthy"
        assert health["sentinel-main"]["status"] == "throttled"
        assert health["sentinel-main"]["last_error_code"] == "throttled"
    finally:
        await rt.stop()


async def test_raw_evidence_is_encrypted_at_rest(tmp_path):
    vendors = MockVendors()
    rt = await build_runtime(tmp_path, [SENTINEL_SRC], vendors)
    try:
        await settle(rt, 1)
        row = await rt.db.fetchone("SELECT raw_enc, raw_sha256 FROM source_events")
        assert b"Suspicious PowerShell" not in row["raw_enc"]
        ev = await rt.ledger.get_event(
            (await rt.db.fetchone("SELECT canonical_event_id AS c FROM source_events"))["c"],
            include_raw=True)
        assert ev["raw"]["AlertName"] == "Suspicious PowerShell"
    finally:
        await rt.stop()
