"""Alert revisions: an updated vendor payload re-scores its chain without
duplicates, lost evidence or unintended response actions."""

from __future__ import annotations

import asyncio
import json

import pytest

from engine.response.models import ActionState, Conflict
from tests.test_api_v2 import CSRF, client, make_api, token_for
from tests.test_reliability_v2 import frozen, inactive, manual_poll
from tests.test_response_v2 import FakeTransport, LA
from tests.v2_helpers import SENTINEL_ROW, SENTINEL_SRC, MockVendors, build_runtime


def alert(alert_id, minute, host="WS01", severity="High", **extra):
    """A Sentinel row for one alert at 00:<minute> on <host>."""
    entities = json.dumps([{"Type": "host", "HostName": host, "DnsDomain": "corp.local"},
                           {"Type": "account", "Name": "alice", "NTDomain": "CORP"}])
    return {**SENTINEL_ROW, "SystemAlertId": alert_id, "VendorOriginalId": alert_id,
            "StartTime": f"2026-10-28T00:{minute:02d}:00Z",
            "TimeGenerated": f"2026-10-28T00:{minute:02d}:05Z",
            "AlertSeverity": severity, "Entities": entities, **extra}


async def setup(tmp_path, rows, **extra):
    vendors = MockVendors()
    vendors.sentinel_rows = rows
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], vendors, **extra)
    await manual_poll(rt, "sentinel-main")
    await rt.drain_work()
    rt.pipeline.evaluate(flush=True)
    await rt.evaluate_now()                       # investigation revision 1
    return rt, vendors


async def revise(rt, vendors, rows):
    vendors.sentinel_rows = rows
    await manual_poll(rt, "sentinel-main")
    await rt.drain_work()
    await rt.evaluate_now()


def only_chain(rt):
    (cluster,) = rt.pipeline.correlator.clusters()
    return cluster, rt.pipeline.correlator.cluster_summary(cluster)


async def test_a_higher_severity_rescores_the_chain_without_a_second_alert(tmp_path):
    rt, vendors = await setup(tmp_path, [alert("a1", 0)])
    try:
        _, before = only_chain(rt)
        assert before["risk_score"] == 8.0
        await revise(rt, vendors, [alert("a1", 0, severity="Critical",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        _, after = only_chain(rt)
        assert after["alert_count"] == 1                       # still one alert
        assert after["risk_score"] == 16.0 and after["risk_breakdown"]["total"] == 16.0
        revs = await rt.investigations.revisions(after["cluster_id"])
        assert [r["revision"] for r in revs] == [1, 2]         # earlier revision kept
        new = revs[1]["summary"]
        assert new["previous"] == {"revision": 1, "risk_score": 8.0}
        assert new["rule_version"] == "2.0"
        assert new["triggered_by"][0]["source_revision"] == 2
        assert new["triggered_by"][0]["effect"] == "rescored"
        (ref,) = new["source_revisions"].values()
        assert ref["revision"] == 2 and ref["provider"] == "sentinel"
        assert revs[0]["summary"]["risk_score"] == 8.0          # history not rewritten
    finally:
        await rt.stop()


async def test_a_payload_that_changes_nothing_security_relevant_is_not_a_new_revision(tmp_path):
    rt, vendors = await setup(tmp_path, [alert("a1", 0)])
    try:
        await revise(rt, vendors, [alert("a1", 0, Description="reworded text",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        cluster, summary = only_chain(rt)
        assert summary["alert_count"] == 1 and summary["risk_score"] == 8.0
        assert len(await rt.investigations.revisions(cluster.cluster_id)) == 1
        ledger = await rt.db.fetchone("SELECT COUNT(*) AS n FROM source_event_revisions")
        assert ledger["n"] == 2                                 # the new payload is still stored
        states = {i["state"] for i in await rt.db.fetchall("SELECT state FROM ingest_work_items")}
        assert states == {"processed"}
    finally:
        await rt.stop()


async def test_changed_attack_tactics_update_the_progression(tmp_path):
    rt, vendors = await setup(tmp_path, [alert("a1", 0, Tactics="Execution")])
    try:
        assert only_chain(rt)[1]["tactic_sequence"] == ["Execution"]
        await revise(rt, vendors, [alert("a1", 0, Tactics="Execution,CredentialAccess",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        cluster, summary = only_chain(rt)
        assert summary["tactic_sequence"] == ["Execution", "Credential Access"]
        assert len(await rt.investigations.revisions(cluster.cluster_id)) == 2
    finally:
        await rt.stop()


async def test_changed_host_reevaluates_membership_when_it_is_safe(tmp_path):
    rt, vendors = await setup(tmp_path, [alert("a1", 0, host="WS01")])
    try:
        before, _ = only_chain(rt)
        await revise(rt, vendors, [alert("a1", 0, host="WS02",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        cluster, summary = only_chain(rt)
        assert cluster.cluster_id == before.cluster_id          # same investigation id
        assert summary["alert_count"] == 1 and summary["primary_entity"] == "WS02"
        revs = await rt.investigations.revisions(cluster.cluster_id)
        assert revs[-1]["summary"]["triggered_by"][0]["effect"] == "reclustered"
    finally:
        await rt.stop()


async def test_a_change_that_would_split_a_chain_is_flagged_and_nothing_is_rewritten(tmp_path):
    rows = [alert("a1", 0), alert("a2", 10), alert("a3", 20)]   # one chain, a1-a2-a3
    rt, vendors = await setup(tmp_path, rows)
    try:
        before, summary = only_chain(rt)
        assert summary["alert_count"] == 3
        # Kusto returns rows in TimeGenerated order, so the revised a2 comes last
        moved = [rows[0], rows[2],
                 alert("a2", 10, host="WS09", TimeGenerated="2026-10-28T00:40:00Z")]
        await revise(rt, vendors, moved)
        cluster, after = only_chain(rt)
        assert cluster.cluster_id == before.cluster_id and after["alert_count"] == 3
        assert {a["host"] for a in after["alerts"]} == {"WS01"}   # history not rewritten
        (flag,) = await rt.investigations.review_flags(cluster.cluster_id)
        assert "split" in flag["reason"] and flag["revision"] == 2
        revs = await rt.investigations.revisions(cluster.cluster_id)
        assert revs[-1]["summary"]["review_open"] == 1            # visible as its own revision
        assert await rt.investigations.resolve_flag(flag["flag_id"], "ann")
        assert await rt.investigations.review_flags(cluster.cluster_id) == []
    finally:
        await rt.stop()


async def test_a_revision_waits_for_its_original_and_is_applied_in_order(tmp_path):
    vendors = MockVendors()
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], vendors)
    try:
        await manual_poll(rt, "sentinel-main")                  # revision 1 queued
        vendors.sentinel_rows = [dict(vendors.sentinel_rows[0], AlertSeverity="Critical",
                                      TimeGenerated="2026-10-28T00:30:00Z")]
        await manual_poll(rt, "sentinel-main")                  # revision 2 queued
        real = rt.pipeline.process
        calls = []

        def fail_once(record):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("correlator hiccup")
            return real(record)
        rt.pipeline.process = fail_once
        await rt._process_batch()                               # rev 1 fails, rev 2 must wait
        states = {(i["revision"], i["state"]) for i in await rt.db.fetchall(
            "SELECT revision, state FROM ingest_work_items")}
        assert states == {(1, "failed_retryable"), (2, "failed_retryable")}
        await rt.db.execute("UPDATE ingest_work_items SET next_attempt_at='2000-01-01T00:00:00Z'")
        await rt.drain_work()
        rt.pipeline.evaluate(flush=True)
        _, summary = only_chain(rt)
        assert summary["alert_count"] == 1 and summary["risk_score"] == 16.0   # latest applied
    finally:
        await rt.stop()


async def test_ai_analysis_is_marked_stale_not_rewritten_or_rerun(tmp_path):
    rt, vendors = await setup(tmp_path, [alert("a1", 0)])
    try:
        cid = only_chain(rt)[0].cluster_id
        doc = rt.service.results[cid]
        doc["triage"] = {"verdict": "False Positive", "confidence_score": 80}
        doc["triage_status"] = "triaged"                        # an earlier analysis exists
        await revise(rt, vendors, [alert("a1", 0, severity="Critical",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        now = rt.service.results[cid]
        assert now["triage_stale"] is True and "revised" in now["triage_stale_reason"]
        assert now["triage"]["verdict"] == "False Positive"       # kept, not replaced
        assert now["chain"]["risk_score"] == 16.0                 # facts are current
        assert now["evidence_stamp"] != now["current_evidence_stamp"]
    finally:
        await rt.stop()


# ---------------------------------------------------------------------------
# Response proposals are checked against the current revision
# ---------------------------------------------------------------------------

async def with_actions(tmp_path):
    vendors = MockVendors()
    vendors.sentinel_rows = [alert("a1", 0)]
    rt = await frozen(tmp_path, [inactive(SENTINEL_SRC)], vendors, **LA)
    rt.dispatcher._transport = FakeTransport()
    await rt.dispatcher.stop()
    await manual_poll(rt, "sentinel-main")
    await rt.drain_work()
    rt.pipeline.evaluate(flush=True)
    await rt.evaluate_now()
    return rt, vendors


def propose(rt, cluster, revision, message="check ws01"):
    return rt.actions.propose("ann", "analyst", cluster_id=cluster, revision=revision,
                              workflow_id="notify-soc-v1",
                              payload={"message": message, "severity": "high"},
                              evidence_refs=[])


async def test_a_pending_proposal_cannot_be_approved_after_the_investigation_moved(tmp_path):
    rt, vendors = await with_actions(tmp_path)
    try:
        cid = only_chain(rt)[0].cluster_id
        action = await propose(rt, cid, 1)
        await revise(rt, vendors, [alert("a1", 0, severity="Critical",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        with pytest.raises(Conflict) as exc:
            await rt.actions.approve("rob", "responder", action.action_id)
        assert "changed after" in str(exc.value)
        assert (await rt.actions.get(action.action_id)).state == ActionState.EXPIRED
        trail = {e["action"] for e in await rt.audit.list(target=action.action_id)}
        assert "action.superseded" in trail
        fresh = await propose(rt, cid, 2)                        # proposing again on revision 2 works
        assert (await rt.actions.approve("rob", "responder", fresh.action_id)).state == ActionState.QUEUED
    finally:
        await rt.stop()


async def test_an_approved_but_unsent_action_is_not_sent_after_a_revision(tmp_path):
    rt, vendors = await with_actions(tmp_path)
    try:
        cid = only_chain(rt)[0].cluster_id
        action = await propose(rt, cid, 1)
        await rt.actions.approve("rob", "responder", action.action_id)       # queued
        await revise(rt, vendors, [alert("a1", 0, severity="Critical",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        assert await rt.dispatcher.run_once() is False
        assert rt.dispatcher._transport.sent == []                          # never sent
        assert (await rt.actions.get(action.action_id)).state == ActionState.EXPIRED
        assert (await rt.db.fetchone("SELECT delivery_state FROM outbox"))["delivery_state"] == "expired"
    finally:
        await rt.stop()


async def test_an_action_already_in_flight_is_left_alone(tmp_path):
    rt, vendors = await with_actions(tmp_path)
    try:
        cid = only_chain(rt)[0].cluster_id
        action = await propose(rt, cid, 1)
        await rt.actions.approve("rob", "responder", action.action_id)
        claimed, _ = await rt.dispatcher._claim()                           # now dispatching
        await revise(rt, vendors, [alert("a1", 0, severity="Critical",
                                         TimeGenerated="2026-10-28T00:30:00Z")])
        assert claimed.state == ActionState.DISPATCHING
        assert (await rt.actions.get(action.action_id)).state == ActionState.DISPATCHING
    finally:
        await rt.stop()


# ---------------------------------------------------------------------------
# API: earlier revisions stay reachable
# ---------------------------------------------------------------------------

async def test_api_lists_revisions_and_reads_an_earlier_source_version(tmp_path):
    vendors = MockVendors()
    app, rt = await make_api(tmp_path, vendors=vendors)
    try:
        analyst = await token_for(rt, "ann", "analyst")
        viewer = await token_for(rt, "vera", "viewer")
        async with client(app, host="203.0.113.7") as c:
            listing = (await c.get("/api/v2/investigations", headers=viewer)).json()
            cid = listing["investigations"][0]["cluster_id"]
            detail = (await c.get(f"/api/v2/investigations/{cid}", headers=viewer)).json()
            assert detail["ai_stale"] is False and detail["review_flags"] == []
            revs = (await c.get(f"/api/v2/investigations/{cid}/revisions", headers=viewer)).json()
            assert revs["revisions"][0]["revision"] == 1
            ev = (await c.get(f"/api/v2/investigations/{cid}/evidence", headers=viewer)).json()
            first = next(e for e in ev["events"] if e["record_kind"] == "alert"
                         and e["provider"] == "sentinel")
            assert first["revisions"] and first["revisions"][0]["revision"] == 1
            url = (f"/api/v2/investigations/{cid}/evidence/{first['canonical_event_id']}"
                   "/revisions/1")
            assert (await c.get(url, headers=viewer)).status_code == 200      # metadata
            assert (await c.get(url, params={"include_raw": True}, headers=viewer)).status_code == 403
            raw = await c.get(url, params={"include_raw": True}, headers=analyst)
            assert raw.status_code == 200 and raw.json()["raw"]["AlertName"]
            trail = [e["action"] for e in await rt.audit.list(target=cid)]
            assert "evidence.raw_read" in trail
    finally:
        await rt.stop()
