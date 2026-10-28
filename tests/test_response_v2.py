"""Approval-gated response: idempotency, separation of duties, ambiguity."""

from __future__ import annotations

import httpx
import pytest

from engine.connectors.outputs.logic_apps import LogicAppsTransport
from engine.response.models import (
    ActionState, Conflict, DispatchResult, Forbidden, ResponseError,
)
from tests.v2_helpers import MockVendors, build_runtime

LA = {"outputs": {"logic_apps": {
    "enabled": True, "auth_profile_id": "la",
    "allowed_workflows": ["notify-soc-v1", "create-incident-v1"]}}}


class FakeTransport:
    def __init__(self, *results):
        self.results, self.sent = list(results), []

    async def send(self, contract):
        self.sent.append(contract)
        return self.results.pop(0) if self.results else DispatchResult("accepted", "run-1")

    async def aclose(self):
        pass


async def runtime(tmp_path, transport=None):
    import engine.runtime as r  # noqa: F401
    rt = await build_runtime(tmp_path, [], MockVendors(), **LA)
    rt.dispatcher._transport = transport or FakeTransport()
    await rt.dispatcher.stop()  # tests drive run_once() deterministically
    return rt


async def propose(rt, workflow="notify-soc-v1", user="ann", payload=None, rev=1,
                  cluster="CHAIN-X"):
    return await rt.actions.propose(
        user, "analyst", cluster_id=cluster, revision=rev, workflow_id=workflow,
        payload=payload or {"message": "check ws01", "severity": "high"},
        evidence_refs=["SRC:s:alert:1"])


async def test_happy_path_is_dispatched_once_with_idempotency_key(tmp_path):
    t = FakeTransport(DispatchResult("accepted", "run-42", http_status=202))
    rt = await runtime(tmp_path, t)
    try:
        a = await propose(rt)
        assert a.state == ActionState.APPROVAL_REQUIRED
        a = await rt.actions.approve("bob", "responder", a.action_id)
        assert a.state == ActionState.QUEUED
        assert await rt.dispatcher.run_once() is True
        assert await rt.dispatcher.run_once() is False        # nothing left
        a = await rt.actions.get(a.action_id)
        assert a.state == ActionState.ACKNOWLEDGED and a.provider_run_id == "run-42"
        assert len(t.sent) == 1
        sent = t.sent[0]
        assert sent["idempotency_key"] == a.idempotency_key
        assert sent["requested_operation"] == "notify_analyst"
        assert sent["approved_by"] == ["bob"] and sent["scope_id"] == "org-local"
        view = a.view()["status_layers"]
        assert view["downstream_effect"] == "not_observed"    # 202 != effect
    finally:
        await rt.stop()


async def test_duplicate_proposal_is_refused_until_the_first_is_closed(tmp_path):
    rt = await runtime(tmp_path)
    try:
        first = await propose(rt)
        with pytest.raises(Conflict):
            await propose(rt)                                  # identical, still live
        await rt.actions.reject("bob", "responder", first.action_id, "no")
        again = await propose(rt)                              # rejected frees the key
        assert again.action_id != first.action_id
        # a rejected action cannot be revived
        with pytest.raises(Conflict):
            await rt.actions.approve("bob", "responder", first.action_id)
    finally:
        await rt.stop()


async def test_roles_and_separation_of_duties_enforced_server_side(tmp_path):
    rt = await runtime(tmp_path)
    try:
        with pytest.raises(Forbidden):
            await rt.actions.propose("v", "viewer", cluster_id="C", revision=1,
                                     workflow_id="notify-soc-v1",
                                     payload={"message": "m", "severity": "low"},
                                     evidence_refs=[])
        a = await propose(rt, workflow="create-incident-v1", user="ann",
                          payload={"title": "T", "severity": "high"})
        with pytest.raises(Forbidden):
            await rt.actions.approve("ann", "responder", a.action_id)   # self-approve
        with pytest.raises(Forbidden):
            await rt.actions.approve("bob", "analyst", a.action_id)     # wrong role
        done = await rt.actions.approve("bob", "responder", a.action_id)
        assert done.state == ActionState.QUEUED
    finally:
        await rt.stop()


async def test_payload_is_typed_and_workflow_must_be_allowlisted(tmp_path):
    rt = await runtime(tmp_path)
    try:
        with pytest.raises(ResponseError):
            await propose(rt, payload={"message": "m", "severity": "apocalyptic"})
        with pytest.raises(ResponseError):
            await propose(rt, payload={"message": "m", "severity": "low",
                                       "url": "https://evil.example"})
        with pytest.raises(Forbidden):
            await propose(rt, workflow="isolate-host-v1")
        with pytest.raises(Forbidden):            # defined, but not enabled in config
            await propose(rt, workflow="handoff-escalation-v1",
                          payload={"team": "t", "summary": "s"})
    finally:
        await rt.stop()


async def test_ambiguous_delivery_is_never_resent_and_can_be_reconciled(tmp_path):
    t = FakeTransport(DispatchResult("unknown", detail="ReadTimeout"))
    rt = await runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        await rt.dispatcher.run_once()
        a = await rt.actions.get(a.action_id)
        assert a.state == ActionState.RECONCILIATION_REQUIRED
        assert await rt.dispatcher.run_once() is False         # NOT retried
        assert len(t.sent) == 1
        a = await rt.reconciler.resolve("bob", "responder", a.action_id,
                                        "delivered", run_id="run-9", note="seen in portal")
        assert a.state == ActionState.ACKNOWLEDGED and a.provider_run_id == "run-9"
        with pytest.raises(Conflict):
            await rt.reconciler.resolve("bob", "responder", a.action_id, "delivered")
    finally:
        await rt.stop()


async def test_rejected_by_workflow_fails_without_effect(tmp_path):
    t = FakeTransport(DispatchResult("rejected", detail="HTTP 400", http_status=400))
    rt = await runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        await rt.dispatcher.run_once()
        assert (await rt.actions.get(a.action_id)).state == ActionState.FAILED_WITHOUT_EFFECT
    finally:
        await rt.stop()


async def test_crash_mid_dispatch_goes_to_reconciliation_not_resend(tmp_path):
    t = FakeTransport()
    rt = await runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        # simulate: claimed + marked dispatching, then the process died mid-send
        item = await rt.outbox.claim_next()
        row = await rt.actions.get(a.action_id)
        await rt.dispatcher._set_state(row, ActionState.DISPATCHING, "system", "sending")
        assert await rt.dispatcher.recover() == 1
        assert (await rt.actions.get(a.action_id)).state == ActionState.RECONCILIATION_REQUIRED
        assert await rt.dispatcher.run_once() is False and t.sent == []
        assert item["action_id"] == a.action_id
    finally:
        await rt.stop()


async def test_claimed_but_never_started_is_safely_requeued(tmp_path):
    t = FakeTransport()
    rt = await runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        await rt.outbox.claim_next()           # crash before DISPATCHING was recorded
        assert await rt.dispatcher.recover() == 0
        await rt.dispatcher.run_once()
        assert len(t.sent) == 1
    finally:
        await rt.stop()


async def test_expired_action_cannot_be_approved(tmp_path):
    rt = await runtime(tmp_path)
    try:
        a = await propose(rt)
        await rt.db.execute("UPDATE response_actions SET expires_at='2000-01-01T00:00:00Z'")
        with pytest.raises(Conflict):
            await rt.actions.approve("bob", "responder", a.action_id)
        assert (await rt.actions.get(a.action_id)).state == ActionState.EXPIRED
    finally:
        await rt.stop()


async def test_audit_chain_detects_tampering(tmp_path):
    rt = await runtime(tmp_path)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        assert (await rt.audit.verify())["valid"] is True
        await rt.db.execute(
            "UPDATE audit_events SET actor='mallory' WHERE seq=1")
        verdict = await rt.audit.verify()
        assert verdict["valid"] is False and verdict["broken_at"] == 1
    finally:
        await rt.stop()


async def test_concurrent_writers_do_not_corrupt_transactions(tmp_path):
    import asyncio
    rt = await runtime(tmp_path)
    try:
        async def one(i):
            a = await propose(rt, payload={"message": f"m{i}", "severity": "low"},
                              cluster=f"C{i}")
            return await rt.actions.approve("bob", "responder", a.action_id)
        done = await asyncio.gather(*(one(i) for i in range(12)))
        assert all(d.state == ActionState.QUEUED for d in done)
        assert (await rt.audit.verify())["valid"] is True
    finally:
        await rt.stop()


# -- Logic Apps transport classification ---------------------------------------------

def la(handler, auth="sas"):
    return LogicAppsTransport(
        {"kind": "logic_app", "auth": auth,
         "url": "https://prod-01.eastus.logic.azure.com/workflows/abc/triggers/manual?sig=SECRET"},
        transport=httpx.MockTransport(handler))


CONTRACT = {"idempotency_key": "k", "action_id": "a"}


async def test_logic_apps_classifies_outcomes():
    ok = await la(lambda r: httpx.Response(202, headers={"x-ms-workflow-run-id": "R1"})).send(CONTRACT)
    assert (ok.outcome, ok.run_id) == ("accepted", "R1")
    assert (await la(lambda r: httpx.Response(400)).send(CONTRACT)).outcome == "rejected"
    assert (await la(lambda r: httpx.Response(429)).send(CONTRACT)).outcome == "rejected"
    assert (await la(lambda r: httpx.Response(502)).send(CONTRACT)).outcome == "unknown"

    def read_timeout(_r):
        raise httpx.ReadTimeout("slow")
    def no_connect(_r):
        raise httpx.ConnectError("refused")
    assert (await la(read_timeout).send(CONTRACT)).outcome == "unknown"
    assert (await la(no_connect).send(CONTRACT)).outcome == "rejected"


async def test_logic_apps_sends_idempotency_headers_and_hides_sas_in_results():
    seen = {}
    def h(r):
        seen.update(r.headers)
        return httpx.Response(400)
    result = await la(h).send(CONTRACT)
    assert seen["idempotency-key"] == "k" and seen["x-loglookup-action-id"] == "a"
    assert "SECRET" not in result.detail


def test_logic_apps_refuses_non_azure_hosts():
    from engine.connectors.base import ConfigurationError
    with pytest.raises(ConfigurationError):
        LogicAppsTransport({"kind": "logic_app", "auth": "sas",
                            "url": "https://attacker.example/hook"})


async def test_cancel_that_lands_after_the_claim_wins_over_dispatch(tmp_path):
    t = FakeTransport()
    rt = await runtime(tmp_path, t)
    try:
        a = await propose(rt)
        await rt.actions.approve("bob", "responder", a.action_id)
        claimed = await rt.outbox.claim_next()            # dispatcher claimed it...
        await rt.actions.cancel("ann", "analyst", a.action_id)   # ...then the requester cancelled
        assert claimed["action_id"] == a.action_id
        # the dispatcher's guarded transition now refuses, so nothing is sent
        row = await rt.actions.get(a.action_id)
        applied = await rt.dispatcher._set_state(
            row, ActionState.DISPATCHING, "system", "sending",
            expect=ActionState.QUEUED)
        assert applied is False and t.sent == []
        assert (await rt.actions.get(a.action_id)).state == ActionState.CANCELLED
    finally:
        await rt.stop()
