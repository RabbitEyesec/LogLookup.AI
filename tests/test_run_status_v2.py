"""Azure Logic Apps run-status lookup: read-only, exact matching, and no
guessing about what the workflow actually did."""

from __future__ import annotations

import httpx
import pytest

from engine.connectors.base import ConfigurationError, ConnectorError
from engine.connectors.outputs.logic_apps import LogicAppsTransport
from engine.response.models import ActionState, Conflict, DispatchResult, Forbidden, ResponseError
from engine.response.run_status import RunLookup, RunStatusClient, RunStatusService
from tests.test_api_v2 import client, make_api, token_for
from tests.test_response_v2 import FakeTransport, LA, propose, runtime

SUB = "33333333-3333-3333-3333-333333333333"
ACTION = "11111111-aaaa-bbbb-cccc-222222222222"


async def arm_token(_scope):
    return "arm-token"


def arm(plan="consumption"):
    return {"plan": plan, "subscription_id": SUB, "resource_group": "rg1",
            "workflow_name": "notify", "site_name": "la-std"}


def run(name, status="Succeeded", tracking=ACTION, **props):
    return {"name": name, "properties": {
        "status": status, "startTime": "2026-10-28T01:00:00Z",
        "endTime": "2026-10-28T01:00:05Z",
        "correlation": {"clientTrackingId": tracking}, **props}}


class FakeAzure:
    def __init__(self, runs, ignore_filter=False, reject_filter=False):
        self.runs = runs
        self.ignore_filter, self.reject_filter = ignore_filter, reject_filter
        self.requests = []

    def handler(self, request):
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/runs"):
            if "$filter" in request.url.params and self.reject_filter:
                return httpx.Response(400, text="filter not supported")
            runs = self.runs
            if "$filter" in request.url.params and not self.ignore_filter:
                want = request.url.params["$filter"].split("'")[1]
                runs = [r for r in runs if r["properties"]["correlation"]["clientTrackingId"] == want]
            return httpx.Response(200, json={"value": runs})
        name = path.rsplit("/runs/", 1)[1]
        for r in self.runs:
            if r["name"] == name:
                return httpx.Response(200, json=r)
        return httpx.Response(404, text="not found")


def client_for(azure, plan="consumption"):
    return RunStatusClient(arm(plan), arm_token, transport=httpx.MockTransport(azure.handler))


# -- the Azure client -----------------------------------------------------------

async def test_consumption_run_is_read_by_its_run_id_with_get_only():
    azure = FakeAzure([run("RUN1", "Succeeded")])
    found = await client_for(azure).lookup(ACTION, "RUN1")
    assert (found.found, found.status, found.matched_by) == (True, "Succeeded", "run_id")
    (req,) = azure.requests
    assert req.method == "GET" and req.headers["authorization"] == "Bearer arm-token"
    assert req.url.path == (f"/subscriptions/{SUB}/resourceGroups/rg1/providers/"
                            "Microsoft.Logic/workflows/notify/runs/RUN1")
    assert req.url.params["api-version"] == "2016-06-01"


async def test_standard_uses_the_workflow_management_api():
    azure = FakeAzure([run("RUN1")])
    await client_for(azure, "standard").lookup(ACTION, "RUN1")
    path = azure.requests[0].url.path
    assert "/providers/Microsoft.Web/sites/la-std/hostruntime/runtime/webhooks/workflow/" \
           "api/management/workflows/notify/runs/RUN1" in path
    assert azure.requests[0].url.params["api-version"] == "2018-11-01"


async def test_a_run_id_that_belongs_to_another_request_is_not_trusted():
    azure = FakeAzure([run("RUN1", tracking="99999999-0000-0000-0000-000000000000")])
    found = await client_for(azure).lookup(ACTION, "RUN1")
    assert found.found is False and found.reason == "id_mismatch"


@pytest.mark.parametrize("runs,reason,found_flag", [
    ([], "no_match", False),
    ([run("R1")], "ok", True),
    ([run("R1"), run("R2")], "ambiguous", False),
])
async def test_tracking_id_lookup_needs_exactly_one_run(runs, reason, found_flag):
    found = await client_for(FakeAzure(runs)).lookup(ACTION, None)
    assert (found.found, found.reason) == (found_flag, reason)
    if reason == "ok":
        assert found.matched_by == "client_tracking_id" and found.run_name == "R1"


async def test_other_runs_are_never_chosen_even_if_the_server_ignores_the_filter():
    azure = FakeAzure([run("OTHER1", tracking="aaaaaaaa-0000-0000-0000-000000000001"),
                       run("MINE"),
                       run("OTHER2", tracking="aaaaaaaa-0000-0000-0000-000000000002")],
                      ignore_filter=True)
    found = await client_for(azure).lookup(ACTION, None)
    assert found.run_name == "MINE" and found.candidates == 1


async def test_a_server_that_rejects_the_filter_falls_back_to_exact_local_matching():
    azure = FakeAzure([run("MINE"), run("OTHER", tracking="aaaaaaaa-0000-0000-0000-000000000001")],
                      reject_filter=True)
    found = await client_for(azure).lookup(ACTION, None)
    assert found.found and found.run_name == "MINE"


async def test_an_unknown_run_id_falls_back_to_the_tracking_id():
    found = await client_for(FakeAzure([run("REAL")])).lookup(ACTION, "GONE")
    assert found.found and found.run_name == "REAL" and found.matched_by == "client_tracking_id"


@pytest.mark.parametrize("status", ["Running", "Waiting", "Succeeded", "Failed",
                                    "Cancelled", "TimedOut"])
async def test_every_azure_status_is_reported_as_azure_said_it(status):
    found = await client_for(FakeAzure([run("R1", status)])).lookup(ACTION, "R1")
    assert found.status == status and found.found


async def test_error_details_are_kept_short_and_scrubbed():
    err = {"error": {"code": "ActionFailed",
                     "message": "boom Authorization: Bearer abc.def-123 " + "x" * 500}}
    found = await client_for(FakeAzure([run("R1", "Failed", **err)])).lookup(ACTION, "R1")
    assert found.error_code == "ActionFailed" and len(found.error_message) <= 300
    assert "abc.def-123" not in found.error_message


async def test_a_next_link_to_another_host_is_refused():
    def handler(request):
        return httpx.Response(200, json={"value": [], "nextLink": "https://evil.example/runs"})
    c = RunStatusClient(arm(), arm_token, transport=httpx.MockTransport(handler))
    with pytest.raises(ConnectorError) as exc:
        await c.lookup(ACTION, None)
    assert exc.value.code == "bad_next_link"


def test_bad_arm_settings_are_rejected():
    for bad in ({**arm(), "subscription_id": "nope"}, {**arm(), "plan": "premium"},
                {**arm("standard"), "site_name": ""}, {**arm(), "workflow_name": "a/b"}):
        with pytest.raises(ConfigurationError):
            RunStatusClient(bad, arm_token)


async def test_the_transport_sends_the_action_id_as_the_tracking_id():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(202, headers={"x-ms-workflow-run-id": "RUN9",
                                            "x-ms-client-tracking-id": "something-else"})
    t = LogicAppsTransport(
        {"kind": "logic_app", "auth": "sas",
         "url": "https://prod-01.eastus.logic.azure.com/workflows/abc/triggers/manual?sig=S"},
        transport=httpx.MockTransport(handler))
    result = await t.send({"idempotency_key": "k", "action_id": ACTION})
    assert seen["x-ms-client-tracking-id"] == ACTION
    assert result.run_id == "RUN9"                       # only from the run-id header


# -- the "Check remote status" operation ------------------------------------------

class FakeClient:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    async def lookup(self, action_id, run_id):
        self.calls.append((action_id, run_id))
        if self.error:
            raise self.error
        return self.result


def found(status, **kw):
    return RunLookup(True, "ok", status, "client_tracking_id", "RUN7",
                     "2026-10-28T01:00:00Z", "2026-10-28T01:00:05Z", candidates=1, **kw)


async def sent_action(rt, outcome):
    a = await propose(rt)
    await rt.actions.approve("bob", "responder", a.action_id)
    await rt.dispatcher.run_once()
    return (await rt.actions.get(a.action_id))


def install(rt, client):
    rt.run_status = RunStatusService(rt.db, rt.audit, rt.actions, rt.policy, client)


@pytest.mark.parametrize("status,expected", [
    ("Succeeded", ActionState.ACKNOWLEDGED), ("Running", ActionState.ACKNOWLEDGED),
    ("Waiting", ActionState.ACKNOWLEDGED),
    ("Failed", ActionState.RECONCILIATION_REQUIRED),
    ("TimedOut", ActionState.RECONCILIATION_REQUIRED),
    ("Cancelled", ActionState.RECONCILIATION_REQUIRED),
])
async def test_only_a_delivered_run_finalises_an_ambiguous_action(tmp_path, status, expected):
    t = FakeTransport(DispatchResult("unknown", detail="ReadTimeout"))
    rt = await runtime(tmp_path, t)
    try:
        action = await sent_action(rt, "unknown")
        assert action.state == ActionState.RECONCILIATION_REQUIRED
        install(rt, FakeClient(found(status)))
        after = await rt.run_status.check("rob", "responder", action.action_id)
        assert after.state == expected
        assert after.remote_status == status                    # stored apart from our state
        assert after.downstream_effect == "not_observed"         # never inferred
        assert len(t.sent) == 1                                  # the request was NOT sent again
        if expected == ActionState.ACKNOWLEDGED:
            ob = await rt.db.fetchone("SELECT delivery_state FROM outbox")
            assert ob["delivery_state"] == "delivered"
    finally:
        await rt.stop()


@pytest.mark.parametrize("lookup", [
    RunLookup(False, "no_match"), RunLookup(False, "ambiguous", candidates=2),
    RunLookup(False, "id_mismatch"),
])
async def test_zero_or_several_runs_leave_the_action_for_a_person(tmp_path, lookup):
    rt = await runtime(tmp_path, FakeTransport(DispatchResult("unknown")))
    try:
        action = await sent_action(rt, "unknown")
        install(rt, FakeClient(lookup))
        after = await rt.run_status.check("rob", "responder", action.action_id)
        assert after.state == ActionState.RECONCILIATION_REQUIRED
        assert after.remote_status == "unresolved" and after.remote_run["reason"] == lookup.reason
    finally:
        await rt.stop()


async def test_a_failed_run_never_turns_an_acknowledged_action_into_no_effect(tmp_path):
    t = FakeTransport(DispatchResult("accepted", "RUN7", http_status=202))
    rt = await runtime(tmp_path, t)
    try:
        action = await sent_action(rt, "accepted")
        assert action.state == ActionState.ACKNOWLEDGED
        install(rt, FakeClient(found("Failed", error_code="ActionFailed", error_message="step 3")))
        after = await rt.run_status.check("rob", "responder", action.action_id)
        assert after.state == ActionState.ACKNOWLEDGED          # not failed_without_effect
        assert after.remote_status == "Failed" and after.remote_run["error_code"] == "ActionFailed"
        assert after.view()["status_layers"] == {
            "loglookup_dispatch": "acknowledged", "workflow_run": "Failed",
            "downstream_effect": "not_observed"}
        trail = [e for e in await rt.audit.list(target=action.action_id)
                 if e["action"] == "action.remote_status_checked"]
        assert trail and trail[0]["detail"]["status"] == "Failed"
    finally:
        await rt.stop()


async def test_checks_are_for_responders_and_for_sent_actions_only(tmp_path):
    rt = await runtime(tmp_path, FakeTransport(DispatchResult("unknown")))
    try:
        pending = await propose(rt)
        install(rt, FakeClient(found("Succeeded")))
        with pytest.raises(Forbidden):
            await rt.run_status.check("ann", "analyst", pending.action_id)
        with pytest.raises(Conflict):                           # never sent: nothing to look up
            await rt.run_status.check("rob", "responder", pending.action_id)
        install(rt, None)
        await rt.actions.approve("bob", "responder", pending.action_id)
        await rt.dispatcher.run_once()
        with pytest.raises(ResponseError) as exc:
            await rt.run_status.check("rob", "responder", pending.action_id)
        assert exc.value.status == 503
    finally:
        await rt.stop()


async def test_an_azure_failure_is_reported_and_audited_without_changing_state(tmp_path):
    rt = await runtime(tmp_path, FakeTransport(DispatchResult("unknown")))
    try:
        action = await sent_action(rt, "unknown")
        install(rt, FakeClient(error=ConnectorError("denied", code="permission_denied")))
        with pytest.raises(ResponseError) as exc:
            await rt.run_status.check("rob", "responder", action.action_id)
        assert exc.value.status == 502
        assert (await rt.actions.get(action.action_id)).state == ActionState.RECONCILIATION_REQUIRED
        trail = {e["action"] for e in await rt.audit.list(target=action.action_id)}
        assert "action.remote_status_failed" in trail
    finally:
        await rt.stop()


async def test_a_person_records_a_confirmed_downstream_effect_separately(tmp_path):
    rt = await runtime(tmp_path, FakeTransport(DispatchResult("unknown")))
    try:
        action = await sent_action(rt, "unknown")
        install(rt, FakeClient(found("Succeeded")))
        await rt.run_status.check("rob", "responder", action.action_id)       # -> acknowledged
        # a Succeeded run does not prove the effect; only a person's check does
        assert (await rt.actions.get(action.action_id)).downstream_effect == "not_observed"
        await rt.db.execute("UPDATE response_actions SET state='reconciliation_required'")
        done = await rt.reconciler.resolve("rob", "responder", action.action_id, "delivered",
                                           downstream_effect="confirmed", note="seen in ticket")
        assert done.downstream_effect == "confirmed_effect" and done.remote_status == "Succeeded"
        with pytest.raises(Conflict):
            await rt.reconciler.resolve("rob", "responder", action.action_id, "delivered",
                                        downstream_effect="maybe")
    finally:
        await rt.stop()


async def test_the_api_endpoint_is_responder_only_and_audited(tmp_path):
    t = FakeTransport(DispatchResult("unknown"))
    app, rt = await make_api(tmp_path, sources=[], transport=t)
    try:
        action = await sent_action(rt, "unknown")
        install(rt, FakeClient(found("Succeeded")))
        analyst = await token_for(rt, "ann", "analyst")
        responder = await token_for(rt, "rob", "responder")
        url = f"/api/v2/actions/{action.action_id}/check-status"
        async with client(app, host="203.0.113.7") as c:
            assert (await c.post(url, headers=analyst)).status_code == 403
            ok = await c.post(url, headers=responder)
            assert ok.status_code == 200
            body = ok.json()
            assert body["state"] == "acknowledged" and body["remote_status"] == "Succeeded"
            assert body["status_layers"]["downstream_effect"] == "not_observed"
        assert len(t.sent) == 1
    finally:
        await rt.stop()
