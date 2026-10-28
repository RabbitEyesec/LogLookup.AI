/* Response drawer: preview the exact outbound payload, then propose.
 * Approval, separation of duties and dispatch are enforced by the server;
 * the buttons here only reflect state. A workflow acknowledgement is shown
 * separately from any downstream effect. */

import { v2Get, v2Send } from "./api.js";
import { el, mount } from "./format.js";

const STATE_HINT = {
  approval_required: "Waiting for approval",
  queued: "Approved - queued for dispatch",
  dispatching: "Sending",
  acknowledged: "Workflow accepted the request (not proof of effect)",
  reconciliation_required: "Delivery unknown - will NOT be resent automatically",
  failed_without_effect: "Not delivered - no effect",
  rejected: "Rejected", expired: "Expired", cancelled: "Cancelled", completed: "Completed",
};

function actionCard(a, reload) {
  const btn = (label, path, body, cls = "") => el("button", { class: cls,
    onclick: async (ev) => {
      ev.target.disabled = true;
      try { await v2Send(path, "POST", body); } catch (err) { alert(err.message); }
      reload();
    } }, label);
  const buttons = [];
  if (a.state === "approval_required") {
    buttons.push(btn("Approve", `/actions/${a.action_id}/approve`, { rationale: "" }, "primary"),
      btn("Reject", `/actions/${a.action_id}/reject`, { rationale: "" }),
      btn("Cancel", `/actions/${a.action_id}/cancel`));
  }
  if (a.state === "reconciliation_required") {
    buttons.push(
      btn("Mark delivered", `/actions/${a.action_id}/reconcile`, { outcome: "delivered" }),
      btn("Mark not delivered", `/actions/${a.action_id}/reconcile`, { outcome: "not_delivered" }));
  }
  const layers = a.status_layers || {};
  return el("div", { class: `v2-card v2-action v2-action--${a.state}` },
    el("div", { class: "v2-card-head" }, el("strong", {}, a.workflow_id),
      el("span", { class: `v2-status v2-status--${a.state}` }, a.state.replaceAll("_", " "))),
    el("div", { class: "v2-meta" }, STATE_HINT[a.state] || ""),
    el("div", { class: "v2-meta" },
      `Requested by ${a.requested_by} · approvals ${a.approvals.length}/${a.approvals_required}`),
    el("div", { class: "v2-meta" },
      `Dispatch: ${layers.loglookup_dispatch} · Workflow run: ${layers.workflow_run} · Downstream effect: ${layers.downstream_effect}`),
    a.provider_run_id ? el("div", { class: "v2-meta" }, `Run reference: ${a.provider_run_id}`) : null,
    el("div", { class: "row" }, buttons));
}

function form(clusterId, revision, refs, workflows, reload) {
  const wf = el("select", {}, workflows.map((w) => el("option", { value: w.workflow_id }, w.label)));
  const fields = el("div", {});
  const preview = el("pre", { class: "v2-raw" });
  const msg = el("div", { class: "notice", hidden: "" });
  const values = {};

  const current = () => workflows.find((w) => w.workflow_id === wf.value);
  const draw = () => {
    fields.replaceChildren();
    for (const k of Object.keys(values)) delete values[k];
    for (const [name, spec] of Object.entries(current().fields)) {
      const input = spec.type === "enum"
        ? el("select", {}, el("option", { value: "" }, "—"),
            spec.choices.map((c) => el("option", { value: c }, c)))
        : el("input", { maxlength: String(spec.max_len) });
      input.addEventListener("input", () => { values[name] = input.value; refresh(); });
      input.addEventListener("change", () => { values[name] = input.value; refresh(); });
      fields.append(el("label", {}, name + (spec.required ? " *" : ""), input));
    }
    refresh();
  };
  const refresh = () => {
    preview.textContent = JSON.stringify({
      workflow_id: wf.value, cluster_id: clusterId, investigation_revision: revision,
      evidence_refs: refs, payload: Object.fromEntries(
        Object.entries(values).filter(([, v]) => v)),
    }, null, 2);
  };
  wf.addEventListener("change", draw);
  draw();

  const submit = el("button", { class: "primary", onclick: async () => {
    msg.hidden = true;
    try {
      await v2Send(`/investigations/${encodeURIComponent(clusterId)}/actions`, "POST", {
        workflow_id: wf.value, expected_revision: revision, evidence_refs: refs,
        payload: Object.fromEntries(Object.entries(values).filter(([, v]) => v)),
      });
      reload();
    } catch (err) { msg.className = "notice error"; msg.textContent = err.message; msg.hidden = false; }
  } }, "Request approval");

  return el("div", { class: "v2-card" },
    el("h3", {}, "Propose a workflow"),
    el("label", {}, "Workflow", wf), fields,
    el("h3", {}, "Exact outbound payload"), preview, submit, msg);
}

export async function renderResponse(root, clusterId) {
  if (!clusterId) {
    mount(root, el("div", { class: "v2-empty" }, "Open an incident to propose a response."));
    return;
  }
  mount(root, el("div", { class: "v2-meta" }, "Loading…"));
  const reload = () => renderResponse(root, clusterId);
  try {
    const [wf, inv, acts] = await Promise.all([
      v2Get("/response/workflows"),
      v2Get(`/investigations/${encodeURIComponent(clusterId)}`),
      v2Get(`/investigations/${encodeURIComponent(clusterId)}/actions`),
    ]);
    const nodes = [];
    if (!wf.enabled || !wf.workflows.length) {
      nodes.push(el("div", { class: "v2-empty" },
        "The Logic Apps response channel is not enabled. Nothing can be dispatched."));
    } else {
      nodes.push(form(inv.cluster_id, inv.revision, inv.evidence_refs.slice(0, 1), wf.workflows, reload));
    }
    nodes.push(el("h3", {}, "Action history"),
      ...(acts.actions.length ? acts.actions.map((a) => actionCard(a, reload))
        : [el("div", { class: "v2-empty" }, "No actions yet.")]));
    mount(root, ...nodes);
  } catch (err) {
    mount(root, el("div", { class: "notice error" }, err.message));
  }
}
