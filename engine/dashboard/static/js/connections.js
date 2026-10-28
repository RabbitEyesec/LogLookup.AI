/* Connections panel: one card per source, each state visually distinct.
 * A disabled or failing source is never drawn as healthy. Credentials are
 * write-only: they are sent once and the inputs are cleared. */

import { v2Get, v2Send } from "./api.js";
import { el, fmtTime, mount } from "./format.js";

export const STATUS_LABELS = {
  healthy: "Healthy",
  paused: "Paused",
  not_configured: "Not configured",
  permission_denied: "Permission denied",
  limited_by_license: "Limited by licence",
  throttled: "Throttled",
  temporarily_unavailable: "Temporarily unavailable",
  starting: "Starting",
};

export const PROVIDER_BADGES = {
  elastic: "Elastic",
  sentinel: "Sentinel",
  splunk: "Splunk",
  defender_xdr: "Defender XDR",
  entra_id: "Entra ID",
};

export function statusChip(status) {
  return el("span", { class: `v2-status v2-status--${status}` },
    STATUS_LABELS[status] || status);
}

export function providerBadge(provider, count) {
  return el("span", { class: `v2-badge v2-badge--${provider}` },
    PROVIDER_BADGES[provider] || provider, count != null ? ` · ${count}` : "");
}

function scopeLine(c) {
  const o = c.options || {};
  const parts = [o.tenant_id && `tenant ${o.tenant_id}`,
    o.workspace_id && `workspace ${o.workspace_id}`,
    o.management_url, o.host].filter(Boolean);
  return parts.join(" · ") || c.scope_id;
}

function card(conn, reload) {
  const h = conn.health || {};
  const status = conn.paused ? "paused" : (h.status || "not_configured");
  const actions = [];
  if (conn.origin === "managed") {
    actions.push(el("button", {
      onclick: async (ev) => {
        ev.target.disabled = true;
        try { await v2Send(`/connections/${conn.connection_id}/${conn.paused ? "resume" : "pause"}`, "POST"); }
        finally { reload(); }
      },
    }, conn.paused ? "Resume" : "Pause"));
  }
  return el("div", { class: "v2-card", "data-status": status },
    el("div", { class: "v2-card-head" },
      providerBadge(conn.provider), el("strong", {}, conn.name || conn.connection_id),
      statusChip(status)),
    el("div", { class: "v2-meta" }, scopeLine(conn)),
    el("div", { class: "v2-meta" },
      `Last receipt: ${h.last_receipt ? fmtTime(h.last_receipt) : "—"} · `,
      `committed ${h.records_committed ?? 0}`,
      h.quarantined ? ` · quarantined ${h.quarantined}` : ""),
    h.last_error_code
      ? el("div", { class: "v2-meta v2-meta--err" }, `Last error: ${h.last_error_code}`) : null,
    (h.warnings || []).map((w) => el("div", { class: "v2-meta v2-meta--warn" }, w)),
    conn.status === "not_configured" || status === "not_configured"
      ? el("div", { class: "v2-meta" }, conn.prerequisites || "") : null,
    el("div", { class: "row" }, actions,
      conn.managed_by === "legacy_poll"
        ? el("span", { class: "v2-meta" }, "Managed by the original Elastic poll") : null));
}

const CRED_FIELDS = {
  elastic: [["api_key", "API key", "password"]],
  splunk: [["token", "Authentication token", "password"]],
  microsoft: [["client_id", "Client ID", "text"], ["client_secret", "Client secret", "password"]],
};

function addForm(providers, reload) {
  const msg = el("div", { class: "notice", hidden: "" });
  const provider = el("select", {}, Object.entries(providers).map(
    ([k, v]) => el("option", { value: k }, v.label)));
  const id = el("input", { placeholder: "connection id (e.g. sentinel-main)" });
  const options = el("textarea", { rows: "4", spellcheck: "false",
    placeholder: '{"tenant_id": "...", "workspace_id": "..."}' });
  const credInputs = el("div", { class: "v2-creds" });

  const credsFor = () => provider.value === "elastic" ? CRED_FIELDS.elastic
    : provider.value === "splunk" ? CRED_FIELDS.splunk : CRED_FIELDS.microsoft;
  const drawCreds = () => {
    credInputs.replaceChildren(...credsFor().map(([key, label, type]) =>
      el("label", {}, label, el("input", { type, "data-k": key, autocomplete: "off" }))));
  };
  provider.addEventListener("change", drawCreds);
  drawCreds();

  const submit = el("button", { class: "primary", onclick: async () => {
    msg.hidden = true;
    let opts;
    try { opts = options.value.trim() ? JSON.parse(options.value) : {}; }
    catch { msg.className = "notice error"; msg.textContent = "Options must be valid JSON."; msg.hidden = false; return; }
    const credentials = {};
    credInputs.querySelectorAll("input").forEach((i) => { if (i.value) credentials[i.dataset.k] = i.value; });
    const isMs = !["elastic", "splunk"].includes(provider.value);
    if (Object.keys(credentials).length) {
      if (isMs) credentials.kind = "client_secret";
      else if (provider.value === "splunk") credentials.kind = "token";
      else credentials.kind = "api_key";
    }
    try {
      await v2Send("/connections", "POST", {
        connection_id: id.value.trim(), provider: provider.value,
        options: opts, enabled: false,
        credentials: Object.keys(credentials).length ? credentials : undefined,
      });
      id.value = ""; options.value = "";
      credInputs.querySelectorAll("input").forEach((i) => { i.value = ""; });  // write-only
      msg.className = "notice ok";
      msg.textContent = "Saved (disabled). Enable it when its permissions are in place.";
      msg.hidden = false;
      reload();
    } catch (err) {
      msg.className = "notice error"; msg.textContent = err.message; msg.hidden = false;
    }
  } }, "Add connection");

  return el("details", { class: "v2-add" },
    el("summary", {}, "Add a connection"),
    el("label", {}, "Provider", provider), el("label", {}, "Connection id", id),
    el("label", {}, "Options (JSON, no secrets)", options),
    credInputs, submit, msg);
}

export async function renderConnections(root) {
  mount(root, el("div", { class: "v2-meta" }, "Loading connections…"));
  try {
    const data = await v2Get("/connections");
    const reload = () => renderConnections(root);
    mount(root, 
      el("div", { class: "v2-legend" }, "Read-only collection · each source reports its own state"),
      ...data.connections.map((c) => card(c, reload)),
      data.connections.length ? null
        : el("div", { class: "v2-empty" }, "No connections yet. Add Elastic, Sentinel, Splunk, Defender XDR or Entra ID."),
      addForm(data.providers, reload));
  } catch (err) {
    mount(root, el("div", { class: "notice error" }, err.message));
  }
}
