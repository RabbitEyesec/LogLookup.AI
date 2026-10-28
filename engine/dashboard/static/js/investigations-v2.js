/* Multi-source investigation panel + the Sources & Response drawer
 * controller. Everything shown is served by /api/v2; nothing is inferred
 * client-side. External links open in a new tab and are never fetched by
 * the server. */

import { v2Get, v2Send } from "./api.js";
import { providerBadge, renderConnections } from "./connections.js";
import { renderEvidenceV2 } from "./evidence-v2.js";
import { renderResponse } from "./response.js";
import { el, fmtTime, mount } from "./format.js";

const $ = (id) => document.getElementById(id);
const PROVIDERS = ["", "elastic", "sentinel", "splunk", "defender_xdr", "entra_id"];

function currentClusterId() {
  const m = window.location.pathname.match(/^\/incident\/(.+)$/);
  return m ? decodeURIComponent(m[1]) : null;
}

function safeLink(link) {
  if (typeof link.url !== "string" || !link.url.startsWith("https://")) return null;
  const label = link.title || (link.kind === "provider_incident"
    ? `${(link.provider || "provider").replace("_", " ")} incident ${link.external_incident_id || ""}`.trim()
    : link.kind);
  return el("a", { href: link.url, target: "_blank", rel: "noopener noreferrer" }, `${label} ↗`);
}

function breakdownTable(bd) {
  if (!bd || !bd.rule_version) return null;
  const rows = [["Severity evidence", bd.severity_evidence],
    ["Independent source confirmation", bd.independent_source_confirmation],
    ["Supported attack progression", bd.supported_attack_progression],
    ["Benign / conflicting context", bd.documented_benign_or_conflicting_context],
    ["Total", bd.total]];
  return el("div", { class: "v2-card" }, el("h3", {}, `Risk breakdown · rules v${bd.rule_version}`),
    ...rows.map(([k, v]) => el("div", { class: "v2-kv" }, el("span", {}, k),
      el("code", {}, Number(v ?? 0).toFixed(1)))));
}

export async function renderInvestigationV2(root, clusterId) {
  if (!clusterId) return renderInvestigationList(root);
  mount(root, el("div", { class: "v2-meta" }, "Loading…"));
  try {
    const d = await v2Get(`/investigations/${encodeURIComponent(clusterId)}`);
    const links = (await v2Get(`/investigations/${encodeURIComponent(clusterId)}/external-links`)).links
      .map(safeLink).filter(Boolean);
    const chain = d.document.chain || {};
    const ctx = d.identity_context || { observations: [] };
    const noteBox = el("textarea", { rows: "3", maxlength: "5000", placeholder: "Analyst note" });
    const noteMsg = el("div", { class: "notice", hidden: "" });
    mount(root, 
      el("div", { class: "v2-card" },
        el("div", { class: "v2-card-head" }, el("strong", {}, d.cluster_id),
          el("span", { class: "v2-meta" }, `revision ${d.revision} · ${d.status}`)),
        d.resolved_from ? el("div", { class: "v2-meta" }, `Resolved from merged id ${d.resolved_from}`) : null,
        el("div", { class: "v2-badges" }, (chain.sources || []).map((s) => providerBadge(s.provider, s.alert_count))),
        el("div", { class: "v2-meta" }, `Owner: ${d.owner || "unassigned"}`)),
      breakdownTable(chain.risk_breakdown),
      el("div", { class: "v2-card" }, el("h3", {}, "Identity context (not detections)"),
        ...(ctx.observations.length ? ctx.observations.slice(0, 20).map((o) =>
          el("div", { class: "v2-kv" }, el("span", {}, `${o.type} · ${o.principal}`),
            el("code", {}, fmtTime(o.event_time))))
          : [el("div", { class: "v2-empty" }, ctx.note || "No linked identity context.")])),
      el("div", { class: "v2-card" }, el("h3", {}, "Provider links"),
        ...(links.length ? links.map((a) => el("div", {}, a)) : [el("div", { class: "v2-empty" }, "None.")])),
      el("div", { class: "v2-card" }, el("h3", {}, "Notes"),
        ...d.notes.map((n) => el("div", { class: "v2-meta" }, `${n.author}: ${n.body}`)),
        noteBox,
        el("button", { onclick: async () => {
          try {
            await v2Send(`/investigations/${encodeURIComponent(clusterId)}/notes`, "POST",
              { body: noteBox.value, expected_revision: d.revision });
            renderInvestigationV2(root, clusterId);
          } catch (err) { noteMsg.className = "notice error"; noteMsg.textContent = err.message; noteMsg.hidden = false; }
        } }, "Add note"), noteMsg));
  } catch (err) {
    mount(root, el("div", { class: "notice error" }, err.message));
  }
}

export async function renderInvestigationList(root, provider = "") {
  mount(root, el("div", { class: "v2-meta" }, "Loading…"));
  try {
    const q = provider ? `?provider=${encodeURIComponent(provider)}` : "";
    const data = await v2Get(`/investigations${q}`);
    const filters = el("div", { class: "seg" }, PROVIDERS.map((p) => el("button", {
      class: p === provider ? "on" : "", onclick: () => renderInvestigationList(root, p) },
      p ? p.replace("_", " ") : "All")));
    mount(root, filters,
      ...(data.investigations.length ? data.investigations.map((i) =>
        el("a", { class: "v2-card v2-link", href: `/incident/${encodeURIComponent(i.cluster_id)}` },
          el("div", { class: "v2-card-head" }, el("strong", {}, i.title || i.cluster_id),
            el("span", { class: "v2-meta" }, `risk ${Math.round(i.risk_score)} · ${i.status}`)),
          el("div", { class: "v2-badges" }, i.sources.map((s) => providerBadge(s.provider, s.alert_count))),
          el("div", { class: "v2-meta" }, `${i.source_diversity} source(s) · ${i.cluster_id}`)))
        : [el("div", { class: "v2-empty" }, "No investigations match this source filter.")]));
  } catch (err) {
    mount(root, el("div", { class: "notice error" }, err.message));
  }
}

const TABS = {
  sources: (body) => renderConnections(body),
  investigation: (body) => renderInvestigationV2(body, currentClusterId()),
  evidence: (body) => renderEvidenceV2(body, currentClusterId()),
  response: (body) => renderResponse(body, currentClusterId()),
};
let activeTab = "sources";

function show(tab) {
  activeTab = tab;
  document.querySelectorAll("#v2-tabs button").forEach((b) =>
    b.classList.toggle("on", b.dataset.tab === tab));
  TABS[tab]($("v2-body"));
}

function open(tab) {
  $("v2-drawer").classList.add("open");
  $("v2-scrim").classList.add("open");
  show(tab || activeTab);
}

function close() {
  $("v2-drawer").classList.remove("open");
  $("v2-scrim").classList.remove("open");
}

if ($("btn-v2")) {
  $("btn-v2").addEventListener("click", () => open());
  $("v2-close").addEventListener("click", close);
  $("v2-scrim").addEventListener("click", close);
  document.querySelectorAll("#v2-tabs button").forEach((b) =>
    b.addEventListener("click", () => show(b.dataset.tab)));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
}
