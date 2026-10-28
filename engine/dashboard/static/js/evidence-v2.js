/* Evidence inspector: provider, ids, timestamps and content hash for every
 * source record behind an investigation. Raw vendor payloads sit behind an
 * explicit, audited request. */

import { v2Get } from "./api.js";
import { providerBadge } from "./connections.js";
import { el, fmtTime, mount } from "./format.js";

function row(label, value) {
  return el("div", { class: "v2-kv" }, el("span", {}, label),
    el("code", {}, value == null || value === "" ? "—" : String(value)));
}

function eventCard(ev, clusterId) {
  const rawBox = el("pre", { class: "v2-raw", hidden: "" });
  const reveal = el("button", { onclick: async () => {
    reveal.disabled = true;
    try {
      const data = await v2Get(
        `/investigations/${encodeURIComponent(clusterId)}/evidence?include_raw=true&limit=200`);
      const hit = data.events.find((e) => e.canonical_event_id === ev.canonical_event_id);
      rawBox.textContent = JSON.stringify(hit ? hit.raw : null, null, 2);
      rawBox.hidden = false;
    } catch (err) { rawBox.textContent = err.message; rawBox.hidden = false; }
  } }, "Reveal raw record (audited)");
  return el("div", { class: "v2-card" },
    el("div", { class: "v2-card-head" }, providerBadge(ev.provider),
      el("strong", {}, ev.record_kind), el("span", { class: "v2-meta" }, `rev ${ev.revision}`)),
    row("Evidence ref", ev.evidence_ref),
    row("Connection", ev.connection_id),
    row("Source event id", ev.source_event_id),
    row("Event time", ev.event_time ? fmtTime(ev.event_time) : ""),
    row("Observed", ev.observed_at),
    row("SHA-256", ev.raw_sha256),
    ev.duplicate_of ? row("Duplicate of", ev.duplicate_of) : null,
    reveal, rawBox);
}

export async function renderEvidenceV2(root, clusterId) {
  if (!clusterId) {
    mount(root, el("div", { class: "v2-empty" }, "Open an incident to inspect its source evidence."));
    return;
  }
  mount(root, el("div", { class: "v2-meta" }, "Loading evidence…"));
  try {
    const data = await v2Get(`/investigations/${encodeURIComponent(clusterId)}/evidence?limit=100`);
    mount(root, 
      el("div", { class: "v2-legend" }, `${data.total} source record(s) · stored encrypted`),
      ...(data.events.length ? data.events.map((e) => eventCard(e, clusterId))
        : [el("div", { class: "v2-empty" }, "No ledger evidence for this chain (legacy Elastic alerts are read from Elastic).")]));
  } catch (err) {
    mount(root, el("div", { class: "notice error" }, err.message));
  }
}
