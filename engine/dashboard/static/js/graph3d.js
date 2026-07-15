/* 3D force-directed entity graph (Phase 19): entities as nodes, alerts as
 * edges — the view that reveals shared pivot points. Renders exactly one
 * pre-filtered cluster at a time, never the whole alert universe, so it
 * stays performant (Master Specification 6.2).
 *
 * Uses the vendored 3d-force-graph bundle (global ForceGraph3D). */

import { el, riskColor, severityColor } from "./format.js";

let graphInstance = null;

/** Render the cluster graph; calls onSelect(kind, payload) on click. */
export function renderGraph(container, graph, onSelect) {
  const nodes = (graph.nodes || []).map((node) => ({ ...node }));
  const links = (graph.links || []).map((link) => ({ ...link }));

  if (graphInstance === null) {
    graphInstance = ForceGraph3D()(container)
      .backgroundColor("rgba(0,0,0,0)")
      .showNavInfo(false)
      .width(container.clientWidth || 440)
      .height(container.clientHeight || 250);
    window.addEventListener("resize", () => {
      graphInstance
        .width(container.clientWidth || 440)
        .height(container.clientHeight || 250);
    });
  }

  graphInstance
    .nodeId("id")
    .nodeLabel((node) =>
      `<b>${node.id}</b><br/>${node.domain} · risk ${node.risk_score}` +
      `<br/>${node.alerts.length} alert(s)`)
    .nodeColor((node) => resolveCss(riskColor(node.risk_score || 0)))
    .nodeVal((node) => Math.max(2, Math.min(14, 2 + node.risk_score / 4)))
    .nodeOpacity(0.92)
    .linkLabel((link) =>
      `<b>${link.title}</b><br/>${link.alert_uid} · ${link.severity}` +
      `<br/>${link.time_dt}`)
    .linkColor((link) => severityCss(link.severity))
    .linkWidth(1.6)
    .linkOpacity(0.55)
    .linkDirectionalParticles(2)
    .linkDirectionalParticleWidth(1.6)
    .onNodeClick((node) => onSelect("entity", node))
    .onLinkClick((link) => onSelect("alert", link))
    .graphData({ nodes, links });

  return graphInstance;
}

function severityCss(severity) {
  return resolveCss(severityColor(severity));
}

function resolveCss(varName) {
  // Resolve a CSS variable to a concrete colour for WebGL materials.
  const probe = document.createElement("span");
  probe.style.color = varName;
  document.body.append(probe);
  const resolved = getComputedStyle(probe).color;
  probe.remove();
  return resolved || "#757575";
}

/** Inspector content for a clicked node or edge. */
export function describeSelection(kind, payload) {
  if (kind === "entity") {
    const identifiers = Object.entries(payload.identifiers || {})
      .map(([idKind, values]) => `${idKind}: ${values.join(", ")}`)
      .join("\n") || "(none recorded)";
    return el("div", {},
      el("div", { class: "kv" }, el("b", {}, "Entity:"), ` ${payload.id}`,
        payload.is_primary ? " (primary)" : ""),
      el("div", { class: "kv" }, el("b", {}, "Domain:"), ` ${payload.domain}`),
      el("div", { class: "kv" }, el("b", {}, "Risk score:"),
        ` ${payload.risk_score}`),
      el("div", { class: "kv" }, el("b", {}, "Alerts touching it:"),
        ` ${payload.alerts.map((a) => a.uid).join(", ") || "—"}`),
      el("div", { class: "mono-block" }, identifiers),
    );
  }
  const techniques = (payload.techniques || [])
    .map((t) => [t.uid, t.name].filter(Boolean).join(" "))
    .join(", ");
  return el("div", {},
    el("div", { class: "kv" }, el("b", {}, "Alert:"), ` ${payload.alert_uid}`),
    el("div", { class: "kv" }, el("b", {}, "Title:"), ` ${payload.title}`),
    el("div", { class: "kv" }, el("b", {}, "Severity:"),
      ` ${payload.severity}`),
    el("div", { class: "kv" }, el("b", {}, "Time:"), ` ${payload.time_dt}`),
    techniques
      ? el("div", { class: "kv" }, el("b", {}, "ATT&CK:"), ` ${techniques}`)
      : null,
    el("div", { class: "kv" }, el("b", {}, "Connects:"),
      ` ${linkEnd(payload.source)} ↔ ${linkEnd(payload.target)}`),
  );
}

function linkEnd(end) {
  return typeof end === "object" && end !== null ? end.id : String(end);
}
