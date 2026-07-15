/* Deterministic 2D attack-chain graph. Events form the timeline spine;
 * observed entities, techniques, commands, files, persistence artifacts and
 * network values are placed around the event that contains them. */

import { riskColor, severityColor } from "./format.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const KIND_COLORS = {
  event: "var(--signal)", technique: "var(--sev-medium)", host: "var(--sev-high)",
  user: "#9fa8da", ip: "#80cbc4", process: "#ce93d8", parent_process: "#b39ddb",
  powershell: "#42a5f5", encoded_command: "var(--sev-critical)", command: "#90caf9",
  downloaded_file: "#ffcc80", registry: "#ef9a9a", scheduled_task: "#ffab91",
  service: "#bcaaa4", network: "#80cbc4",
};

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

function endpoint(value) {
  return typeof value === "object" && value ? value.id : value;
}

function layout(nodes, links, width, height) {
  const positions = new Map();
  const events = nodes.filter((node) => node.kind === "event")
    .sort((a, b) => (a.index || 0) - (b.index || 0));
  const eventIndex = new Map(events.map((node, index) => [node.id, index]));
  const xAt = (index) => 54 + (index / Math.max(events.length - 1, 1)) * Math.max(width - 108, 1);
  events.forEach((node, index) => positions.set(node.id, { x: xAt(index), y: height * 0.52 }));

  const attached = new Map();
  for (const link of links) {
    const source = endpoint(link.source); const target = endpoint(link.target);
    if (eventIndex.has(source) && !eventIndex.has(target)) attached.set(target, source);
    if (eventIndex.has(target) && !eventIndex.has(source)) attached.set(source, target);
  }
  const buckets = new Map();
  for (const node of nodes.filter((item) => item.kind !== "event")) {
    const anchor = attached.get(node.id) || events[0]?.id;
    const key = `${anchor}:${["host", "user", "ip", "entity"].includes(node.kind) ? "top" : "bottom"}`;
    const list = buckets.get(key) || [];
    list.push(node);
    buckets.set(key, list);
  }
  for (const [key, bucket] of buckets) {
    const [anchorId, side] = key.split(":");
    const anchor = positions.get(anchorId) || { x: width / 2, y: height / 2 };
    bucket.sort((a, b) => a.id.localeCompare(b.id));
    bucket.forEach((node, index) => {
      const spread = Math.min(64, Math.max(30, width / Math.max(events.length * 2, 2)));
      const offset = (index - (bucket.length - 1) / 2) * spread;
      const row = Math.floor(index / 4);
      positions.set(node.id, {
        x: Math.max(34, Math.min(width - 34, anchor.x + offset)),
        y: side === "top" ? 46 + row * 45 : height - 46 - row * 45,
      });
    });
  }
  return positions;
}

export function renderGraph2D(container, graph, { selectedUid, onSelect } = {}) {
  container.replaceChildren();
  const nodes = graph.chain_nodes || graph.nodes || [];
  const links = graph.chain_links || graph.links || [];
  const width = Math.max(container.clientWidth || 440, 240);
  const height = Math.max(container.clientHeight || 250, 180);
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`,
    role: "img", "aria-label": "Attack chain graph" });
  const positions = layout(nodes, links, width, height);

  for (const link of links) {
    const a = positions.get(endpoint(link.source));
    const b = positions.get(endpoint(link.target));
    if (!a || !b) continue;
    const active = selectedUid && link.alert_uid === selectedUid;
    const line = svgEl("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      class: `g2d-link${active ? " chain" : ""}` });
    const title = svgEl("title");
    title.textContent = `${link.relationship || "related"}${link.alert_uid ? ` · ${link.alert_uid}` : ""}`;
    line.append(title); svg.append(line);
  }

  for (const node of nodes) {
    const pos = positions.get(node.id);
    if (!pos) continue;
    const colour = node.kind === "event"
      ? severityColor(node.severity) : (KIND_COLORS[node.kind] || riskColor(node.risk_score || 0));
    const active = node.alert_uid && node.alert_uid === selectedUid;
    const group = svgEl("g", { class: "g2d-node", tabindex: "0", role: "button",
      "aria-label": `${node.kind || "entity"}: ${node.label || node.id}` });
    const circle = svgEl("circle", { cx: pos.x, cy: pos.y,
      r: node.kind === "event" ? 9 : 6.5, fill: active ? colour : "#090909",
      stroke: colour, "stroke-width": active ? 3 : 2 });
    const title = svgEl("title");
    title.textContent = `${node.kind || "entity"}: ${node.label || node.id}` +
      `${node.time_dt ? `\n${node.time_dt}` : ""}`;
    circle.append(title); group.append(circle);
    const kind = svgEl("text", { x: pos.x, y: pos.y - 11, class: "g2d-kind" });
    kind.textContent = String(node.kind || "entity").replaceAll("_", " ");
    group.append(kind);
    const label = svgEl("text", { x: pos.x, y: pos.y + 19,
      class: `g2d-label${node.kind === "event" ? " primary" : ""}` });
    const text = node.label || node.id;
    label.textContent = text.length > 22 ? `${text.slice(0, 21)}…` : text;
    group.append(label);
    const select = () => {
      if (!onSelect) return;
      if (node.alert_uid) onSelect("alert", { alert_uid: node.alert_uid });
      else if (node.entity_id) onSelect("entity", { ...node, id: node.entity_id });
      else onSelect(node.kind || "artifact", node);
    };
    group.addEventListener("click", select);
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); }
    });
    svg.append(group);
  }
  container.append(svg);
}
