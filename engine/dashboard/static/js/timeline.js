/* 2D MITRE timeline (Phase 19): tactics as lanes in kill-chain order,
 * alerts placed by event time. Pure SVG — deterministic layout, no library.
 * "The narrative you act on" (Master Specification 6.1). */

import { el, severityColor } from "./format.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const MARGIN = { top: 18, right: 40, bottom: 34, left: 170 };
const LANE_HEIGHT = 56;
const DOT_RADIUS = 7;

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, value);
  }
  return node;
}

/** Render the timeline into `svg`; calls onSelect(event) on alert click. */
export function renderTimeline(svg, timeline, onSelect) {
  svg.replaceChildren();
  const events = timeline.events || [];
  const lanes = timeline.lanes || [];
  if (!events.length) {
    const note = svgEl("text", { x: 20, y: 40, class: "tl-lane-label" });
    note.textContent = "No alerts in this chain.";
    svg.append(note);
    return;
  }

  const width = svg.clientWidth || svg.parentElement.clientWidth || 900;
  const height = MARGIN.top + lanes.length * LANE_HEIGHT + MARGIN.bottom;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("height", height);

  const t0 = Math.min(...events.map((e) => e.time));
  const t1 = Math.max(...events.map((e) => e.time));
  const span = Math.max(t1 - t0, 1);
  const plotWidth = width - MARGIN.left - MARGIN.right;
  const x = (time) => MARGIN.left + ((time - t0) / span) * plotWidth;
  const laneY = (index) => MARGIN.top + index * LANE_HEIGHT + LANE_HEIGHT / 2;

  // Lanes: label + guide line, kill-chain order top to bottom.
  lanes.forEach((lane, index) => {
    const y = laneY(index);
    svg.append(svgEl("line", {
      x1: MARGIN.left - 8, x2: width - MARGIN.right, y1: y, y2: y,
      class: "tl-lane-line",
    }));
    const label = svgEl("text", {
      x: MARGIN.left - 14, y: y + 4, "text-anchor": "end",
      class: "tl-lane-label",
    });
    label.textContent = lane;
    svg.append(label);
  });

  // Time axis: first and last alert timestamps.
  const axis = svgEl("g", { class: "tl-axis" });
  for (const [time, anchor] of [[t0, "start"], [t1, "end"]]) {
    const tickX = x(time);
    axis.append(svgEl("line", {
      x1: tickX, x2: tickX,
      y1: MARGIN.top - 6, y2: height - MARGIN.bottom + 6,
    }));
    const label = svgEl("text", {
      x: tickX, y: height - MARGIN.bottom + 20, "text-anchor": anchor,
    });
    label.textContent = new Date(time).toISOString().replace(".000Z", "Z");
    axis.append(label);
  }
  svg.append(axis);

  // Progression path connecting alerts in event-time order.
  const ordered = [...events].sort((a, b) => a.time - b.time || (a.uid < b.uid ? -1 : 1));
  const path = ordered
    .map((event, i) => `${i ? "L" : "M"}${x(event.time)},${laneY(event.lane_index)}`)
    .join(" ");
  svg.append(svgEl("path", { d: path, class: "tl-link" }));

  // Alerts as dots, coloured by severity (theme-independent).
  ordered.forEach((event) => {
    const cx = x(event.time);
    const cy = laneY(event.lane_index);
    const dot = svgEl("circle", {
      cx, cy, r: DOT_RADIUS, class: "tl-dot",
      fill: severityColor(event.severity),
      tabindex: "0", role: "button",
    });
    dot.addEventListener("click", () => onSelect(event));
    dot.addEventListener("keydown", (keyEvent) => {
      if (keyEvent.key === "Enter" || keyEvent.key === " ") onSelect(event);
    });
    const title = svgEl("title");
    title.textContent =
      `${event.uid} · ${event.title} · ${event.severity}\n${event.time_dt}`;
    dot.append(title);
    svg.append(dot);

    const label = svgEl("text", {
      x: cx, y: cy - 14, "text-anchor": "middle", class: "tl-dot-label",
    });
    label.textContent =
      event.title.length > 34 ? `${event.title.slice(0, 33)}…` : event.title;
    svg.append(label);
  });
}

/** Inspector content for one selected timeline alert. */
export function describeEvent(event) {
  const techniques = (event.techniques || [])
    .map((t) => [t.uid, t.name].filter(Boolean).join(" "))
    .join(", ");
  return el("div", {},
    el("div", { class: "kv" }, el("b", {}, "Alert:"), ` ${event.uid}`),
    el("div", { class: "kv" }, el("b", {}, "Time:"), ` ${event.time_dt}`),
    el("div", { class: "kv" }, el("b", {}, "Severity:"), ` ${event.severity}`),
    el("div", { class: "kv" }, el("b", {}, "Tactic lane:"), ` ${event.lane}`),
    techniques
      ? el("div", { class: "kv" }, el("b", {}, "ATT&CK:"), ` ${techniques}`)
      : null,
    el("div", { class: "kv" }, el("b", {}, "Entities:"),
      ` ${(event.entities || []).join(", ") || "—"}`),
  );
}
