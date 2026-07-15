/* LogLookup AI  SOC IDE (Engineering Handoff v1.0).
 *
 * One highly reactive state machine over the whole console: selecting an
 * event updates the evidence tabs, the attack graph, the AI verdict pane,
 * and the entity context in the same frame. Keyboard-first, anchored by
 * the ⌘K palette and the `/` command bar. State changes are instant (0ms)
 * — the only animation in the app is the kinetic AI loading trace.
 *
 * The IDE renders what the engine serves; it never recomputes correlation
 * and never invents data. Every empty/error state says exactly why. */

import {
  getAiSettings, getCluster, getClusters, getGraph, getSetup, getStatus,
  getTechniques, getTimeline, isPreviewMode, putAiSettings, putSiemSettings,
  retriage, validateAi,
} from "./api.js";
import { el, fmtTime, renderMarkdown, riskColor, severityColor } from "./format.js";
import { renderGraph2D } from "./graph2d.js";
import { renderGraph } from "./graph3d.js";
import { renderTimeline } from "./timeline.js";

const REFRESH_MS = 15000;
const $ = (id) => document.getElementById(id);

const SEV_RANK = { Unknown: 0, Informational: 1, Low: 2, Medium: 3, High: 4,
  Critical: 5, Fatal: 6 };

/* ================= state ================= */

const state = {
  view: "explorer",          // explorer | incident
  clusterId: null,
  clusters: [],
  total: 0,
  status: null,
  managed: false,
  offline: false,
  offlineDetail: "",

  navMode: "active",         // active | all | triaged
  filters: { sev: "", verdict: "", hours: "24", search: "" },
  cursor: 0,                 // keyboard row cursor (explorer + incident)

  doc: null,
  timeline: null,
  graph: null,
  centerView: "table",       // table | lanes
  graphMode: "2d",
  evidenceTab: "evidence",
  techniques: new Map(),
  sort: { key: "time", direction: "asc" },
  nodeFilter: "",
  selectedUid: null,         // selected alert uid inside the incident
  selectedEntity: null,      // selected entity name
  triaging: false,
};

/* ================= boot & routing ================= */

function routeFromLocation() {
  const match = window.location.pathname.match(/^\/incident\/(.+)$/);
  if (match) {
    state.view = "incident";
    state.clusterId = decodeURIComponent(match[1]);
  } else {
    state.view = "explorer";
    state.clusterId = null;
  }
}

function navigate(path) {
  const query = isPreviewMode ? "?preview=1" : "";
  window.history.pushState({}, "", `${path}${query}`);
  routeFromLocation();
  state.cursor = 0;
  if (state.view === "incident") loadIncident();
  else { clearIncident(); render(); }
}

window.addEventListener("popstate", () => {
  routeFromLocation();
  if (state.view === "incident") loadIncident();
  else { clearIncident(); render(); }
});

function clearIncident() {
  state.doc = null;
  state.timeline = null;
  state.graph = null;
  state.selectedUid = null;
  state.selectedEntity = null;
  state.techniques = new Map();
  state.nodeFilter = "";
}

/* ================= data loading ================= */

async function refreshStatus() {
  try {
    state.status = await getStatus();
    state.offline = false;
  } catch (error) {
    state.offline = true;
    state.offlineDetail = error.message;
  }
  renderSystem();
  if (state.offline && state.view === "explorer") renderCenter();
}

async function refreshClusters() {
  try {
    const body = await getClusters(false);
    state.clusters = body.clusters;
    state.total = body.total;
    state.offline = false;
  } catch (error) {
    state.offline = true;
    state.offlineDetail = error.message;
  }
  renderNavCounts();
  if (state.view === "explorer") renderCenter();
}

async function loadIncident() {
  clearIncident();
  render();
  showCenterLoading(`OPENING ${state.clusterId}`);
  try {
    state.doc = await getCluster(state.clusterId);
  } catch (error) {
    state.doc = null;
    renderCenterState({
      title: "No results for this chain",
      body: `${error.message}. The engine that produced this chain may not ` +
        "be running, and the result was not found in the Elastic results index.",
      error: true,
    });
    renderRail();
    return;
  }
  const techniqueIds = [...new Set(chainAlerts().flatMap((alert) =>
    (alert.techniques || []).map((technique) => technique.uid).filter(Boolean)))];
  const [timeline, graph, techniques] = await Promise.allSettled([
    getTimeline(state.clusterId), getGraph(state.clusterId), getTechniques(techniqueIds),
  ]);
  state.timeline = timeline.status === "fulfilled" ? timeline.value : null;
  state.graph = graph.status === "fulfilled" ? graph.value : null;
  state.techniques = new Map(
    (techniques.status === "fulfilled" ? techniques.value.techniques : [])
      .map((technique) => [technique.uid, technique]));
  const alerts = chainAlerts();
  if (alerts.length) selectEvent(alerts[alerts.length - 1].uid, { silent: true });
  applyHash();
  render();
}

/** Deep-linkable view state: /incident/<id>#lanes,3d,tab=report */
function applyHash() {
  const hash = window.location.hash.slice(1);
  if (!hash) return;
  for (const part of hash.split(",")) {
    if (part === "lanes" || part === "events") {
      state.centerView = part === "lanes" ? "lanes" : "table";
      syncSeg("center-view", state.centerView === "lanes" ? "lanes" : "table");
    } else if (part === "2d" || part === "3d") {
      state.graphMode = part;
      syncSeg("graph-mode", part);
    } else if (part.startsWith("tab=")) {
      switchTab(part.slice(4));
    }
  }
}

/* ================= derived data ================= */

function chainAlerts() {
  return state.doc?.chain?.alerts || [];
}

function entityDomains() {
  const domains = new Map();
  for (const entity of state.doc?.chain?.entities || []) {
    domains.set(entity.name, entity.domain);
  }
  return domains;
}

function entityOf(alert, wantDomain, domains) {
  for (const name of alert.entities || []) {
    if ((domains.get(name) || "unknown") === wantDomain) return name;
  }
  return "";
}

function maxSeverity(alerts) {
  return alerts.reduce(
    (best, a) => (SEV_RANK[a.severity] > SEV_RANK[best] ? a.severity : best),
    "Unknown");
}

function filteredClusters() {
  const { sev, verdict, hours, search } = state.filters;
  const cutoff = hours ? Date.now() - Number(hours) * 3600_000 : null;
  const needle = search.trim().toLowerCase();
  return state.clusters.filter((c) => {
    if (state.navMode === "active" && !c.surfaced) return false;
    if (state.navMode === "triaged" && c.triage_status !== "triaged") return false;
    if (sev === "high" && SEV_RANK[c.max_severity] < SEV_RANK.High) return false;
    if (sev === "critical" && SEV_RANK[c.max_severity] < SEV_RANK.Critical) return false;
    if (verdict === "tp" && c.verdict !== "True Positive") return false;
    if (verdict === "esc" && c.verdict !== "Needs Escalation") return false;
    if (verdict === "pending" && c.verdict) return false;
    if (cutoff && c.last_time && Date.parse(c.last_time) < cutoff) return false;
    if (needle) {
      const hay = `${c.cluster_id} ${c.primary_entity} ` +
        `${c.incident_title || ""} ${c.search_text || ""} ` +
        `${(c.tactic_sequence || []).join(" ")} ` +
        `${(c.mitre_attack_techniques || []).join(" ")}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
}

function filteredEvents() {
  const needle = state.filters.search.trim().toLowerCase();
  const domains = entityDomains();
  const nodeNeedle = state.nodeFilter.toLowerCase();
  const events = chainAlerts().filter((a) => {
    const hay = `${a.uid} ${a.title} ${a.description || ""} ${a.rule || ""} ` +
      `${a.host || ""} ${a.user || ""} ${a.process || ""} ${a.command || ""} ` +
      `${a.source_ip || ""} ${a.destination_ip || ""} ${(a.entities || []).join(" ")} ` +
      `${(a.tactics || []).join(" ")} ${(a.techniques || []).map((t) => `${t.uid} ${t.name}`).join(" ")} ` +
      `${JSON.stringify(a.evidence || {})}`;
    if (needle && !hay.toLowerCase().includes(needle)) return false;
    return !nodeNeedle || hay.toLowerCase().includes(nodeNeedle);
  }).map((a) => ({
    ...a,
    host: a.host || entityOf(a, "host", domains),
    user: a.user || entityOf(a, "user", domains),
    parent: evidenceValue(a.evidence, ["process.parent.name", "parent.process.name"]),
  }));
  const direction = state.sort.direction === "desc" ? -1 : 1;
  const key = state.sort.key;
  return events.sort((a, b) => {
    const left = key === "technique" ? ((a.techniques || [])[0]?.uid || "")
      : key === "time" ? (a.time || 0) : (a[key] || "");
    const right = key === "technique" ? ((b.techniques || [])[0]?.uid || "")
      : key === "time" ? (b.time || 0) : (b[key] || "");
    return String(left).localeCompare(String(right), undefined, { numeric: true }) * direction;
  });
}

/* ================= render: shell ================= */

function render() {
  renderNav();
  renderHeader();
  renderCenter();
  renderRail();
  renderPivots();
}

function renderNav() {
  $("nav-active").classList.toggle("active", state.navMode === "active" && state.view === "explorer");
  $("nav-all").classList.toggle("active", state.navMode === "all" && state.view === "explorer");
  $("nav-triaged").classList.toggle("active", state.navMode === "triaged" && state.view === "explorer");
  renderNavCounts();
}

function renderNavCounts() {
  const surfaced = state.clusters.filter((c) => c.surfaced).length;
  const triaged = state.clusters.filter((c) => c.triage_status === "triaged").length;
  const active = $("count-active");
  active.textContent = String(surfaced);
  active.className = `count ${surfaced ? "hot" : "calm"}`;
  $("count-all").textContent = String(state.total);
  $("count-triaged").textContent = String(triaged);
}

function renderSystem() {
  const status = state.status;
  const setDot = (id, cls) => { $(id).className = `dot ${cls}`; };
  if (state.offline || !status) {
    setDot("sys-siem-dot", "bad"); setDot("sys-ai-dot", "bad"); setDot("sys-kb-dot", "bad");
    $("sys-siem").textContent = "engine offline";
    $("sys-ai").textContent = "—";
    $("sys-kb").textContent = "—";
    return;
  }
  const siem = status.siem || {};
  if (!siem.configured) {
    setDot("sys-siem-dot", "warn");
    $("sys-siem").textContent = "not connected";
  } else {
    setDot("sys-siem-dot",
      siem.reachable === true ? "ok" : siem.reachable === false ? "bad" : "warn");
    $("sys-siem").textContent = siem.reachable === false
      ? "unreachable" : (siem.host || "").replace(/^https?:\/\//, "");
  }
  $("sys-siem").title = siem.detail || siem.host || "";
  const ai = status.ai || {};
  const aiOk = ai.triage_available && ai.reachable !== false;
  setDot("sys-ai-dot", aiOk ? "ok" : "warn");
  $("sys-ai").textContent = ai.triage_available
    ? (ai.model_id || ai.provider) : "unavailable";
  $("sys-ai").title = ai.disabled_reason || ai.detail || "";
  const kb = status.kb || {};
  setDot("sys-kb-dot", kb.loaded ? "ok" : "bad");
  $("sys-kb").textContent = kb.loaded
    ? `v${kb.attack_version} · ${kb.techniques}` : "KB missing";
}

/* ================= render: center ================= */

function renderHeader() {
  const chips = $("hdr-chips");
  chips.replaceChildren();
  if (state.view === "explorer") {
    $("hdr-title").textContent = "Incidents";
    $("hdr-chain-id").hidden = true;
    $("center-view").hidden = true;
    const rows = filteredClusters().length;
    chips.append(el("span", { class: "chip" }, `${rows} of ${state.total} chains`));
    return;
  }
  $("hdr-title").textContent = incidentName(state.doc?.chain || {});
  $("hdr-chain-id").textContent = state.clusterId || "";
  $("hdr-chain-id").hidden = false;
  $("center-view").hidden = false;
  const doc = state.doc;
  if (!doc) return;
  const chain = doc.chain || {};
  const alerts = chain.alerts || [];
  const domains = entityDomains();
  const hosts = new Set(); const users = new Set();
  for (const [name, domain] of domains) {
    if (domain === "host") hosts.add(name);
    if (domain === "user") users.add(name);
  }
  const sev = maxSeverity(alerts);
  const duration = durationLabel(chain.first_time, chain.last_time);
  chips.append(
    el("span", { class: `chip sev-${sev.toLowerCase()}` }, sev.toUpperCase()),
    el("span", { class: "chip risk" }, `Risk ${Math.round(chain.risk_score || 0)}`),
  );
  if (doc.triage?.verdict) {
    const cls = doc.triage.verdict === "True Positive" ? "verdict-tp"
      : doc.triage.verdict === "Needs Escalation" ? "verdict-esc" : "verdict-fp";
    chips.append(el("span", { class: `chip ${cls}` },
      `${doc.triage.verdict} · ${doc.triage.confidence_score}%`));
  }
  chips.append(
    el("span", { class: "chip" }, `${alerts.length} Events`),
    el("span", { class: "chip" }, `${hosts.size} Hosts`),
    el("span", { class: "chip" }, `${users.size} Users`),
    el("span", { class: "chip live" },
      `Start: ${shortTime(chain.first_time)} | Dur: ${duration} | `,
      el("span", { class: chain.surfaced ? "on" : "" },
        chain.surfaced ? "● Active" : "○ Below threshold")),
  );
}

function incidentName(chain) {
  const alerts = chain.alerts || [];
  const techniques = new Set(alerts.flatMap((alert) =>
    (alert.techniques || []).map((technique) => String(technique.name || "").toLowerCase())));
  const tactics = new Set(alerts.flatMap((alert) =>
    (alert.tactics || []).map((tactic) => String(tactic).toLowerCase())));
  if (techniques.has("powershell") && tactics.has("credential access")) {
    return "PowerShell Credential Theft";
  }
  const ranked = [...alerts].sort((a, b) =>
    (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || (b.time || 0) - (a.time || 0));
  return ranked[0]?.title || "Security Investigation";
}

function shortTime(iso) {
  if (!iso) return "—";
  const m = String(iso).match(/T(\d{2}:\d{2})/);
  return m ? m[1] : String(iso);
}

function durationLabel(first, last) {
  if (!first || !last) return "—";
  const ms = Date.parse(last) - Date.parse(first);
  if (ms < 60_000) return `${Math.max(1, Math.round(ms / 1000))}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

function renderCenterState({ title, body, detail, error, loading, label }) {
  const stateBox = $("center-state");
  $("main-grid").hidden = true;
  $("lane-wrap").hidden = true;
  stateBox.hidden = false;
  stateBox.replaceChildren();
  if (loading) {
    stateBox.append(traceLoader(label || "LOADING"));
    return;
  }
  stateBox.append(el("h2", {}, title));
  if (body) stateBox.append(el("p", {}, body));
  if (detail) stateBox.append(el("div", { class: "mono-detail" }, detail));
  if (error) stateBox.querySelector("h2").style.color = "var(--sev-critical)";
}

function showCenterLoading(label) {
  renderCenterState({ loading: true, label });
}

function renderCenter() {
  const zone = $("zone-center");
  zone.classList.toggle("no-evidence", state.view !== "incident");
  if (state.view === "explorer") renderExplorer();
  else renderIncident();
}

function renderExplorer() {
  const grid = $("main-grid");
  const stateBox = $("center-state");
  $("lane-wrap").hidden = true;

  if (state.offline) {
    renderCenterState({
      title: "Engine offline",
      body: "The LogLookup engine is not answering. Start it with " +
        "`loglookup serve` (or `python -m engine.server`), then retry.",
      detail: state.offlineDetail,
      error: true,
    });
    return;
  }
  const rows = filteredClusters();
  if (!rows.length) {
    const siem = state.status?.siem || {};
    if (!state.clusters.length && !siem.configured) {
      renderCenterState({
        title: "No SIEM connected",
        body: "Connect Elasticsearch in Settings or run the setup wizard. " +
          "Alerts will appear after the next polling cycle.",
      });
    } else if (!state.clusters.length) {
      renderCenterState({
        title: "No attack chains yet",
        body: siem.reachable === false
          ? "The configured SIEM is unreachable. Check the connection in Settings."
          : "Polling is live. Chains appear as soon as correlated alerts cross the risk threshold.",
      });
    } else {
      renderCenterState({
        title: "Nothing matches these filters",
        body: "Loosen the severity/verdict/time filters in the left rail, or clear the search.",
      });
    }
    return;
  }

  stateBox.hidden = true;
  grid.hidden = false;
  renderHeaders([
    ["incident", "INCIDENT"], ["verdict", "VERDICT"], ["severity", "SEV"],
    ["risk", "RISK"], ["events", "EVENTS"], ["entity", "HOST / ENTITY"],
    ["tactics", "TACTIC PROGRESSION"], ["last", "LAST ACTIVITY"],
  ], false);

  state.cursor = Math.min(state.cursor, rows.length - 1);
  $("grid-body").replaceChildren(...rows.map((c, index) => {
    const row = el("tr", {
      class: index === state.cursor ? "selected" : "",
      onclick: () => navigate(`/incident/${encodeURIComponent(c.cluster_id)}`),
    },
      el("td", {},
        el("div", { style: "color:var(--text);font-family:var(--font-ui);font-weight:600" },
          highlightMatches(c.incident_title || "Security Investigation")),
        el("div", { class: "t-time", style: "font-size:9px;margin-top:3px" }, c.cluster_id)),
      el("td", {}, verdictCell(c)),
      el("td", {}, sevDot(c.max_severity, c.surfaced)),
      el("td", {}, riskCell(c)),
      el("td", {}, String(c.alert_count)),
      el("td", {}, highlightMatches(c.primary_entity || "—")),
      el("td", { class: "t-desc" }, highlightMatches((c.tactic_sequence || []).join(" → ") || "—")),
      el("td", { class: "t-time" }, fmtTime(c.last_time)),
    );
    return row;
  }));
}

function renderHeaders(columns, sortable = true) {
  let widths = {};
  try { widths = JSON.parse(localStorage.getItem("loglookup.columnWidths") || "{}"); }
  catch { localStorage.removeItem("loglookup.columnWidths"); }
  $("grid-head").replaceChildren(...columns.map(([key, label]) => {
    const th = el("th", {
      class: sortable ? `sortable${state.sort.key === key ? ` sort-${state.sort.direction}` : ""}` : "",
      scope: "col", "aria-sort": state.sort.key === key
        ? (state.sort.direction === "asc" ? "ascending" : "descending") : "none",
    }, label);
    if (widths[key]) th.style.width = `${widths[key]}px`;
    if (sortable) th.addEventListener("click", () => {
      if (state.sort.key === key) state.sort.direction = state.sort.direction === "asc" ? "desc" : "asc";
      else { state.sort.key = key; state.sort.direction = "asc"; }
      renderIncident();
    });
    const handle = el("span", { class: "column-resizer", role: "separator",
      "aria-label": `Resize ${label} column` });
    handle.addEventListener("pointerdown", (event) => {
      event.preventDefault(); event.stopPropagation();
      const startX = event.clientX; const startWidth = th.getBoundingClientRect().width;
      handle.setPointerCapture(event.pointerId);
      const move = (moveEvent) => { th.style.width = `${Math.max(60, startWidth + moveEvent.clientX - startX)}px`; };
      const up = () => {
        handle.removeEventListener("pointermove", move);
        handle.removeEventListener("pointerup", up);
        handle.removeEventListener("pointercancel", up);
        widths[key] = Math.round(th.getBoundingClientRect().width);
        localStorage.setItem("loglookup.columnWidths", JSON.stringify(widths));
      };
      handle.addEventListener("pointermove", move);
      handle.addEventListener("pointerup", up);
      handle.addEventListener("pointercancel", up);
    });
    return th;
  }));
}

function verdictCell(c) {
  if (c.verdict) {
    const cls = c.verdict === "True Positive" ? "verdict-tp"
      : c.verdict === "Needs Escalation" ? "verdict-esc" : "verdict-fp";
    return el("span", { class: `chip ${cls}` }, `${c.verdict} · ${c.confidence_score}%`);
  }
  if (c.triage_status === "ai_unavailable") {
    return el("span", { class: "chip" }, "AI unavailable");
  }
  return el("span", { class: "chip", style: "color:var(--faint)" }, "pending");
}

function sevDot(severity, glow) {
  return el("span", {
    class: `sev-dot${glow && SEV_RANK[severity] >= SEV_RANK.High ? " glow" : ""}`,
    style: `background:${severityColor(severity)};color:${severityColor(severity)}`,
    title: severity,
  });
}

function riskCell(c) {
  return el("span", {
    class: "mono",
    style: c.surfaced ? `color:${riskColor(c.risk_score)};font-weight:600` : "",
  }, String(Math.round(c.risk_score || 0)));
}

function renderIncident() {
  if (!state.doc) return;
  if (state.centerView === "lanes") { renderLanes(); return; }
  $("lane-wrap").hidden = true;
  const events = filteredEvents();
  if (!events.length) {
    renderCenterState({
      title: "No events match",
      body: "This chain has no alerts matching the search.",
    });
    renderEvidence();
    return;
  }
  $("center-state").hidden = true;
  const grid = $("main-grid");
  grid.hidden = false;
  renderHeaders([
    ["time", "TIME"], ["severity", "SEVERITY"], ["technique", "TECHNIQUE"],
    ["rule", "RULE"], ["process", "PROCESS"], ["parent", "PARENT"],
    ["user", "USER"], ["host", "HOST"], ["description", "DESCRIPTION"],
  ]);
  $("grid-body").replaceChildren(...events.map((a) => {
    const selected = a.uid === state.selectedUid;
    const technique = (a.techniques || [])[0];
    const mitre = technique?.uid || "";
    return el("tr", {
      class: selected ? "selected" : "",
      "data-uid": a.uid,
      onclick: () => selectEvent(a.uid),
    },
      el("td", { class: "t-time" }, timeOfDay(a.time_dt)),
      el("td", {}, sevDot(a.severity, selected), ` ${a.severity}`),
      el("td", {}, mitre ? techniqueBadge(technique, selected ? a.severity : "") : "—"),
      el("td", {}, highlightMatches(a.rule || a.title || "—")),
      el("td", {}, highlightMatches(a.process || "—")),
      el("td", {}, highlightMatches(a.parent || "—")),
      el("td", {}, highlightMatches(a.user || "—")),
      el("td", {}, highlightMatches(a.host || "—")),
      el("td", { class: "t-desc", title: a.description || a.title },
        highlightMatches(a.description || a.title || "—")),
    );
  }));
  renderEvidence();
}

function techniqueBadge(technique, selectedSeverity = "") {
  const uid = technique?.uid || "";
  const official = state.techniques.get(uid) || {};
  const name = official.name || technique?.name || "Unknown technique";
  const url = official.url || `https://attack.mitre.org/techniques/${uid.replace(".", "/")}/`;
  const badge = el("a", {
    class: "chip tech", href: url, target: "_blank", rel: "noopener noreferrer",
    title: `${official.description || "Official ATT&CK description unavailable in the local KB."}\n${url}`,
    "aria-label": `${uid} ${name}. Open official MITRE ATT&CK page`,
    style: selectedSeverity && SEV_RANK[selectedSeverity] >= SEV_RANK.High
      ? "color:var(--sev-critical);border-color:rgba(255,23,68,.3);background:rgba(255,23,68,.15)" : "",
    onclick: (event) => event.stopPropagation(),
  }, el("span", { class: "mono" }, uid), el("span", {}, name));
  return badge;
}

function highlightMatches(value) {
  const text = String(value ?? "");
  const needle = state.filters.search.trim();
  const fragment = document.createDocumentFragment();
  if (!needle) { fragment.append(text); return fragment; }
  let cursor = 0; const lower = text.toLowerCase(); const match = needle.toLowerCase();
  while (cursor < text.length) {
    const index = lower.indexOf(match, cursor);
    if (index < 0) { fragment.append(text.slice(cursor)); break; }
    if (index > cursor) fragment.append(text.slice(cursor, index));
    fragment.append(el("mark", { class: "search-hit" }, text.slice(index, index + needle.length)));
    cursor = index + needle.length;
  }
  return fragment;
}

function flattenEvidence(value, prefix = "", out = {}) {
  if (Array.isArray(value)) value.forEach((child, index) => flattenEvidence(child, `${prefix}.${index}`, out));
  else if (value && typeof value === "object") Object.entries(value).forEach(([key, child]) =>
    flattenEvidence(child, prefix ? `${prefix}.${key}` : key, out));
  else if (value !== null && value !== undefined && value !== "") out[prefix.toLowerCase()] = String(value);
  return out;
}

function evidenceValue(evidence, paths) {
  const flat = flattenEvidence(evidence || {});
  for (const path of paths) {
    const needle = path.toLowerCase();
    const found = Object.entries(flat).find(([key]) => key === needle || key.endsWith(`.${needle}`));
    if (found) return found[1];
  }
  return "";
}

function timeOfDay(iso) {
  const m = String(iso || "").match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : fmtTime(iso);
}

function renderLanes() {
  $("main-grid").hidden = true;
  $("center-state").hidden = true;
  const wrap = $("lane-wrap");
  wrap.hidden = false;
  if (!state.timeline) {
    wrap.replaceChildren(el("div", { class: "notice" },
      "Timeline view unavailable for this chain."));
    return;
  }
  const svg = $("timeline-svg") || el("svg", { id: "timeline-svg" });
  if (!svg.isConnected) wrap.append(svg);
  renderTimeline(svg, state.timeline, (event) => selectEvent(event.uid));
  renderEvidence();
}

/* ================= evidence tabs ================= */

function renderEvidence() {
  if (state.view !== "incident" || !state.doc) return;
  for (const button of $("evidence-tabs").querySelectorAll("button[data-tab]")) {
    button.classList.toggle("active", button.dataset.tab === state.evidenceTab);
  }
  const meta = $("evidence-meta");
  const body = $("evidence-body");
  const doc = state.doc;
  const alert = chainAlerts().find((a) => a.uid === state.selectedUid);
  meta.textContent = alert ? `event ${alert.uid}` : doc.cluster_id;

  if (state.evidenceTab === "evidence") {
    body.replaceChildren(renderEvidenceCards(alert));
  } else if (state.evidenceTab === "raw") {
    body.replaceChildren(jsonBlock(alert || doc.chain));
  } else if (state.evidenceTab === "correlation") {
    const chain = doc.chain || {};
    body.replaceChildren(jsonBlock({
      cluster_id: doc.cluster_id,
      window: { first: chain.first_time, last: chain.last_time },
      tactic_sequence: chain.tactic_sequence,
      disposition: chain.disposition,
      risk_score: chain.risk_score,
      surfaced: chain.surfaced,
      primary_entity: chain.primary_entity,
      entities: chain.entities,
    }));
  } else if (state.evidenceTab === "verdict") {
    if (doc.triage) body.replaceChildren(jsonBlock(doc.triage));
    else {
      body.replaceChildren(el("div", { class: "notice" },
        doc.triage_status === "ai_unavailable"
          ? `AI triage unavailable: ${doc.triage_error || "see engine logs"}`
          : "AI triage has not run for this chain. Enter /triage to run it."));
    }
  } else if (state.evidenceTab === "report") {
    const report = el("article", { class: "report" });
    report.innerHTML = renderMarkdown(
      doc.report_markdown || "_No report was generated for this chain._");
    body.replaceChildren(report);
  }
}

function renderEvidenceCards(alert) {
  if (!alert) return el("div", { class: "notice" }, "Select an event to inspect its evidence values.");
  const evidence = alert.evidence || {};
  const fields = [
    ["Host", alert.host || evidenceValue(evidence, ["host.name", "host.hostname"])],
    ["User", alert.user || evidenceValue(evidence, ["user.name", "actor.user.name"])],
    ["Rule", alert.rule || alert.title],
    ["Process", alert.process || evidenceValue(evidence, ["process.name", "process.executable"])],
    ["Command", alert.command || evidenceValue(evidence, ["process.command_line", "command_line", "cmd_line"])],
    ["Parent", evidenceValue(evidence, ["process.parent.name", "parent.process.name"])],
    ["Hash", evidenceValue(evidence, ["file.hash.sha256", "hash.sha256", "process.hash.sha256", "file.hash.md5"])],
    ["Registry", evidenceValue(evidence, ["registry.path", "registry.key", "registry.value"])],
    ["Network", [
      alert.source_ip || evidenceValue(evidence, ["source.ip"]),
      alert.destination_ip || evidenceValue(evidence, ["destination.ip", "destination.domain"]),
    ].filter(Boolean).join(" → ")],
    ["Description", alert.description || evidenceValue(evidence, ["message", "event.original"])],
  ].filter(([, value]) => value);
  const cards = el("div", { class: "evidence-cards" });
  for (const [label, value] of fields) {
    const card = el("div", { class: "evidence-card" },
      el("div", { class: "label" }, label),
      el("div", { class: "value" },
        el("code", {}, highlightMatches(value)),
        el("button", { class: "copy-btn", type: "button", title: `Copy ${label}`,
          "aria-label": `Copy ${label}` }, "Copy")));
    const button = card.querySelector("button");
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(String(value));
        button.textContent = "Copied";
      } catch {
        button.textContent = "Blocked";
      }
      setTimeout(() => { button.textContent = "Copy"; }, 1200);
    });
    card.querySelector("code").addEventListener("click", () => card.classList.toggle("expanded"));
    cards.append(card);
  }
  if (!fields.length) cards.append(el("div", { class: "notice" }, "No human-readable values were normalized for this event. Raw JSON remains available."));
  return cards;
}

function jsonBlock(value) {
  const pre = el("pre", { class: "json" });
  pre.innerHTML = highlightJson(JSON.stringify(value ?? {}, null, 2));
  return pre;
}

function highlightJson(text) {
  return text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(
      /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g,
      (match, str, colon, bool) => {
        if (str) {
          return colon
            ? `<span class="k">${str}</span>${colon}`
            : `<span class="s">${str}</span>`;
        }
        if (bool) return `<span class="b">${match}</span>`;
        if (match === "null") return `<span class="p">null</span>`;
        return `<span class="n">${match}</span>`;
      });
}

/* ================= right rail ================= */

function renderRail() {
  renderGraphPane();
  renderVerdictPane();
  renderEntityPane();
}

function renderGraphPane() {
  const stateBox = $("graph-state");
  const g2d = $("graph2d");
  const g3d = $("graph3d");
  for (const button of $("graph-mode").querySelectorAll("button")) {
    button.classList.toggle("on", button.dataset.v === state.graphMode);
  }
  if (state.view !== "incident" || !state.graph ||
      !((state.graph.chain_nodes || state.graph.nodes || []).length)) {
    stateBox.hidden = false;
    g2d.hidden = true; g3d.hidden = true;
    stateBox.replaceChildren(el("p", {},
      state.view === "incident"
        ? "No entity graph for this chain."
        : "Select an incident to render its attack graph."));
    return;
  }
  stateBox.hidden = true;
  if (state.graphMode === "2d") {
    g3d.hidden = true;
    g2d.hidden = false;
    renderGraph2D(g2d, state.graph, {
      selectedUid: state.selectedUid,
      onSelect: onGraphSelect,
    });
  } else {
    g2d.hidden = true;
    g3d.hidden = false;
    try {
      // Lazy WebGL: created on first open, then only data updates.
      renderGraph(g3d, state.graph, onGraphSelect);
    } catch (_error) {
      // No WebGL (VM / remote session): fall back to 2D, honestly.
      state.graphMode = "2d";
      syncSeg("graph-mode", "2d");
      g3d.hidden = true;
      g2d.hidden = false;
      renderGraph2D(g2d, state.graph, {
        selectedUid: state.selectedUid, onSelect: onGraphSelect,
      });
    }
  }
}

function onGraphSelect(kind, payload) {
  if (kind === "entity") {
    state.selectedEntity = payload.id;
    state.nodeFilter = payload.id;
    renderIncident();
    renderEntityPane();
  } else if (kind === "alert" && payload.alert_uid) {
    selectEvent(payload.alert_uid);
  } else if (payload?.technique_uid || payload?.value || payload?.label) {
    state.nodeFilter = payload.technique_uid || payload.value || payload.label;
    state.filters.search = state.nodeFilter;
    $("global-search").value = state.nodeFilter;
    renderIncident();
  }
}

function renderVerdictPane() {
  const body = $("verdict-body");
  if (state.view !== "incident" || !state.doc) {
    body.replaceChildren(el("div", { class: "state" },
      el("p", {}, "No incident selected.")));
    return;
  }
  if (state.triaging) {
    body.replaceChildren(el("div", { class: "state" },
      traceLoader("TRIAGING"),
      el("p", {}, "Reviewing the correlated alerts and checking the cited evidence.")));
    return;
  }
  const doc = state.doc;
  const triage = doc.triage;
  if (!triage) {
    const reason = doc.triage_status === "ai_unavailable"
      ? `AI was unavailable: ${doc.triage_error || "see engine logs"}`
      : "This chain has not been triaged. Its risk score may be below the " +
        "threshold when triage scope is set to “surfaced chains only”.";
    body.replaceChildren(
      el("div", { class: "notice" + (doc.triage_status === "ai_unavailable" ? " error" : "") }, reason),
      el("div", { style: "margin-top:10px" },
        el("button", { class: "primary", onclick: runTriage }, "Run AI triage (r)")),
    );
    return;
  }
  const validation = triage.validation || {};
  const confidence = triage.confidence_score;
  const confidenceLabel = confidence >= 80 ? "High" : confidence >= 50 ? "Medium" : "Low";
  const reasoning = splitReasoning(triage.investigation_chain_of_thought);
  const grid = el("div", { class: "v-grid" },
    el("span", { class: "k" }, "VERDICT"),
    el("span", { class: "val", style: `color:${verdictColor(triage.verdict)};font-weight:600` },
      triage.verdict),
    el("span", { class: "k" }, "CONFIDENCE"),
    el("span", { class: "val mono", style: confidence >= 50 ? "color:var(--signal)" : "color:var(--sev-high)" },
      `${confidence}% (${confidenceLabel})`),
    el("span", { class: "k" }, "GROUNDED"),
    el("span", { class: "val", style: validation.grounded === false
      ? "color:var(--sev-high)" : "color:var(--signal)" },
      validation.grounded === false ? "△ Evidence adjusted" : "✓ Evidence verified"),
    el("span", { class: "k" }, "SEVERITY"),
    el("span", { class: "val mono", style: `color:${severityColor(maxSeverity(chainAlerts()))}` },
      maxSeverity(chainAlerts())),
    el("span", { class: "k" }, "MITRE"),
    el("span", { class: "val" },
      ...(triage.mitre_attack_techniques || []).map((uid) =>
        techniqueBadge({ uid, name: state.techniques.get(uid)?.name })),
      (triage.mitre_attack_techniques || []).length ? "" : "—"),
    el("span", { class: "k" }, "EVIDENCE"),
    el("span", { class: "val mono", style: "font-size:10.5px;color:var(--muted)" },
      (triage.critical_evidence_fields || []).join(", ") || "—"),
  );
  const children = [grid];

  if (reasoning.length) {
    children.push(el("div", { class: "v-grid", style: "margin-top:12px" },
      el("span", { class: "k" }, "REASONING"),
      el("span", { class: "val" },
        ...reasoning.map((line) => el("div", { class: "v-reason" }, line)))));
  }
  const recs = triage.remediation_recommendations || [];
  if (recs.length) {
    children.push(el("div", { class: "v-grid", style: "margin-top:12px" },
      el("span", { class: "k" }, "RECOMMENDED"),
      el("span", { class: "val" },
        ...recs.map((rec) => el("div", { class: "v-rec" }, rec)))));
  }
  if (validation.original_confidence != null && validation.original_confidence !== confidence) {
    children.push(el("div", { class: "v-note", style: "color:var(--sev-high)" },
      "Grounding validation reduced confidence because unsupported evidence was removed."));
  }
  if ((validation.notes || []).length) {
    children.push(el("div", { class: "v-note" },
      `Grounding validator: ${validation.notes.join("; ")}`));
  }
  children.push(el("div", { class: "v-note" },
    `Generated by ${triage.model_id} at ${fmtTime(triage.generated_at)}. ` +
    `Review before acting. LogLookup does not execute response actions.`));
  children.push(el("div", { style: "margin-top:10px" },
    el("button", { onclick: runTriage }, "Re-triage (r)")));
  body.replaceChildren(...children);
}

function verdictColor(verdict) {
  return verdict === "True Positive" ? "var(--verdict-tp)"
    : verdict === "Needs Escalation" ? "var(--verdict-esc)" : "var(--verdict-fp)";
}

function splitReasoning(text) {
  if (!text) return [];
  return String(text)
    .split(/\n+|(?<=\.)\s+(?=\d+\))/)
    .map((s) => s.replace(/^\d+\)\s*/, "").trim())
    .filter(Boolean)
    .slice(0, 6);
}

function renderEntityPane() {
  const body = $("entity-body");
  if (state.view !== "incident" || !state.doc) {
    body.replaceChildren(el("div", { class: "state" },
      el("p", {}, "Select an event or a graph node.")));
    return;
  }
  const entities = state.doc.chain?.entities || [];
  let entity = entities.find((e) => e.name === state.selectedEntity);
  if (!entity) {
    const alert = chainAlerts().find((a) => a.uid === state.selectedUid);
    const domains = entityDomains();
    const preferred = alert ? entityOf(alert, "host", domains) || (alert.entities || [])[0] : null;
    entity = entities.find((e) => e.name === preferred)
      || entities.find((e) => e.name === state.doc.chain.primary_entity)
      || entities[0];
  }
  if (!entity) {
    body.replaceChildren(el("div", { class: "state" },
      el("p", {}, "No resolved entities on this chain.")));
    return;
  }
  const touching = chainAlerts().filter((a) => (a.entities || []).includes(entity.name));
  const first = touching.length ? touching[0].time_dt : null;
  const last = touching.length ? touching[touching.length - 1].time_dt : null;
  const colour = riskColor(entity.risk_score || 0);
  const identifiers = Object.entries(entity.identifiers || {});
  const selected = touching.find((a) => a.uid === state.selectedUid) || touching[0] || {};
  const evidence = selected.evidence || {};
  const hostname = entity.domain === "host" ? entity.name
    : evidenceValue(evidence, ["host.name", "host.hostname"]);
  const user = entity.domain === "user" ? entity.name
    : selected.user || evidenceValue(evidence, ["user.name"]);
  const ip = entity.domain === "ip" ? entity.name
    : evidenceValue(evidence, ["host.ip.0", "host.ip", "source.ip", "destination.ip"]);
  const os = evidenceValue(evidence, ["host.os.full", "host.os.name", "device.os.name"]);
  const agent = evidenceValue(evidence, ["agent.name", "agent.type", "agent.id"]);
  const related = state.clusters.filter((cluster) =>
    `${cluster.primary_entity} ${cluster.search_text || ""}`.toLowerCase().includes(entity.name.toLowerCase()));
  body.replaceChildren(
    el("div", { class: "entity-title" },
      el("span", { class: "sev-dot glow", style: `background:${colour};color:${colour}` }),
      entity.name,
      el("span", { class: "risk-badge", style: `background:${colour}` },
        `RISK ${Math.round(entity.risk_score || 0)}`)),
    el("div", { class: "entity-kv" },
      el("span", {}, "Hostname: ", el("b", {}, hostname || "—")),
      el("span", {}, "User: ", el("b", {}, user || "—")),
      el("span", {}, "IP: ", el("b", {}, ip || "—")),
      el("span", {}, "OS: ", el("b", {}, os || "—")),
      el("span", {}, "Agent: ", el("b", {}, agent || "—")),
      el("span", {}, "Risk score: ", el("b", {}, String(Math.round(entity.risk_score || 0)))),
      el("span", {}, "Alert count: ", el("b", {}, String(touching.length))),
      el("span", {}, "Related incidents: ", el("b", {}, String(related.length))),
      ...identifiers.map(([kind, values]) =>
        el("span", {}, `${kind}: `, el("b", {}, values.join(", ")))),
      el("span", {}, "First seen: ", el("b", {}, fmtTime(first))),
      el("span", {}, "Last seen: ", el("b", {}, fmtTime(last)))),
    el("div", { class: "row", style: "margin-top:10px;flex-wrap:wrap" },
      hostname ? el("button", { onclick: () => pivotTo(hostname) }, "Pivot hostname") : null,
      user ? el("button", { onclick: () => pivotTo(user) }, "Pivot user") : null,
      ip ? el("button", { onclick: () => pivotTo(ip) }, "Pivot IP") : null),
    el("div", { class: "entity-alerts" },
      el("div", { class: "lbl" }, "ALERTS TOUCHING THIS ENTITY"),
      ...touching.map((a) => el("div", {
        class: "entity-alert-row",
        style: a.uid === state.selectedUid ? "border-color:var(--signal-edge);color:var(--text)" : "",
        onclick: () => selectEvent(a.uid),
      }, `${timeOfDay(a.time_dt)}  ${a.uid}  ${a.title}`))),
  );
}

/* ================= selection (absolute synchronization) ================= */

function selectEvent(uid, { silent } = {}) {
  state.selectedUid = uid;
  const alert = chainAlerts().find((a) => a.uid === uid);
  if (alert) {
    const domains = entityDomains();
    state.selectedEntity = entityOf(alert, "host", domains)
      || (alert.entities || [])[0] || state.selectedEntity;
  }
  if (silent) return;
  // One click — every zone updates, same frame, no animation.
  renderIncident();
  renderGraphPane();
  renderEntityPane();
  renderPivots();
}

function selectedAlert() {
  return chainAlerts().find((a) => a.uid === state.selectedUid) || null;
}

function renderPivots() {
  const alert = selectedAlert();
  const domains = entityDomains();
  const host = alert ? entityOf(alert, "host", domains) : "";
  const user = alert ? entityOf(alert, "user", domains) : "";
  const ip = alert ? entityOf(alert, "ip", domains) : "";
  configPivot("pivot-host", host);
  configPivot("pivot-user", user);
  configPivot("pivot-ip", ip);
  $("btn-export").disabled = !state.doc;
}

function configPivot(id, value) {
  const button = $(id);
  button.disabled = !value;
  button.title = value ? `Find every chain touching ${value}` : "";
  button.onclick = value ? () => pivotTo(value) : null;
}

function pivotTo(value) {
  state.filters.search = value;
  state.navMode = "all";
  $("global-search").value = value;
  syncSeg("filter-time", "");
  state.filters.hours = "";
  navigate("/");
}

/* ================= actions ================= */

async function runTriage() {
  if (!state.clusterId || state.triaging) return;
  state.triaging = true;
  renderVerdictPane();
  try {
    state.doc = await retriage(state.clusterId);
  } catch (error) {
    state.triaging = false;
    renderVerdictPane();
    $("verdict-body").prepend(el("div", { class: "notice error" },
      `Re-triage failed: ${error.message}`));
    return;
  }
  state.triaging = false;
  render();
}

function downloadText(text, type, extension) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = el("a", { href: url, download: `${state.doc.cluster_id}.${extension}` });
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function buildSocReport() {
  const doc = state.doc;
  const chain = doc.chain || {}; const triage = doc.triage || {};
  const timeline = (chain.alerts || []).map((alert) =>
    `| ${alert.time_dt || "—"} | ${alert.severity || "—"} | ${alert.title || "—"} | ${(alert.techniques || []).map((t) => `${t.uid} ${t.name || ""}`).join(", ") || "—"} |`).join("\n");
  const evidence = (chain.alerts || []).map((alert) =>
    `### ${alert.uid} — ${alert.title}\n\n${Object.entries(flattenEvidence(alert.evidence || {})).slice(0, 30).map(([key, value]) => `- **${key}:** \`${value}\``).join("\n")}`).join("\n\n");
  return `# ${incidentName(chain)}\n\n**Chain ID:** ${doc.cluster_id}\n\n` +
    `**Severity:** ${maxSeverity(chain.alerts || [])}  \n**Risk:** ${Math.round(chain.risk_score || 0)}  \n` +
    `**Verdict:** ${triage.verdict || "Pending"}  \n**Confidence:** ${triage.confidence_score ?? "—"}%\n\n` +
    `## Timeline\n\n| Time | Severity | Event | MITRE ATT&CK |\n|---|---|---|---|\n${timeline}\n\n` +
    `## Reasoning\n\n${triage.investigation_chain_of_thought || "No AI reasoning available."}\n\n` +
    `## Evidence\n\n${evidence}\n\n## Recommendations\n\n` +
    `${(triage.remediation_recommendations || []).map((item) => `- ${item}`).join("\n") || "- Analyst review required."}\n`;
}

function exportReport(format = "markdown") {
  const doc = state.doc;
  if (!doc) return;
  const soc = buildSocReport();
  if (format === "json") {
    downloadText(JSON.stringify({ ...doc, timeline: state.timeline, graph: state.graph }, null, 2),
      "application/json", "json");
  } else if (format === "executive") {
    const triage = doc.triage || {};
    const text = `# Executive Incident Report\n\n## ${incidentName(doc.chain || {})}\n\n` +
      `**Severity:** ${maxSeverity(doc.chain?.alerts || [])}  \n**Verdict:** ${triage.verdict || "Pending analyst review"}  \n` +
      `**Confidence:** ${triage.confidence_score ?? "—"}%\n\n## Business summary\n\n` +
      `${triage.malicious_hypothesis || triage.investigation_chain_of_thought || "A correlated security incident requires review."}\n\n` +
      `## Recommended actions\n\n${(triage.remediation_recommendations || []).map((item) => `- ${item}`).join("\n") || "- Complete analyst review."}\n`;
    downloadText(text, "text/markdown", "executive.md");
  } else if (format === "pdf") {
    const popup = window.open("", "_blank");
    if (!popup) return;
    popup.document.title = `${doc.cluster_id} SOC Report`;
    popup.document.body.innerHTML = `<main style="max-width:900px;margin:40px auto;font:14px system-ui;line-height:1.6">${renderMarkdown(soc)}</main>`;
    popup.print();
  } else {
    const content = format === "soc" ? soc : (doc.report_markdown || soc);
    downloadText(content, "text/markdown", format === "soc" ? "soc.md" : "md");
  }
}

function traceLoader(label) {
  const holder = el("div", { class: "trace-loader" });
  holder.innerHTML = `
<svg width="220" height="64" viewBox="0 0 320 64" aria-label="${label}">
  <g transform="translate(16, 12)">
    ${[8, 20, 32].map((y) => [8, 20, 32].map((x) =>
      `<circle cx="${x}" cy="${y}" r="1.5" fill="#222222"/>`).join("")).join("")}
    <path class="trace" d="M 8 32 L 20 20 L 20 8 L 32 20 L 32 32 L 8 8"
      fill="none" stroke="#00E676" stroke-width="1.5"/>
    <rect class="pulse" x="30.5" y="18.5" width="3" height="3" fill="#00E676"/>
  </g>
  <text x="64" y="38" fill="#555555" font-weight="600" font-size="14"
    letter-spacing="1" font-family="var(--font-mono)">${label}<tspan
    class="ellipsis" fill="#00E676">…</tspan></text>
</svg>`;
  return holder;
}

/* ================= command bar ================= */

const COMMANDS = [
  { name: "/open", arg: "<chain-id>", hint: "open an incident", run: (arg) => arg && navigate(`/incident/${encodeURIComponent(arg)}`) },
  { name: "/triage", arg: "", hint: "re-run AI triage on this chain", run: () => runTriage() },
  { name: "/view", arg: "2d|3d|events|lanes", hint: "switch a view", run: (arg) => switchView(arg) },
  { name: "/tab", arg: "evidence|raw|correlation|verdict|report", hint: "evidence tab", run: (arg) => switchTab(arg) },
  { name: "/pivot", arg: "host|user|ip", hint: "hunt the selected entity", run: (arg) => pivotCommand(arg) },
  { name: "/export", arg: "", hint: "download the case report", run: () => exportReport() },
  { name: "/filter", arg: "sev=high|crit|all", hint: "set severity filter", run: (arg) => filterCommand(arg) },
  { name: "/refresh", arg: "", hint: "refetch from the engine", run: () => { refreshStatus(); refreshClusters(); if (state.view === "incident") loadIncident(); } },
  { name: "/settings", arg: "", hint: "open settings", run: () => openSettings() },
  { name: "/back", arg: "", hint: "back to incidents", run: () => navigate("/") },
  { name: "/help", arg: "", hint: "keyboard shortcuts", run: () => toggleHelp(true) },
];

function switchView(arg) {
  if (arg === "2d" || arg === "3d") { state.graphMode = arg; renderGraphPane(); }
  else if (arg === "lanes" || arg === "events") {
    state.centerView = arg === "lanes" ? "lanes" : "table";
    syncSeg("center-view", state.centerView);
    renderCenter();
  }
}

function switchTab(arg) {
  const tabs = ["evidence", "raw", "correlation", "verdict", "report"];
  if (tabs.includes(arg)) { state.evidenceTab = arg; renderEvidence(); }
}

function pivotCommand(arg) {
  const alert = selectedAlert();
  if (!alert) return;
  const domains = entityDomains();
  const value = entityOf(alert, arg === "ip" ? "ip" : arg, domains);
  if (value) pivotTo(value);
}

function filterCommand(arg) {
  const m = String(arg || "").match(/sev=(high|crit|critical|all)/);
  if (!m) return;
  state.filters.sev = m[1] === "all" ? "" : m[1] === "crit" ? "critical" : m[1];
  syncSeg("filter-sev", state.filters.sev);
  renderCenter(); renderHeader();
}

const cmdInput = $("cmd-input");
const cmdSuggest = $("cmd-suggest");
let suggestIndex = 0;

function suggestions() {
  const value = cmdInput.value.trim();
  if (!value.startsWith("/")) return [];
  const [head] = value.split(/\s+/);
  return COMMANDS.filter((c) => c.name.startsWith(head)).slice(0, 8);
}

function renderSuggest() {
  const items = suggestions();
  if (!items.length || document.activeElement !== cmdInput) {
    cmdSuggest.hidden = true;
    return;
  }
  suggestIndex = Math.min(suggestIndex, items.length - 1);
  cmdSuggest.hidden = false;
  cmdSuggest.replaceChildren(
    el("div", { class: "lbl" }, "SUGGESTED ACTIONS"),
    ...items.map((c, i) => el("div", {
      class: `row${i === suggestIndex ? " active" : ""}`,
      onmousedown: (event) => { event.preventDefault(); applySuggestion(c); },
    },
      el("span", {}, c.name),
      c.arg ? el("span", { class: "arg" }, c.arg) : null,
      el("span", { class: "arg", style: "margin-left:auto" }, c.hint),
    )));
}

function applySuggestion(command) {
  cmdInput.value = `${command.name} `;
  cmdInput.focus();
  renderSuggest();
}

function executeCommand() {
  const value = cmdInput.value.trim();
  if (!value) return;
  const [head, ...rest] = value.split(/\s+/);
  const command = COMMANDS.find((c) => c.name === head)
    || suggestions()[suggestIndex];
  cmdInput.value = "";
  cmdSuggest.hidden = true;
  if (command) command.run(rest.join(" "));
}

cmdInput.addEventListener("input", () => { suggestIndex = 0; renderSuggest(); });
cmdInput.addEventListener("focus", renderSuggest);
cmdInput.addEventListener("blur", () => { cmdSuggest.hidden = true; });
cmdInput.addEventListener("keydown", (event) => {
  const items = suggestions();
  if (event.key === "Tab" && items.length) {
    event.preventDefault();
    applySuggestion(items[suggestIndex]);
  } else if (event.key === "ArrowUp" && items.length) {
    event.preventDefault();
    suggestIndex = (suggestIndex - 1 + items.length) % items.length;
    renderSuggest();
  } else if (event.key === "ArrowDown" && items.length) {
    event.preventDefault();
    suggestIndex = (suggestIndex + 1) % items.length;
    renderSuggest();
  } else if (event.key === "Enter") {
    executeCommand();
  } else if (event.key === "Escape") {
    cmdInput.blur();
  }
});

/* ================= command palette (⌘K) ================= */

const palette = $("palette");
const paletteScrim = $("palette-scrim");
const paletteInput = $("palette-input");
const paletteResults = $("palette-results");
let paletteIndex = 0;

function paletteItems() {
  const needle = paletteInput.value.trim().toLowerCase();
  const commands = COMMANDS.map((c) => ({
    kind: "cmd", glyph: ">", label: `${c.name} ${c.arg}`.trim(), hint: c.hint,
    run: () => { togglePalette(false); if (c.arg) { cmdInput.value = `${c.name} `; cmdInput.focus(); renderSuggest(); } else c.run(""); },
  }));
  const incidents = state.clusters.map((c) => ({
    kind: "inc", glyph: "◆",
    label: c.cluster_id,
    hint: `${c.primary_entity || ""} · ${c.max_severity}`,
    run: () => { togglePalette(false); navigate(`/incident/${encodeURIComponent(c.cluster_id)}`); },
  }));
  const all = [...incidents, ...commands];
  if (!needle) return all.slice(0, 12);
  return all.filter((item) =>
    `${item.label} ${item.hint}`.toLowerCase().includes(needle)).slice(0, 12);
}

function renderPalette() {
  const items = paletteItems();
  paletteIndex = Math.min(paletteIndex, Math.max(0, items.length - 1));
  paletteResults.replaceChildren(
    ...(items.length ? items.map((item, i) => el("div", {
      class: `row${i === paletteIndex ? " active" : ""}`,
      onmousedown: (event) => { event.preventDefault(); item.run(); },
    },
      el("span", { class: "glyph" }, item.glyph),
      el("span", {}, item.label),
      el("span", { class: "hint" }, item.hint),
    )) : [el("div", { class: "empty" }, "No matches.")]));
}

function togglePalette(open) {
  palette.classList.toggle("open", open);
  paletteScrim.classList.toggle("open", open);
  if (open) {
    paletteInput.value = "";
    paletteIndex = 0;
    renderPalette();
    paletteInput.focus();
  }
}

paletteInput.addEventListener("input", () => { paletteIndex = 0; renderPalette(); });
paletteInput.addEventListener("keydown", (event) => {
  const items = paletteItems();
  if (event.key === "ArrowDown") { event.preventDefault(); paletteIndex = (paletteIndex + 1) % items.length; renderPalette(); }
  else if (event.key === "ArrowUp") { event.preventDefault(); paletteIndex = (paletteIndex - 1 + items.length) % items.length; renderPalette(); }
  else if (event.key === "Enter" && items[paletteIndex]) items[paletteIndex].run();
  else if (event.key === "Escape") togglePalette(false);
});
paletteScrim.addEventListener("click", () => togglePalette(false));

/* ================= settings drawer ================= */

const drawer = $("settings-drawer");
const drawerScrim = $("drawer-scrim");

function toggleDrawer(open) {
  drawer.classList.toggle("open", open);
  drawerScrim.classList.toggle("open", open);
}

function syncProviderFields() {
  const provider = $("set-provider").value;
  for (const field of drawer.querySelectorAll("[data-for]")) {
    field.style.display =
      (field.getAttribute("data-for") === "local") === (provider === "local")
        ? "" : "none";
  }
}

async function openSettings() {
  try {
    const settings = await getAiSettings();
    $("set-provider").value = settings.provider;
    $("set-local-model").value = settings.local_model || "";
    $("set-local-url").value = settings.local_base_url || "";
    $("set-cloud-model").value = settings.cloud_model || "";
    $("set-cloud-key").value = "";
    $("set-scope").value = settings.triage_scope;
    $("set-timeout").value = settings.timeout_seconds ?? 120;
    $("set-result").hidden = true;
    $("set-siem-result").hidden = true;
    const siem = state.status?.siem || {};
    $("set-siem-host").value = siem.host || "";
    $("set-siem-index").value = siem.alert_index || "";
    $("set-siem-key").value = "";
    $("set-siem-ca-path").value = siem.ca_cert_path || "";
    $("set-siem-ca-file").value = "";
    $("set-siem-tls").value = siem.verify_tls === false
      ? "insecure" : siem.ca_cert_path ? "custom" : "system";
    syncSiemTlsFields();
    const managedOnly = !state.managed;
    $("siem-settings").style.display = managedOnly ? "none" : "";
    $("siem-settings-head").style.display = managedOnly ? "none" : "";
    syncProviderFields();
    toggleDrawer(true);
  } catch (error) {
    alert(`Cannot load settings: ${error.message}`);
  }
}

function collectAiPayload(includeScope) {
  const provider = $("set-provider").value;
  const payload = { provider };
  if (includeScope) {
    payload.triage_scope = $("set-scope").value;
    const timeout = parseInt($("set-timeout").value, 10);
    if (Number.isFinite(timeout) && timeout > 0) payload.timeout_seconds = timeout;
  }
  if (provider === "local") {
    if ($("set-local-model").value) payload.local_model = $("set-local-model").value;
    if ($("set-local-url").value) payload.local_base_url = $("set-local-url").value;
  } else {
    if ($("set-cloud-model").value) payload.cloud_model = $("set-cloud-model").value;
    if ($("set-cloud-key").value) payload.cloud_api_key = $("set-cloud-key").value;
  }
  return payload;
}

$("set-apply").addEventListener("click", async () => {
  const resultBox = $("set-result");
  try {
    const settings = await putAiSettings(collectAiPayload(true));
    resultBox.className = "notice ok";
    resultBox.textContent = isPreviewMode
      ? `Preview model: ${settings.model_id}. This change is in-memory and will not be saved.`
      : `Active model: ${settings.model_id}. The setting was saved and applied.`;
    resultBox.hidden = false;
    refreshStatus();
  } catch (error) {
    resultBox.className = "notice error";
    resultBox.textContent = error.message;
    resultBox.hidden = false;
  }
});

$("set-validate").addEventListener("click", async () => {
  const resultBox = $("set-result");
  resultBox.className = "notice";
  resultBox.textContent = "Testing provider…";
  resultBox.hidden = false;
  try {
    const outcome = await validateAi(collectAiPayload(false));
    resultBox.className = outcome.ok ? "notice ok" : "notice error";
    resultBox.textContent = outcome.ok
      ? isPreviewMode
        ? `${outcome.model_id} preview validation simulated; no provider was contacted.`
        : `${outcome.model_id} answered in ${outcome.latency_ms} ms.`
      : `Failed: ${outcome.error}`;
  } catch (error) {
    resultBox.className = "notice error";
    resultBox.textContent = error.message;
  }
});

$("set-siem-apply").addEventListener("click", async () => {
  const resultBox = $("set-siem-result");
  const payload = {};
  if ($("set-siem-host").value) payload.host = $("set-siem-host").value;
  if ($("set-siem-key").value) payload.api_key = $("set-siem-key").value;
  if ($("set-siem-index").value) payload.alert_index = $("set-siem-index").value;
  const tlsMode = $("set-siem-tls").value;
  payload.verify_tls = tlsMode !== "insecure";
  payload.ca_cert_path = tlsMode === "custom" ? $("set-siem-ca-path").value.trim() : "";
  const caFile = $("set-siem-ca-file").files[0];
  if (caFile) payload.ca_cert_pem = await caFile.text();
  try {
    const outcome = await putSiemSettings(payload);
    resultBox.className = "notice ok";
    resultBox.textContent =
      `SIEM settings saved for ${outcome.host} / ${outcome.alert_index}. Polling now uses these settings.`;
    resultBox.hidden = false;
    refreshStatus(); refreshClusters();
  } catch (error) {
    resultBox.className = "notice error";
    resultBox.textContent = error.message;
    resultBox.hidden = false;
  }
});

$("btn-settings").addEventListener("click", openSettings);
$("set-close").addEventListener("click", () => toggleDrawer(false));
drawerScrim.addEventListener("click", () => toggleDrawer(false));
$("set-provider").addEventListener("change", syncProviderFields);
function syncSiemTlsFields() {
  const mode = $("set-siem-tls").value;
  $("set-siem-ca-field").hidden = mode !== "custom";
  $("set-siem-tls-warning").hidden = mode !== "insecure";
}
$("set-siem-tls").addEventListener("change", syncSiemTlsFields);

/* ================= help overlay ================= */

function toggleHelp(open) {
  $("help-overlay").classList.toggle("open", open);
  paletteScrim.classList.toggle("open", open);
}
$("btn-help").addEventListener("click", () => toggleHelp(true));

/* ================= wiring: nav, filters, tabs, header ================= */

$("nav-active").addEventListener("click", () => setNavMode("active"));
$("nav-all").addEventListener("click", () => setNavMode("all"));
$("nav-triaged").addEventListener("click", () => setNavMode("triaged"));
for (const id of ["nav-active", "nav-all", "nav-triaged"]) {
  $(id).addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") $(id).click();
  });
}

function setNavMode(mode) {
  state.navMode = mode;
  state.cursor = 0;
  if (state.view !== "explorer") navigate("/");
  else { renderNav(); renderCenter(); renderHeader(); }
}

function wireSeg(id, apply) {
  $(id).addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    for (const b of $(id).querySelectorAll("button")) b.classList.toggle("on", b === button);
    apply(button.dataset.v);
  });
}

function syncSeg(id, value) {
  for (const b of $(id).querySelectorAll("button")) {
    b.classList.toggle("on", b.dataset.v === value);
  }
}

wireSeg("filter-sev", (v) => { state.filters.sev = v; state.cursor = 0; renderCenter(); renderHeader(); });
wireSeg("filter-verdict", (v) => { state.filters.verdict = v; state.cursor = 0; renderCenter(); renderHeader(); });
wireSeg("filter-time", (v) => { state.filters.hours = v; state.cursor = 0; renderCenter(); renderHeader(); });
wireSeg("center-view", (v) => { state.centerView = v === "lanes" ? "lanes" : "table"; renderCenter(); });
wireSeg("graph-mode", (v) => { state.graphMode = v; renderGraphPane(); });

$("global-search").addEventListener("input", (event) => {
  state.filters.search = event.target.value;
  state.nodeFilter = "";
  state.cursor = 0;
  renderCenter();
  renderHeader();
});

$("evidence-tabs").addEventListener("click", (event) => {
  const tab = event.target?.dataset?.tab;
  if (tab) { state.evidenceTab = tab; renderEvidence(); }
});

$("btn-export").addEventListener("click", () => {
  const menu = $("export-menu");
  menu.hidden = !menu.hidden;
  $("btn-export").setAttribute("aria-expanded", String(!menu.hidden));
  if (!menu.hidden) menu.querySelector("button")?.focus();
});
$("export-menu").addEventListener("click", (event) => {
  const button = event.target.closest("[data-export]");
  if (!button) return;
  exportReport(button.dataset.export);
  $("export-menu").hidden = true;
  $("btn-export").setAttribute("aria-expanded", "false");
});

/* ================= global keyboard ================= */

function inEditable(target) {
  return target && (target.tagName === "INPUT" || target.tagName === "SELECT"
    || target.tagName === "TEXTAREA" || target.isContentEditable);
}

document.addEventListener("keydown", (event) => {
  const meta = event.metaKey || event.ctrlKey;
  if (meta && event.key.toLowerCase() === "k") {
    event.preventDefault();
    togglePalette(!palette.classList.contains("open"));
    return;
  }
  if (meta && event.key.toLowerCase() === "f") {
    event.preventDefault();
    $("global-search").focus();
    $("global-search").select();
    return;
  }
  if (event.key === "Escape") {
    if (palette.classList.contains("open")) { togglePalette(false); return; }
    if ($("help-overlay").classList.contains("open")) { toggleHelp(false); return; }
    if (drawer.classList.contains("open")) { toggleDrawer(false); return; }
    if (inEditable(event.target)) { event.target.blur(); return; }
    if (state.view === "incident") navigate("/");
    return;
  }
  if (inEditable(event.target)) return;

  switch (event.key) {
    case "/":
      event.preventDefault();
      cmdInput.focus();
      if (!cmdInput.value) { cmdInput.value = "/"; renderSuggest(); }
      break;
    case "j": case "ArrowDown": event.preventDefault(); moveCursor(1); break;
    case "k": case "ArrowUp": event.preventDefault(); moveCursor(-1); break;
    case "Enter": openCursor(); break;
    case "1": switchTab("evidence"); break;
    case "2": switchTab("raw"); break;
    case "3": switchTab("correlation"); break;
    case "4": switchTab("verdict"); break;
    case "5": switchTab("report"); break;
    case "g":
      state.graphMode = state.graphMode === "2d" ? "3d" : "2d";
      renderGraphPane();
      break;
    case "t":
      if (state.view === "incident") {
        state.centerView = state.centerView === "table" ? "lanes" : "table";
        syncSeg("center-view", state.centerView === "lanes" ? "lanes" : "table");
        renderCenter();
      }
      break;
    case "r": if (state.view === "incident") runTriage(); break;
    case "e": exportReport(); break;
    case "?": toggleHelp(!$("help-overlay").classList.contains("open")); break;
    default: break;
  }
});

function moveCursor(delta) {
  if (state.view === "explorer") {
    const rows = filteredClusters();
    if (!rows.length) return;
    state.cursor = Math.max(0, Math.min(rows.length - 1, state.cursor + delta));
    renderExplorer();
    scrollCursorIntoView();
  } else {
    const events = filteredEvents();
    if (!events.length) return;
    const index = events.findIndex((a) => a.uid === state.selectedUid);
    const next = Math.max(0, Math.min(events.length - 1,
      (index === -1 ? 0 : index + delta)));
    selectEvent(events[next].uid);
    scrollCursorIntoView();
  }
}

function scrollCursorIntoView() {
  const row = $("grid-body").querySelector("tr.selected");
  if (row) row.scrollIntoView({ block: "nearest" });
}

function openCursor() {
  if (state.view !== "explorer") return;
  const rows = filteredClusters();
  const target = rows[state.cursor];
  if (target) navigate(`/incident/${encodeURIComponent(target.cluster_id)}`);
}

/* ================= persisted split-pane layout ================= */

const LAYOUT_KEY = "loglookup.investigationLayout.v1";
const LAYOUT_DEFAULTS = { railWidth: 480, evidenceHeight: 300, graphHeight: 260, verdictHeight: 300 };

function readLayout() {
  try { return { ...LAYOUT_DEFAULTS, ...JSON.parse(localStorage.getItem(LAYOUT_KEY) || "{}") }; }
  catch { return { ...LAYOUT_DEFAULTS }; }
}

function applyLayout(layout) {
  const root = document.documentElement;
  root.style.setProperty("--rail-w", `${layout.railWidth}px`);
  root.style.setProperty("--evidence-h", `${layout.evidenceHeight}px`);
  root.style.setProperty("--graph-h", `${layout.graphHeight}px`);
  root.style.setProperty("--verdict-h", `${layout.verdictHeight}px`);
}

function setupSplitter(id, key, axis, measure) {
  const splitter = $(id);
  const startDrag = (event) => {
    if (window.innerWidth <= 1000 && id !== "evidence-resizer") return;
    event.preventDefault();
    const layout = readLayout(); const start = axis === "x" ? event.clientX : event.clientY;
    const initial = layout[key];
    splitter.classList.add("dragging"); document.body.classList.add("is-resizing");
    splitter.setPointerCapture?.(event.pointerId);
    const move = (moveEvent) => {
      const current = axis === "x" ? moveEvent.clientX : moveEvent.clientY;
      layout[key] = measure(initial, current - start);
      applyLayout(layout);
    };
    const stop = () => {
      splitter.removeEventListener("pointermove", move);
      splitter.removeEventListener("pointerup", stop);
      splitter.removeEventListener("pointercancel", stop);
      splitter.classList.remove("dragging"); document.body.classList.remove("is-resizing");
      localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
      renderGraphPane();
    };
    splitter.addEventListener("pointermove", move);
    splitter.addEventListener("pointerup", stop);
    splitter.addEventListener("pointercancel", stop);
  };
  splitter.addEventListener("pointerdown", startDrag);
  splitter.addEventListener("dblclick", () => {
    const layout = readLayout(); layout[key] = LAYOUT_DEFAULTS[key];
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout)); applyLayout(layout); renderGraphPane();
  });
  splitter.addEventListener("keydown", (event) => {
    const direction = axis === "x"
      ? (event.key === "ArrowLeft" ? -1 : event.key === "ArrowRight" ? 1 : 0)
      : (event.key === "ArrowUp" ? -1 : event.key === "ArrowDown" ? 1 : 0);
    if (!direction) return;
    event.preventDefault(); const layout = readLayout();
    layout[key] = measure(layout[key], direction * 16);
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout)); applyLayout(layout); renderGraphPane();
  });
}

function setupLayout() {
  applyLayout(readLayout());
  setupSplitter("rail-resizer", "railWidth", "x", (initial, delta) =>
    Math.max(320, Math.min(window.innerWidth * 0.55, initial - delta)));
  setupSplitter("evidence-resizer", "evidenceHeight", "y", (initial, delta) =>
    Math.max(120, Math.min(window.innerHeight * 0.62, initial - delta)));
  setupSplitter("graph-resizer", "graphHeight", "y", (initial, delta) =>
    Math.max(140, Math.min(window.innerHeight * 0.62, initial + delta)));
  setupSplitter("verdict-resizer", "verdictHeight", "y", (initial, delta) =>
    Math.max(120, Math.min(window.innerHeight * 0.58, initial + delta)));
}

/* ================= boot ================= */

async function boot() {
  setupLayout();
  if (isPreviewMode) {
    document.body.classList.add("preview-mode");
    document.title = `UI PREVIEW · ${document.title}`;
    const banner = el("div", { class: "preview-banner", role: "status" },
      el("b", {}, "UI PREVIEW"),
      el("span", {}, "Sample data · no engine, SIEM, or AI connections"));
    document.querySelector(".zone-nav .brand")?.after(banner);
  }
  try {
    const setup = await getSetup();
    state.managed = setup.managed;
    if (setup.needs_setup) {
      window.location.href = "/setup";
      return;
    }
  } catch {
    /* engine offline — the explorer state explains it */
  }
  routeFromLocation();
  await Promise.allSettled([refreshStatus(), refreshClusters()]);
  if (state.view === "incident") await loadIncident();
  else render();

  setInterval(() => {
    refreshStatus();
    refreshClusters();
    // A pending chain may have been triaged by a background cycle.
    if (state.view === "incident" && state.doc
        && state.doc.triage_status === "pending" && !state.triaging) {
      getCluster(state.clusterId).then((doc) => {
        if (doc.triage_status !== state.doc.triage_status) {
          state.doc = doc;
          render();
        }
      }).catch(() => {});
    }
  }, REFRESH_MS);
}

boot();
