/* Shared formatting: severity colours (theme-independent), verdict chips,
 * timestamps, and a minimal markdown renderer for the case report. */

export const SEVERITY_COLORS = {
  Fatal: "var(--sev-fatal)",
  Critical: "var(--sev-critical)",
  High: "var(--sev-high)",
  Medium: "var(--sev-medium)",
  Low: "var(--sev-low)",
  Informational: "var(--sev-info)",
  Unknown: "var(--sev-unknown)",
};

export function severityColor(severity) {
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS.Unknown;
}

export function severityChip(severity) {
  const el = document.createElement("span");
  el.className = `chip sev-${String(severity || "Unknown").toLowerCase()}`;
  el.textContent = String(severity || "Unknown").toUpperCase();
  return el;
}

/** Deterministic risk banding used by both graphs and badges. */
export function riskColor(risk) {
  if (risk >= 16) return "var(--sev-critical)";
  if (risk >= 8) return "var(--sev-high)";
  if (risk >= 4) return "var(--sev-medium)";
  return "var(--sev-low)";
}

export const VERDICT_COLORS = {
  "True Positive": "var(--verdict-tp)",
  "False Positive": "var(--verdict-fp)",
  "Needs Escalation": "var(--verdict-esc)",
};

const VERDICT_CLASSES = {
  "True Positive": "verdict-tp",
  "False Positive": "verdict-fp",
  "Needs Escalation": "verdict-esc",
};

export function verdictChip(verdict, confidence, triageStatus) {
  const el = document.createElement("span");
  el.className = `chip ${VERDICT_CLASSES[verdict] || ""}`.trim();
  if (verdict) {
    el.textContent =
      confidence == null ? verdict : `${verdict} · ${confidence}%`;
  } else if (triageStatus === "ai_unavailable") {
    el.textContent = "AI unavailable";
    el.title = "This result contains correlation data only because AI triage was unavailable.";
  } else {
    el.textContent = "pending";
  }
  return el;
}

export function fmtTime(iso) {
  if (!iso) return "—";
  return String(iso).replace("T", " ").replace(/\.\d+Z$/, "Z");
}

export function fmtTimeMs(ms) {
  if (ms == null) return "—";
  return fmtTime(new Date(ms).toISOString());
}

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child == null) continue;
    node.append(child.nodeType ? child : document.createTextNode(child));
  }
  return node;
}

/* -- minimal markdown renderer (headings, tables, lists, bold, code,
 *    links, blockquotes, hr) — enough for the engine's case reports. ---- */

function escapeHtml(text) {
  return text
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function inline(text) {
  let out = escapeHtml(text);
  out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/_([^_]+)_/g, "<em>$1</em>");
  out = out.replace(
    /\[([^\]]+)\]\((https?:\/\/[^)\s]+|\/[^)\s]*)\)/g,
    '<a href="$2">$1</a>'
  );
  return out;
}

export function renderMarkdown(markdown) {
  const lines = String(markdown || "").split("\n");
  const html = [];
  let list = false;
  let table = false;
  const closeBlocks = () => {
    if (list) { html.push("</ul>"); list = false; }
    if (table) { html.push("</tbody></table>"); table = false; }
  };
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\s*$/.test(line)) { closeBlocks(); continue; }
    if (line.startsWith("|")) {
      const cells = line.split("|").slice(1, -1).map((c) => c.trim());
      if (cells.every((c) => /^-+$/.test(c))) continue; // separator row
      if (!table) {
        html.push("<table><thead><tr>");
        html.push(...cells.map((c) => `<th>${inline(c)}</th>`));
        html.push("</tr></thead><tbody>");
        table = true;
        continue;
      }
      html.push("<tr>", ...cells.map((c) => `<td>${inline(c)}</td>`), "</tr>");
      continue;
    }
    if (table) { html.push("</tbody></table>"); table = false; }
    if (line.startsWith("### ")) { closeBlocks(); html.push(`<h3>${inline(line.slice(4))}</h3>`); continue; }
    if (line.startsWith("## ")) { closeBlocks(); html.push(`<h2>${inline(line.slice(3))}</h2>`); continue; }
    if (line.startsWith("# ")) { closeBlocks(); html.push(`<h1>${inline(line.slice(2))}</h1>`); continue; }
    if (line.startsWith("> ")) { closeBlocks(); html.push(`<blockquote>${inline(line.slice(2))}</blockquote>`); continue; }
    if (/^---+$/.test(line.trim())) { closeBlocks(); html.push("<hr/>"); continue; }
    if (line.startsWith("- ")) {
      if (!list) { html.push("<ul>"); list = true; }
      html.push(`<li>${inline(line.slice(2))}</li>`);
      continue;
    }
    closeBlocks();
    html.push(`<p>${inline(line)}</p>`);
  }
  closeBlocks();
  return html.join("\n");
}
