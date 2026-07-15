/* First launch onboarding wizard.
 *
 * Four screens: Welcome -> Connect SIEM -> Configure AI -> Review.
 * Everything is honest: connection tests hit the real SIEM, provider
 * validation performs a real inference round-trip, and nothing is
 * pre-filled with fake data. Completion POSTs /api/setup/complete; the
 * engine persists config + encrypted secrets and starts polling live.
 */

const $ = (id) => document.getElementById(id);
const isPreviewMode =
  new URLSearchParams(window.location.search).get("preview") === "1";

async function previewApi(path, options) {
  const payload = options.body ? JSON.parse(options.body) : {};
  if (path === "/api/setup") {
    return { managed: true, needs_setup: true, preview: true };
  }
  if (path === "/api/setup/siem/test") {
    return {
      ok: true,
      cluster: { cluster_name: "preview-security", version: "9.1.0" },
      indices: [
        { index: ".alerts-security", docs: 12842 },
        { index: "logs-endpoint.events-*", docs: 84620 },
      ],
      suggested: [".alerts-security"],
    };
  }
  if (path === "/api/ai/local") {
    return {
      running: true,
      binary_found: true,
      version: "preview",
      base_url: "local preview",
      models: [{ name: "foundation-sec-8b:latest", size: 8_200_000_000 }],
      recommended: [
        { name: "foundation-sec-8b", note: "security-focused local model", approx_size_gb: 8.2 },
      ],
    };
  }
  if (path === "/api/ai/validate") {
    const provider = payload.provider || "local";
    const model = payload.local_model || payload.cloud_model || "preview-model";
    return { ok: true, model_id: `${provider}/${model}`, latency_ms: 0, preview: true };
  }
  if (path === "/api/status") {
    return { kb: { loaded: true, techniques: 684, attack_version: "preview" } };
  }
  if (path === "/api/setup/complete") {
    return { ok: true, preview: true };
  }
  throw new Error(`Action ${path} is not available in the UI preview.`);
}

async function api(path, options = {}) {
  if (isPreviewMode) return previewApi(path, options);
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return body;
}

/* ---- state --------------------------------------------------------------- */

const state = {
  step: 0,
  siem: { host: "", api_key: "", alert_index: "", poll_seconds: 60,
          severity_floor: "medium", tested: false, skipped: false,
          cluster: null, verify_tls: true, ca_cert_path: "", ca_cert_pem: "" },
  ai: { provider: "local", local_model: "", local_base_url: "http://localhost:11434",
        cloud_model: "", cloud_api_key: "", redaction: true,
        zero_data_retention: true, validated: false, validation: null },
  ollama: null,
};

/* ---- step navigation ------------------------------------------------------- */

function show(step) {
  state.step = step;
  document.querySelectorAll(".screen").forEach((el) => {
    el.classList.toggle("show", Number(el.dataset.screen) === step);
  });
  document.querySelectorAll(".steps .step").forEach((el) => {
    const n = Number(el.dataset.step);
    el.classList.toggle("now", n === step);
    el.classList.toggle("done", n < step);
  });
  if (step === 2 && !state.ollama) detectOllama();
  if (step === 3) renderReview();
}

document.querySelectorAll("[data-back]").forEach((btn) => {
  btn.addEventListener("click", () => show(Math.max(0, state.step - 1)));
});
$("btn-start").addEventListener("click", () => show(1));

/* ---- screen 2: SIEM ------------------------------------------------------------ */

function pill(el, textEl, kind, text) {
  el.hidden = false;
  el.classList.remove("ok", "bad", "warn");
  if (kind) el.classList.add(kind);
  textEl.textContent = text;
}

function syncSiemTls() {
  const mode = $("siem-tls").value;
  $("siem-ca-fields").hidden = mode !== "custom";
  $("siem-tls-warning").hidden = mode !== "insecure";
}
$("siem-tls").addEventListener("change", syncSiemTls);

$("btn-siem-test").addEventListener("click", async () => {
  const host = $("siem-host").value.trim();
  if (!host) {
    pill($("siem-test-pill"), $("siem-test-text"), "bad", "enter a URL first");
    return;
  }
  pill($("siem-test-pill"), $("siem-test-text"), "warn", "testing…");
  $("siem-test-result").hidden = true;
  try {
    const tlsMode = $("siem-tls").value;
    const caFile = $("siem-ca-file").files[0];
    const caCertPem = caFile ? await caFile.text() : "";
    const result = await api("/api/setup/siem/test", {
      method: "POST",
      body: JSON.stringify({
        host, api_key: $("siem-key").value,
        verify_tls: tlsMode !== "insecure",
        ca_cert_path: tlsMode === "custom" ? $("siem-ca-path").value.trim() : "",
        ca_cert_pem: tlsMode === "custom" ? caCertPem : "",
      }),
    });
    if (!result.ok) throw new Error(result.error || "connection failed");
    state.siem.tested = true;
    state.siem.skipped = false;
    state.siem.cluster = result.cluster;
    pill($("siem-test-pill"), $("siem-test-text"), "ok",
         `Connected to ${result.cluster.cluster_name || "cluster"} ` +
         `(v${result.cluster.version || "?"})`);
    const select = $("siem-index");
    select.innerHTML = "";
    const seen = new Set();
    const add = (name, docs, suggested) => {
      if (seen.has(name)) return;
      seen.add(name);
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = docs != null
        ? `${name}  (${docs} docs)${suggested ? " (suggested)" : ""}`
        : name;
      select.appendChild(opt);
    };
    const docsFor = Object.fromEntries(
      (result.indices || []).map((i) => [i.index, i.docs]));
    (result.suggested || []).forEach((n) => add(n, docsFor[n], true));
    (result.indices || []).forEach((i) => add(i.index, i.docs, false));
    if (!seen.size) add(".alerts-security", null, false);
    $("siem-index-field").hidden = false;
    const note = (result.suggested || []).length
      ? `Detected ${seen.size} indices; ${result.suggested.length} look like alert indices.`
      : `Detected ${seen.size} indices. Choose the index that receives your detections.`;
    $("siem-test-result").textContent = note;
    $("siem-test-result").className = "notice ok";
    $("siem-test-result").hidden = false;
    $("btn-siem-next").disabled = false;
  } catch (err) {
    state.siem.tested = false;
    pill($("siem-test-pill"), $("siem-test-text"), "bad", "failed");
    $("siem-test-result").textContent = String(err.message || err);
    $("siem-test-result").className = "notice error";
    $("siem-test-result").hidden = false;
    $("btn-siem-next").disabled = true;
  }
});

$("btn-siem-next").addEventListener("click", async () => {
  state.siem.host = $("siem-host").value.trim();
  state.siem.api_key = $("siem-key").value;
  state.siem.alert_index = $("siem-index").value || ".alerts-security";
  state.siem.poll_seconds = Math.max(10, Number($("siem-poll").value) || 60);
  state.siem.severity_floor = $("siem-floor").value;
  const tlsMode = $("siem-tls").value;
  state.siem.verify_tls = tlsMode !== "insecure";
  state.siem.ca_cert_path = tlsMode === "custom" ? $("siem-ca-path").value.trim() : "";
  state.siem.ca_cert_pem = "";
  const caFile = $("siem-ca-file").files[0];
  if (caFile) state.siem.ca_cert_pem = await caFile.text();
  show(2);
});

$("btn-siem-skip").addEventListener("click", () => {
  state.siem.skipped = true;
  state.siem.tested = false;
  state.siem.host = "";
  state.siem.api_key = "";
  show(2);
});

/* ---- screen 3: AI ---------------------------------------------------------------- */

function selectMode(mode) {
  state.ai.provider = mode === "cloud" ? $("cloud-provider").value : "local";
  $("mode-local").classList.toggle("selected", mode === "local");
  $("mode-cloud").classList.toggle("selected", mode === "cloud");
  $("pane-local").hidden = mode !== "local";
  $("pane-cloud").hidden = mode !== "cloud";
  state.ai.validated = false;
  $("ai-validate-pill").hidden = true;
  $("ai-validate-result").hidden = true;
}
$("mode-local").addEventListener("click", () => selectMode("local"));
$("mode-cloud").addEventListener("click", () => selectMode("cloud"));
$("cloud-provider").addEventListener("change", () => {
  state.ai.provider = $("cloud-provider").value;
  state.ai.validated = false;
});

async function detectOllama() {
  const box = $("ollama-status");
  box.className = "notice";
  box.textContent = "Detecting Ollama…";
  try {
    state.ollama = await api("/api/ai/local");
  } catch (err) {
    box.className = "notice error";
    box.textContent = `Detection failed: ${err.message || err}`;
    return;
  }
  renderOllama();
}

function renderOllama() {
  const o = state.ollama;
  const box = $("ollama-status");
  if (!o.running) {
    box.className = "notice error";
    box.textContent = o.binary_found
      ? `Ollama is installed but not running (${o.detail || "no response"}). Start it, then re open this step.`
      : "Ollama was not detected on this machine. Install it from ollama.com or choose a cloud provider.";
  } else {
    box.className = "notice ok";
    box.textContent = `Ollama ${o.version || ""} detected at ${o.base_url}. ${o.models.length} model(s) installed.`;
  }

  const field = $("local-model-field");
  const select = $("local-model");
  select.innerHTML = "";
  (o.models || []).forEach((m) => {
    const opt = document.createElement("option");
    opt.value = m.name;
    const gb = m.size ? ` (${(m.size / 1e9).toFixed(1)} GB)` : "";
    opt.textContent = `${m.name}${gb}`;
    select.appendChild(opt);
  });
  field.hidden = !(o.models || []).length;

  const rows = $("recommended-rows");
  rows.innerHTML = "";
  const norm = (n) => (n.includes(":") ? n : `${n}:latest`);
  (o.recommended || []).forEach((r) => {
    const installed = (o.models || []).some((m) => norm(m.name) === norm(r.name));
    const row = document.createElement("div");
    row.className = "model-row";
    const btn = installed
      ? `<span class="chip tech">installed</span>`
      : `<button data-pull="${r.name}" ${o.running ? "" : "disabled"}>Download</button>`;
    row.innerHTML = `<span class="mono">${r.name}</span>
      <span class="grow why">${r.note} · ~${r.approx_size_gb} GB</span>${btn}`;
    rows.appendChild(row);
  });
  $("recommended-box").hidden = !(o.recommended || []).length;
  rows.querySelectorAll("[data-pull]").forEach((btn) => {
    btn.addEventListener("click", () => startPull(btn.dataset.pull));
  });
}

let pullTimer = null;

async function startPull(model) {
  try {
    await api("/api/ai/local/pull", {
      method: "POST", body: JSON.stringify({ model }),
    });
  } catch (err) {
    $("ollama-status").className = "notice error";
    $("ollama-status").textContent = `Download failed to start: ${err.message || err}`;
    return;
  }
  $("pull-progress").hidden = false;
  $("pull-name").textContent = model;
  clearInterval(pullTimer);
  pullTimer = setInterval(pollPull, 900);
}

async function pollPull() {
  let p;
  try {
    p = await api("/api/ai/local/pull");
  } catch {
    return;
  }
  const pct = p.percent != null ? p.percent : (p.done ? 100 : 0);
  $("pull-bar").style.width = `${pct}%`;
  $("pull-pct").textContent = p.error ? "failed" : `${pct}%  ${p.status || ""}`;
  if (!p.active) {
    clearInterval(pullTimer);
    if (p.error) {
      $("ollama-status").className = "notice error";
      $("ollama-status").textContent = `Download of ${p.model} failed: ${p.error}`;
    } else if (p.done) {
      detectOllama(); // refresh installed models
    }
  }
}

$("btn-ai-validate").addEventListener("click", async () => {
  const local = !$("pane-local").hidden;
  const body = local
    ? { provider: "local",
        local_model: $("local-model").value || undefined }
    : { provider: $("cloud-provider").value,
        cloud_model: $("cloud-model").value.trim() || undefined,
        cloud_api_key: $("cloud-key").value || undefined,
        zero_data_retention: $("cloud-zdr").checked };
  if (local && !body.local_model) {
    pill($("ai-validate-pill"), $("ai-validate-text"), "bad",
         "no installed model selected");
    return;
  }
  pill($("ai-validate-pill"), $("ai-validate-text"), "warn",
       "testing provider…");
  $("ai-validate-result").hidden = true;
  try {
    const result = await api("/api/ai/validate", {
      method: "POST", body: JSON.stringify(body),
    });
    state.ai.validated = result.ok;
    state.ai.validation = result;
    if (result.ok) {
      pill($("ai-validate-pill"), $("ai-validate-text"), "ok",
           `${result.model_id} answered in ${result.latency_ms} ms`);
    } else {
      pill($("ai-validate-pill"), $("ai-validate-text"), "bad", "failed");
      $("ai-validate-result").textContent = result.error || "validation failed";
      $("ai-validate-result").className = "notice error";
      $("ai-validate-result").hidden = false;
    }
  } catch (err) {
    state.ai.validated = false;
    pill($("ai-validate-pill"), $("ai-validate-text"), "bad", "failed");
    $("ai-validate-result").textContent = String(err.message || err);
    $("ai-validate-result").className = "notice error";
    $("ai-validate-result").hidden = false;
  }
});

$("btn-ai-next").addEventListener("click", () => {
  const local = !$("pane-local").hidden;
  if (local) {
    state.ai.provider = "local";
    state.ai.local_model = $("local-model").value || "";
    state.ai.redaction = true;
    state.ai.zero_data_retention = true;
  } else {
    state.ai.provider = $("cloud-provider").value;
    state.ai.cloud_model = $("cloud-model").value.trim();
    state.ai.cloud_api_key = $("cloud-key").value;
    state.ai.redaction = $("cloud-redaction").checked;
    state.ai.zero_data_retention = $("cloud-zdr").checked;
  }
  show(3);
});

/* ---- screen 4: review ---------------------------------------------------------------- */

function healthPill(kind, text) {
  return `<span class="pill ${kind}"><span class="dot"></span>${text}</span>`;
}

async function renderReview() {
  const pills = [];
  if (state.siem.tested) {
    pills.push(healthPill("ok", `SIEM connected (${state.siem.cluster?.cluster_name || state.siem.host})`));
  } else {
    pills.push(healthPill("warn", "SIEM is not configured. Connect it later in Settings."));
  }
  if (state.ai.validated) {
    pills.push(healthPill("ok", `AI validated (${state.ai.validation?.model_id})`));
  } else {
    pills.push(healthPill("warn", "AI provider is not validated. Triage remains off until validation succeeds."));
  }
  try {
    const status = await api("/api/status");
    pills.push(status.kb.loaded
      ? healthPill("ok", `ATT&CK KB loaded (${status.kb.techniques} techniques, v${status.kb.attack_version})`)
      : healthPill("warn", "ATT&CK knowledge base is not ready. It is normally built during installation."));
  } catch { /* engine still answers /setup; keep going */ }
  $("health-pills").innerHTML = pills.join("");

  const rows = [];
  const kv = (k, v) => rows.push(`<dt>${k}</dt><dd>${v}</dd>`);
  kv("SIEM", state.siem.skipped || !state.siem.host
      ? "not configured (skip)" : `<span class="mono">${state.siem.host}</span>`);
  if (state.siem.host) {
    kv("Alert index", `<span class="mono">${state.siem.alert_index}</span>`);
    kv("Poll interval", `${state.siem.poll_seconds}s, ${state.siem.severity_floor}+ severity`);
    kv("SIEM API key", state.siem.api_key ? "stored encrypted" : "none provided");
    kv("TLS verification", state.siem.verify_tls
      ? (state.siem.ca_cert_path || state.siem.ca_cert_pem ? "custom CA" : "system trust store")
      : "DISABLED (lab only)");
  }
  kv("AI provider", state.ai.provider);
  if (state.ai.provider === "local") {
    kv("Local model", `<span class="mono">${state.ai.local_model || "not selected"}</span>`);
    kv("Privacy", "Evidence stays on this machine");
  } else {
    kv("Cloud model", `<span class="mono">${state.ai.cloud_model || "provider default"}</span>`);
    kv("Cloud API key", state.ai.cloud_api_key ? "stored encrypted" : "none provided");
    kv("Redaction", state.ai.redaction ? "on; values are replaced before each call" : "OFF");
    kv("Zero Data Retention", state.ai.zero_data_retention ? "acknowledged" : "NOT acknowledged; cloud calls are blocked");
  }
  $("summary").innerHTML = rows.join("");
}

$("btn-launch").addEventListener("click", async () => {
  $("btn-launch").disabled = true;
  $("launch-result").hidden = true;
  const body = {
    siem: {
      host: state.siem.host,
      api_key: state.siem.api_key,
      alert_index: state.siem.alert_index || ".alerts-security",
      poll_seconds: state.siem.poll_seconds,
      severity_floor: state.siem.severity_floor,
      verify_tls: state.siem.verify_tls,
      ca_cert_path: state.siem.ca_cert_path,
      ca_cert_pem: state.siem.ca_cert_pem,
    },
    ai: {
      provider: state.ai.provider,
      local_model: state.ai.local_model || "",
      cloud_model: state.ai.cloud_model || null,
      cloud_api_key: state.ai.cloud_api_key || "",
      redaction: state.ai.redaction,
      zero_data_retention: state.ai.zero_data_retention,
    },
  };
  if (!body.ai.local_model) delete body.ai.local_model;
  try {
    await api("/api/setup/complete", {
      method: "POST", body: JSON.stringify(body),
    });
    window.location.href = isPreviewMode ? "/?preview=1" : "/";
  } catch (err) {
    $("btn-launch").disabled = false;
    $("launch-result").textContent = String(err.message || err);
    $("launch-result").className = "notice error";
    $("launch-result").hidden = false;
  }
});

/* ---- boot -------------------------------------------------------------------------- */

if (isPreviewMode) {
  document.title = `UI PREVIEW · ${document.title}`;
  const note = document.createElement("div");
  note.className = "notice";
  note.style.cssText = "border-color:rgba(255,214,0,.35);color:var(--sev-medium);text-align:center";
  note.innerHTML = "<b>UI PREVIEW</b> · setup checks are simulated; nothing will be installed, saved, or contacted";
  document.querySelector(".wizard-tag")?.after(note);
  $("siem-host").value = "https://elastic.preview.local:9200";
}

api("/api/setup").then((s) => {
  if (s.managed && !s.needs_setup) window.location.href = "/";
}).catch(() => {});
show(0);
syncSiemTls();
