/* In-browser sample data for the UI-only preview.
 *
 * This module deliberately has no engine, SIEM, AI provider, network, or
 * package dependencies. It mirrors the API shapes closely enough to exercise
 * every dashboard view while making it impossible to confuse sample results
 * with live security data.
 */

const ago = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();
const epoch = (iso) => Date.parse(iso);
const copy = (value) => JSON.parse(JSON.stringify(value));

function alert(uid, minutesAgo, severity, title, entities, tactic, technique) {
  const time = ago(minutesAgo);
  const host = entities.find((value) => /(?:wkstn|host|runner|api-|dc-)/i.test(value)) || "";
  const user = entities.find((value) => /(?:\.|svc-|bot$)/i.test(value) && value !== host) || "";
  const process = /powershell/i.test(title) ? "powershell.exe" : "";
  const command = process ? "powershell.exe -EncodedCommand SQBFAFgA" : "";
  return {
    uid,
    time: epoch(time),
    time_dt: time,
    severity,
    title,
    entities,
    tactics: tactic ? [tactic] : [],
    techniques: technique ? [technique] : [],
    source: "ui-preview",
    description: title,
    rule: title,
    host, user, process, command,
    evidence: {
      host: { name: host }, user: { name: user },
      process: { name: process, command_line: command,
        parent: { name: process ? "WINWORD.EXE" : "" } },
    },
  };
}

function entity(name, domain, riskScore, identifiers) {
  return { name, domain, risk_score: riskScore, identifiers };
}

const documents = [
  {
    cluster_id: "CHAIN-DEMO-workstation-042",
    triage_status: "triaged",
    written_at: ago(5),
    dashboard_url: "/incident/CHAIN-DEMO-workstation-042",
    chain: {
      alert_count: 4,
      primary_entity: "wkstn-fin-042",
      first_time: ago(82),
      last_time: ago(7),
      tactic_sequence: ["Initial Access", "Execution", "Credential Access", "Lateral Movement"],
      disposition: "progressing",
      risk_score: 94,
      surfaced: true,
      entities: [
        entity("wkstn-fin-042", "host", 94, { hostname: ["wkstn-fin-042"] }),
        entity("a.patel", "user", 81, { username: ["a.patel"] }),
        entity("10.24.8.19", "ip", 72, { ip: ["10.24.8.19"] }),
        entity("dc-eu-01", "host", 86, { hostname: ["dc-eu-01"] }),
      ],
      alerts: [
        alert("demo-001", 82, "Medium", "Suspicious attachment opened", ["wkstn-fin-042", "a.patel"], "Initial Access", { uid: "T1566.001", name: "Spearphishing Attachment" }),
        alert("demo-002", 61, "High", "Encoded PowerShell launched from Office", ["wkstn-fin-042", "a.patel"], "Execution", { uid: "T1059.001", name: "PowerShell" }),
        alert("demo-003", 34, "Critical", "Credential material accessed", ["wkstn-fin-042", "a.patel"], "Credential Access", { uid: "T1003", name: "OS Credential Dumping" }),
        alert("demo-004", 7, "Critical", "Remote service authentication to domain controller", ["wkstn-fin-042", "a.patel", "10.24.8.19", "dc-eu-01"], "Lateral Movement", { uid: "T1021.002", name: "SMB/Windows Admin Shares" }),
      ],
    },
    triage: {
      verdict: "True Positive",
      confidence_score: 92,
      mitre_attack_techniques: ["T1566.001", "T1059.001", "T1003", "T1021.002"],
      critical_evidence_fields: ["process.command_line", "file.name", "destination.hostname"],
      investigation_chain_of_thought: "The sequence begins with a user opening an attachment. Encoded PowerShell follows on the same host and user. Credential access is then followed by authentication to a domain controller, which is consistent with a progressing compromise.",
      remediation_recommendations: [
        "Isolate wkstn-fin-042 while preserving volatile evidence.",
        "Reset a.patel credentials and review recent domain authentications.",
        "Hunt for the same command line and attachment hash across endpoints.",
      ],
      validation: { original_confidence: 92, notes: ["All cited fields are present in the preview evidence."] },
      model_id: "preview/sample-model",
      generated_at: ago(6),
    },
    report_markdown: `# Attack Chain CHAIN-DEMO-workstation-042

> UI preview only — this report is generated from sample data.

## Decision

**True Positive** with **92% confidence**. The correlated sequence shows attachment execution, encoded PowerShell, credential access, and lateral movement toward a domain controller.

## Immediate actions

1. Isolate \`wkstn-fin-042\` while preserving volatile evidence.
2. Reset the \`a.patel\` account and review recent authentications.
3. Hunt for the same process command line and attachment hash.
`,
  },
  {
    cluster_id: "CHAIN-DEMO-api-gateway-017",
    triage_status: "triaged",
    written_at: ago(19),
    dashboard_url: "/incident/CHAIN-DEMO-api-gateway-017",
    chain: {
      alert_count: 3,
      primary_entity: "api-gw-prod-2",
      first_time: ago(144),
      last_time: ago(22),
      tactic_sequence: ["Reconnaissance", "Initial Access", "Discovery"],
      disposition: "ambiguous",
      risk_score: 78,
      surfaced: true,
      entities: [
        entity("api-gw-prod-2", "host", 78, { hostname: ["api-gw-prod-2"] }),
        entity("198.51.100.24", "ip", 70, { ip: ["198.51.100.24"] }),
        entity("svc-catalog", "user", 45, { username: ["svc-catalog"] }),
      ],
      alerts: [
        alert("demo-101", 144, "Medium", "High-rate endpoint enumeration", ["api-gw-prod-2", "198.51.100.24"], "Reconnaissance", { uid: "T1595.002", name: "Vulnerability Scanning" }),
        alert("demo-102", 57, "High", "Authentication bypass signature matched", ["api-gw-prod-2", "198.51.100.24"], "Initial Access", { uid: "T1190", name: "Exploit Public-Facing Application" }),
        alert("demo-103", 22, "High", "Service account queried application metadata", ["api-gw-prod-2", "svc-catalog"], "Discovery", { uid: "T1087", name: "Account Discovery" }),
      ],
    },
    triage: {
      verdict: "Needs Escalation",
      confidence_score: 68,
      mitre_attack_techniques: ["T1595.002", "T1190", "T1087"],
      critical_evidence_fields: ["source.ip", "url.path", "user.name"],
      investigation_chain_of_thought: "The scanning and bypass signature share a source and target. The later service-account activity may be related, but the preview evidence does not establish process or session continuity.",
      remediation_recommendations: ["Review gateway request bodies and response codes.", "Confirm whether svc-catalog activity matches its deployment schedule."],
      validation: { original_confidence: 68, notes: ["Relationship to the service-account event remains unproven."] },
      model_id: "preview/sample-model",
      generated_at: ago(20),
    },
    report_markdown: "# Attack Chain CHAIN-DEMO-api-gateway-017\n\n> UI preview only.\n\n## Decision\n\n**Needs Escalation**. Review gateway request evidence and service-account activity before containment.\n",
  },
  {
    cluster_id: "CHAIN-DEMO-build-runner-008",
    triage_status: "pending",
    written_at: ago(41),
    dashboard_url: "/incident/CHAIN-DEMO-build-runner-008",
    chain: {
      alert_count: 2,
      primary_entity: "runner-ci-08",
      first_time: ago(71),
      last_time: ago(43),
      tactic_sequence: ["Execution", "Discovery"],
      disposition: "forming",
      risk_score: 36,
      surfaced: false,
      entities: [
        entity("runner-ci-08", "host", 36, { hostname: ["runner-ci-08"] }),
        entity("ci-bot", "user", 21, { username: ["ci-bot"] }),
      ],
      alerts: [
        alert("demo-201", 71, "Low", "Shell spawned by build worker", ["runner-ci-08", "ci-bot"], "Execution", { uid: "T1059.004", name: "Unix Shell" }),
        alert("demo-202", 43, "Medium", "Environment discovery command", ["runner-ci-08", "ci-bot"], "Discovery", { uid: "T1082", name: "System Information Discovery" }),
      ],
    },
    triage: null,
    report_markdown: "",
  },
];

let aiSettings = {
  provider: "local",
  local_model: "preview/sample-model",
  local_base_url: "http://localhost:11434",
  cloud_model: "",
  triage_scope: "surfaced",
  timeout_seconds: 120,
  model_id: "preview/sample-model",
};

function maxSeverity(alerts) {
  const order = ["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal"];
  return alerts.reduce((best, item) => order.indexOf(item.severity) > order.indexOf(best) ? item.severity : best, "Unknown");
}

function brief(doc) {
  const chain = doc.chain;
  return {
    cluster_id: doc.cluster_id,
    triage_status: doc.triage_status,
    verdict: doc.triage?.verdict || null,
    confidence_score: doc.triage?.confidence_score ?? null,
    mitre_attack_techniques: doc.triage?.mitre_attack_techniques || [],
    alert_count: chain.alert_count,
    primary_entity: chain.primary_entity,
    first_time: chain.first_time,
    last_time: chain.last_time,
    tactic_sequence: chain.tactic_sequence,
    disposition: chain.disposition,
    risk_score: chain.risk_score,
    surfaced: chain.surfaced,
    max_severity: maxSeverity(chain.alerts),
    dashboard_url: doc.dashboard_url,
    written_at: doc.written_at,
    incident_title: chain.alerts.slice().sort((a, b) =>
      ["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal"].indexOf(b.severity) -
      ["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal"].indexOf(a.severity))[0]?.title || "Security Investigation",
    search_text: chain.alerts.map((item) =>
      `${item.title} ${item.host} ${item.user} ${item.process} ${item.command} ` +
      `${(item.techniques || []).map((technique) => `${technique.uid} ${technique.name}`).join(" ")}`).join(" "),
  };
}

function findDocument(id) {
  const doc = documents.find((item) => item.cluster_id === id);
  if (!doc) throw new Error(`no preview results for cluster '${id}'`);
  return doc;
}

export async function getSetup() {
  return { managed: false, needs_setup: false, preview: true };
}

export async function getStatus() {
  return {
    engine: { mode: "UI preview", results: documents.length, clusters: documents.length, surfaced: 2, entities: 9 },
    siem: { type: "preview", host: "Sample data", alert_index: "not connected", configured: true, reachable: true },
    ai: { provider: "preview", model_id: "sample verdicts", triage_available: true, reachable: true },
    kb: { loaded: true, techniques: 684, attack_version: "preview" },
    preview: true,
  };
}

export async function getClusters(surfacedOnly = false) {
  const clusters = documents.map(brief).filter((item) => !surfacedOnly || item.surfaced);
  return { clusters: copy(clusters), total: clusters.length };
}

export async function getCluster(id) {
  return copy(findDocument(id));
}

export async function getTimeline(id) {
  const doc = findDocument(id);
  const preferredOrder = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", "Untagged"];
  const lanes = [...new Set(doc.chain.alerts.map((item) => item.tactics[0] || "Untagged"))]
    .sort((a, b) => preferredOrder.indexOf(a) - preferredOrder.indexOf(b));
  return {
    cluster_id: id,
    lanes,
    events: doc.chain.alerts.map((item) => ({ ...copy(item), lane: item.tactics[0] || "Untagged", lane_index: lanes.indexOf(item.tactics[0] || "Untagged") })),
    first_time: doc.chain.first_time,
    last_time: doc.chain.last_time,
    tactic_sequence: copy(doc.chain.tactic_sequence),
    disposition: doc.chain.disposition,
  };
}

export async function getGraph(id) {
  const doc = findDocument(id);
  const nodes = doc.chain.entities.map((item) => ({ ...copy(item), id: item.name, alerts: [], is_primary: item.name === doc.chain.primary_entity }));
  const byId = new Map(nodes.map((item) => [item.id, item]));
  const links = [];
  for (const event of doc.chain.alerts) {
    for (const name of event.entities) {
      byId.get(name)?.alerts.push({ uid: event.uid, title: event.title, time_dt: event.time_dt, severity: event.severity });
    }
    for (let left = 0; left < event.entities.length; left += 1) {
      for (let right = left + 1; right < event.entities.length; right += 1) {
        links.push({ source: event.entities[left], target: event.entities[right], alert_uid: event.uid, title: event.title, time_dt: event.time_dt, severity: event.severity, techniques: copy(event.techniques) });
      }
    }
  }
  const chainNodes = [];
  const chainLinks = [];
  let previous = "";
  for (const item of nodes) {
    chainNodes.push({ id: `${item.domain}:${item.id}`, label: item.id,
      kind: item.domain, entity_id: item.id, risk_score: item.risk_score });
  }
  for (const [index, event] of doc.chain.alerts.entries()) {
    const eventId = `event:${event.uid}`;
    chainNodes.push({ id: eventId, label: event.title, kind: "event",
      alert_uid: event.uid, severity: event.severity, time_dt: event.time_dt, index });
    if (previous) chainLinks.push({ source: previous, target: eventId,
      relationship: "then", alert_uid: event.uid });
    previous = eventId;
    for (const name of event.entities) {
      const entityNode = nodes.find((item) => item.id === name);
      chainLinks.push({ source: `${entityNode?.domain || "entity"}:${name}`,
        target: eventId, relationship: "observed", alert_uid: event.uid });
    }
    for (const technique of event.techniques) {
      const techniqueId = `technique:${technique.uid}`;
      if (!chainNodes.some((item) => item.id === techniqueId)) {
        chainNodes.push({ id: techniqueId, label: technique.name,
          kind: "technique", technique_uid: technique.uid });
      }
      chainLinks.push({ source: eventId, target: techniqueId,
        relationship: "uses", alert_uid: event.uid });
    }
  }
  return { cluster_id: id, nodes, links,
    chain_nodes: chainNodes, chain_links: chainLinks };
}

const techniqueDescriptions = {
  "T1059.001": "Adversaries may abuse PowerShell commands and scripts for execution.",
  "T1003": "Adversaries may attempt to dump credentials to obtain account login material.",
};

export async function getTechniques(ids) {
  const found = new Map();
  for (const doc of documents) {
    for (const event of doc.chain.alerts) {
      for (const technique of event.techniques) found.set(technique.uid, technique.name);
    }
  }
  return { techniques: ids.filter((uid) => found.has(uid)).map((uid) => ({
    uid, name: found.get(uid),
    description: techniqueDescriptions[uid] || "Official MITRE ATT&CK technique metadata.",
    url: `https://attack.mitre.org/techniques/${uid.replace(".", "/")}/`,
  })) };
}

export async function getAiSettings() {
  return copy(aiSettings);
}

export async function putAiSettings(changes) {
  aiSettings = { ...aiSettings, ...changes };
  const provider = aiSettings.provider || "local";
  aiSettings.model_id = provider === "local"
    ? (aiSettings.local_model || "preview/sample-model")
    : `${provider}/${aiSettings.cloud_model || "preview-model"}`;
  return copy(aiSettings);
}

export async function putSiemSettings(settings) {
  return { host: settings.host || "Sample data", alert_index: settings.alert_index || "not connected", preview: true };
}

export async function validateAi(overrides = {}) {
  const model = overrides.provider === "local"
    ? overrides.local_model || aiSettings.local_model
    : `${overrides.provider}/${overrides.cloud_model || "preview-model"}`;
  return { ok: true, model_id: model, latency_ms: 0, preview: true };
}

export async function retriage(id) {
  return getCluster(id);
}
