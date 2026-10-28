"""Evidence payload: a formed cluster -> bounded, flattened, XML-delimited.

The correlation -> LLM seam (Build Reference 5.2): the model reads a clean,
flattened payload wrapped in XML delimiters — never raw nested JSON. The
payload also carries the field index used by the post-generation validator
(every cited evidence field must exist in the raw logs) and the RAG query
text extracted from the cluster's indicators.

Everything in the payload comes from the cluster's own alerts and resolved
entities. No enrichment, no lookups, no facts from anywhere else.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from xml.sax.saxutils import escape

import msgspec

from engine.correlate.engine import Cluster, CorrelationEngine
from engine.normalize.ocsf import NormalizedAlert

logger = logging.getLogger(__name__)

#: Bound on a single flattened value; long command lines stay useful, blobs
#: do not.
MAX_VALUE_CHARS = 300
#: Bound on flattened fields per alert (deterministic: keys sorted first).
MAX_FIELDS_PER_ALERT = 60

TRUNCATION_NOTE = "[payload truncated to fit the evidence budget]"


@dataclass
class EvidencePayload:
    """What the reasoner sends to the model, plus validator context."""

    cluster_id: str
    xml: str
    rag_query: str
    #: dotted log-field keys present in the evidence (validator ground truth)
    evidence_fields: set[str] = field(default_factory=set)
    #: field key -> [(alert_uid, rendered value), ...] for citations/report
    field_values: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    truncated: bool = False
    #: evidence references (``SRC:<connection>:<kind>:<id>``) supplied to the
    #: model - the only references it may cite (validator ground truth)
    evidence_refs: set[str] = field(default_factory=set)
    #: provider -> per-alert field cap applied to fit the budget
    source_field_caps: dict[str, int] = field(default_factory=dict)

    @property
    def char_count(self) -> int:
        return len(self.xml)


def flatten(value: Any, prefix: str = "") -> dict[str, str]:
    """Flatten nested dicts/lists into dotted-key -> rendered-value pairs.

    Lists of scalars render as one comma-joined value under the list key
    (arrays-stay-arrays is preserved upstream; this is display only).
    """
    flat: dict[str, str] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flat.update(flatten(item, path))
        return flat
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            flat[prefix] = ", ".join(_render(item) for item in value)
        else:
            for index, item in enumerate(value):
                flat.update(flatten(item, f"{prefix}[{index}]"))
        return flat
    if prefix:
        flat[prefix] = _render(value)
    return flat


def _render(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if len(text) > MAX_VALUE_CHARS:
        text = text[:MAX_VALUE_CHARS] + "…"
    return text


def _raw_event_of(alert: NormalizedAlert) -> Optional[dict[str, Any]]:
    """Decode the byte-for-byte preserved source event, if it is JSON."""
    raw = alert.unmapped.get("raw")
    if not isinstance(raw, str):
        return None
    try:
        decoded = msgspec.json.decode(raw.encode("utf-8"))
    except msgspec.DecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def flatten_alert(alert: NormalizedAlert,
                  cap: int = MAX_FIELDS_PER_ALERT) -> dict[str, str]:
    """The alert's evidence fields: the raw source event, flattened.

    The raw event is the forensic ground truth the analyst can verify
    against. When the raw event is not JSON (e.g. a CSV line), fall back to
    the normalized OCSF fields (minus the envelope/unmapped noise).
    """
    raw_event = _raw_event_of(alert)
    if raw_event is not None:
        flat = flatten(raw_event)
    else:
        tree = msgspec.to_builtins(alert)
        tree.pop("unmapped", None)
        for envelope_key in ("class_uid", "class_name", "category_uid",
                             "category_name", "activity_id", "type_uid"):
            tree.pop(envelope_key, None)
        flat = flatten(tree)
    if len(flat) > cap:
        flat = dict(sorted(flat.items())[:cap])
    return flat


def _alert_attack_tags(alert: NormalizedAlert) -> list[str]:
    tags = []
    for attack in alert.finding_info.attacks:
        tactic = attack.tactic.name if attack.tactic else None
        technique_id = attack.technique.uid if attack.technique else None
        technique_name = attack.technique.name if attack.technique else None
        label = " / ".join(p for p in (tactic, technique_id, technique_name) if p)
        if label:
            tags.append(label)
    return tags


def build_rag_query(engine: CorrelationEngine, cluster: Cluster) -> str:
    """Indicator text for ATT&CK retrieval: titles, tags, processes, IPs."""
    parts: list[str] = []
    for alert in engine.alerts_of(cluster):
        parts.append(alert.finding_info.title)
        if alert.finding_info.desc:
            parts.append(alert.finding_info.desc)
        if alert.message:
            parts.append(alert.message)
        parts.extend(_alert_attack_tags(alert))
        actor = alert.actor
        if actor and actor.process:
            if actor.process.name:
                parts.append(actor.process.name)
            if actor.process.cmd_line:
                parts.append(actor.process.cmd_line)
    seen: set[str] = set()
    unique = []
    for part in parts:
        text = part.strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            unique.append(text)
    return "\n".join(unique)


MIN_FIELDS_PER_ALERT = 6


def _provider_of(alert: NormalizedAlert) -> str:
    return (alert.unmapped.get("source") or {}).get("provider") or "legacy"


def build_payload(
    engine: CorrelationEngine,
    cluster: Cluster,
    *,
    max_chars: int = 24000,
    context: Optional[dict[str, Any]] = None,
) -> EvidencePayload:
    """Package one formed attack chain for the reasoning layer.

    v2: every alert carries its source and a citable ``evidence_ref``; a
    ``<source_coverage>`` block states which sources contributed (and which
    did not); identity context (sign-ins, directory changes) is included as
    context, never as detections. When the evidence budget is exceeded the
    per-alert field cap is reduced *per source* - the noisiest source gives
    up detail first - instead of truncating whichever alerts happen to be
    last.
    """
    alerts = engine.alerts_of(cluster)
    payload = EvidencePayload(
        cluster_id=cluster.cluster_id,
        xml="",
        rag_query=build_rag_query(engine, cluster),
    )
    providers = sorted({_provider_of(a) for a in alerts})
    caps = {p: MAX_FIELDS_PER_ALERT for p in providers}

    def render(caps: dict[str, int]) -> tuple[str, dict[str, int]]:
        sizes = {p: 0 for p in providers}
        sections: list[str] = []
        for alert in alerts:
            provider = _provider_of(alert)
            flat = flatten_alert(alert, caps[provider])
            src = alert.unmapped.get("source") or {}
            attrs = ""
            if src:
                attrs = (f' source="{escape(provider)}" '
                         f'connection="{escape(str(src.get("connection_id", "")))}" '
                         f'evidence_ref="{escape(str(src.get("evidence_ref", "")))}"')
            lines = [
                f'  <alert uid="{escape(alert.uid)}" '
                f'time="{escape(alert.time_dt)}" '
                f'severity="{escape(alert.severity_label())}"{attrs}>',
                f"    title: {escape(alert.finding_info.title)}",
            ]
            entities = sorted(
                entity.display_name
                for entity in engine.resolution_of(alert.uid).entities
            )
            lines.append(f"    resolved_entities: {escape(', '.join(entities))}")
            for key in sorted(flat):
                lines.append(f"    {escape(key)}: {escape(flat[key])}")
            lines.append("  </alert>")
            text = "\n".join(lines)
            sizes[provider] += len(text)
            sections.append(text)
        return "\n".join(sections), sizes

    ti_lines: list[str] = []
    for alert in alerts:
        flat_all = flatten_alert(alert)
        for key, value in flat_all.items():
            payload.evidence_fields.add(key)
            payload.field_values.setdefault(key, []).append((alert.uid, value))
        ref = (alert.unmapped.get("source") or {}).get("evidence_ref")
        if ref:
            payload.evidence_refs.add(ref)
        for tag in _alert_attack_tags(alert):
            line = f"  {escape(alert.uid)}: pre-tagged ATT&CK {escape(tag)}"
            if line not in ti_lines:
                ti_lines.append(line)

    header = (
        f'  cluster_id: {escape(cluster.cluster_id)}\n'
        f"  alert_count: {cluster.alert_count}\n"
        f"  window: {escape(_ms_iso(cluster.first_time_ms))} .. "
        f"{escape(_ms_iso(cluster.last_time_ms))}\n"
        f"  tactic_sequence: "
        f"{escape(' -> '.join(cluster.tactic_sequence) or '(none tagged)')}\n"
        f"  deterministic_disposition: {escape(cluster.disposition)}\n"
        f"  cumulative_entity_risk: {cluster.risk_score}"
    )

    asset_lines = []
    for entity_uid in sorted(cluster.entity_uids):
        entity = engine.resolver.get(entity_uid)
        if entity is None:
            continue
        identifiers = "; ".join(
            f"{kind}={', '.join(sorted(values))}"
            for kind, values in sorted(entity.identifiers.items())
        )
        asset_lines.append(
            f"  <entity domain=\"{escape(entity.domain)}\" "
            f"name=\"{escape(entity.display_name)}\" "
            f"risk_score=\"{entity.risk_score}\">"
            f"{escape(identifiers)}</entity>"
        )

    coverage_lines = [
        f'  <source provider="{escape(s["provider"])}" '
        f'connection="{escape(s["connection_id"])}" '
        f'alerts="{s["alert_count"]}"/>'
        for s in engine.cluster_sources(cluster)
        if s["provider"] != "legacy"
    ]
    breakdown = cluster.risk_breakdown or {}
    if breakdown:
        coverage_lines.append(
            "  risk_components: "
            + escape(", ".join(
                f"{k}={breakdown[k]}" for k in (
                    "severity_evidence", "independent_source_confirmation",
                    "documented_benign_or_conflicting_context") if k in breakdown)))
    identity_lines = []
    identity = (context or {}).get("identity") or {}
    for obs in (identity.get("observations") or [])[:30]:
        attrs = obs.get("attributes") or {}
        brief = "; ".join(f"{k}={attrs[k]}" for k in (
            "app", "ip", "result", "failure_reason", "activity", "category",
            "conditional_access_status") if attrs.get(k) not in (None, ""))
        identity_lines.append(
            f'  <observation type="{escape(str(obs.get("type")))}" '
            f'principal="{escape(str(obs.get("principal")))}" '
            f'time="{escape(str(obs.get("event_time")))}" '
            f'evidence_ref="{escape(str(obs.get("source_ref")))}">'
            f"{escape(brief)}</observation>")
        if obs.get("source_ref"):
            payload.evidence_refs.add(str(obs["source_ref"]))

    def assemble(body: str) -> str:
        parts = [
            "<alert_cluster>\n" + header + "\n" + body + "\n</alert_cluster>",
            "<threat_intelligence_enrichment>\n"
            + ("\n".join(ti_lines) if ti_lines
               else "  (no pre-tagged threat intelligence on these alerts)")
            + "\n</threat_intelligence_enrichment>",
            "<asset_context>\n"
            + ("\n".join(asset_lines) if asset_lines else "  (no resolved entities)")
            + "\n</asset_context>",
        ]
        if coverage_lines:
            parts.append("<source_coverage>\n" + "\n".join(coverage_lines)
                         + "\n</source_coverage>")
        if identity_lines or identity.get("principals"):
            parts.append(
                "<identity_context note=\"supporting observations, not detections\">\n"
                + ("\n".join(identity_lines) if identity_lines
                   else "  (no linked sign-in or directory records)")
                + "\n</identity_context>")
        return "\n".join(parts)

    body, sizes = render(caps)
    xml = assemble(body)
    # Budget fit: the source with the largest footprint gives up detail first.
    guard = 0
    while len(xml) > max_chars and guard < 24:
        guard += 1
        reducible = [p for p in providers if caps[p] > MIN_FIELDS_PER_ALERT]
        if not reducible:
            break
        victim = max(reducible, key=lambda p: (sizes[p], p))
        caps[victim] = max(MIN_FIELDS_PER_ALERT, caps[victim] // 2)
        body, sizes = render(caps)
        xml = assemble(body)
    payload.source_field_caps = {p: c for p, c in caps.items()
                                 if c < MAX_FIELDS_PER_ALERT}
    if payload.source_field_caps:
        payload.truncated = True
    if len(xml) > max_chars:
        xml = xml[: max_chars - len(TRUNCATION_NOTE) - 1] + "\n" + TRUNCATION_NOTE
        payload.truncated = True
        logger.warning(
            "evidence payload for %s truncated to %d chars",
            cluster.cluster_id, max_chars,
        )
    payload.xml = xml
    return payload


def _ms_iso(epoch_ms: int) -> str:
    from engine.normalize.timeutil import ms_to_iso

    return ms_to_iso(epoch_ms)
