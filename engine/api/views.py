"""Dashboard view shapers pure functions over chain documents.

Both views answer a different question over the SAME data (Master
Specification 6.1):

- 2D MITRE timeline ("in what order?") tactics as lanes in kill-chain
  order, alerts placed by event time;
- 3D force graph ("how does it connect?") resolved entities as nodes,
  alerts as edges; shared pivot points become visible structure.

Nothing here recomputes correlation or asks the AI anything: a chain
document in, a render-ready shape out.
"""

from __future__ import annotations

from itertools import combinations
import re
from typing import Any

from engine.correlate.chains import TACTIC_ORDER

UNTAGGED_LANE = "Untagged"

_LANE_RANK = {name: rank for rank, (_uid, name) in enumerate(TACTIC_ORDER)}

_SEVERITY_RANK = {
    "Unknown": 0, "Informational": 1, "Low": 2, "Medium": 3,
    "High": 4, "Critical": 5, "Fatal": 6,
}


def incident_title(chain: dict[str, Any]) -> str:
    """Short analyst-facing name derived only from the correlated evidence."""
    alerts = chain.get("alerts", [])
    techniques = {
        str(t.get("name") or "").lower()
        for alert in alerts for t in alert.get("techniques", [])
    }
    tactics = {str(t).lower() for alert in alerts for t in alert.get("tactics", [])}
    if "powershell" in techniques and "credential access" in tactics:
        return "PowerShell Credential Theft"
    if "powershell" in techniques and "persistence" in tactics:
        return "PowerShell Persistence"
    ranked = sorted(
        alerts,
        key=lambda alert: (
            _SEVERITY_RANK.get(alert.get("severity", "Unknown"), 0),
            alert.get("time", 0),
        ),
        reverse=True,
    )
    if ranked and ranked[0].get("title"):
        return str(ranked[0]["title"])
    return "Security Investigation"


def _lane_of(alert: dict[str, Any]) -> str:
    """The alert's timeline lane: its furthest kill-chain tactic."""
    best_name = None
    best_rank = -1
    for tactic in alert.get("tactics", ()):
        rank = _LANE_RANK.get(tactic.strip().lower(), -1)
        if rank > best_rank:
            best_rank = rank
            best_name = tactic
    return best_name if best_name is not None else UNTAGGED_LANE


def cluster_brief(doc: dict[str, Any]) -> dict[str, Any]:
    """Stream-row view of one chain document (the alert stream list)."""
    chain = doc.get("chain", {})
    triage = doc.get("triage")
    return {
        "cluster_id": doc.get("cluster_id"),
        "incident_title": incident_title(chain),
        "triage_status": doc.get("triage_status"),
        "verdict": triage.get("verdict") if triage else None,
        "confidence_score": triage.get("confidence_score") if triage else None,
        "mitre_attack_techniques":
            triage.get("mitre_attack_techniques", []) if triage else [],
        "alert_count": chain.get("alert_count", 0),
        "primary_entity": chain.get("primary_entity", ""),
        "first_time": chain.get("first_time"),
        "last_time": chain.get("last_time"),
        "tactic_sequence": chain.get("tactic_sequence", []),
        "disposition": chain.get("disposition"),
        "risk_score": chain.get("risk_score", 0),
        "surfaced": chain.get("surfaced", False),
        "max_severity": _max_severity(chain.get("alerts", [])),
        "dashboard_url": doc.get("dashboard_url"),
        "written_at": doc.get("written_at"),
        "search_text": " ".join(
            str(value) for alert in chain.get("alerts", []) for value in (
                alert.get("title", ""), alert.get("description", ""),
                alert.get("rule", ""), alert.get("host", ""),
                alert.get("user", ""), alert.get("process", ""),
                alert.get("command", ""), alert.get("source_ip", ""),
                alert.get("destination_ip", ""),
                " ".join(str(t.get("uid", "")) for t in alert.get("techniques", [])),
            ) if value
        ),
    }


def _max_severity(alerts: list[dict[str, Any]]) -> str:
    best = "Unknown"
    for alert in alerts:
        severity = alert.get("severity", "Unknown")
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(best, 0):
            best = severity
    return best


def timeline_view(doc: dict[str, Any]) -> dict[str, Any]:
    """2D MITRE timeline: kill chain ordered lanes, alerts by event time."""
    chain = doc.get("chain", {})
    alerts = chain.get("alerts", [])

    lanes_present: list[str] = []
    events = []
    for alert in alerts:
        lane = _lane_of(alert)
        if lane not in lanes_present:
            lanes_present.append(lane)
        events.append({
            "uid": alert.get("uid"),
            "time": alert.get("time"),
            "time_dt": alert.get("time_dt"),
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "entities": alert.get("entities", []),
            "tactics": alert.get("tactics", []),
            "techniques": alert.get("techniques", []),
            "lane": lane,
        })

    def lane_sort_key(name: str) -> tuple[int, int]:
        rank = _LANE_RANK.get(name.strip().lower())
        return (0, rank) if rank is not None else (1, 0)

    lanes = sorted(lanes_present, key=lane_sort_key)
    lane_index = {name: index for index, name in enumerate(lanes)}
    for event in events:
        event["lane_index"] = lane_index[event["lane"]]

    return {
        "cluster_id": doc.get("cluster_id"),
        "lanes": lanes,
        "events": events,
        "first_time": chain.get("first_time"),
        "last_time": chain.get("last_time"),
        "tactic_sequence": chain.get("tactic_sequence", []),
        "disposition": chain.get("disposition"),
    }


def graph_view(doc: dict[str, Any]) -> dict[str, Any]:
    """3D force graph: entities as nodes, alerts as edges between them.

    An alert touching N>=2 entities becomes N-choose-2 edges (small N —
    these are resolved entities on one alert, not the alert universe).
    Alerts touching a single entity appear on that node's alert list.
    """
    chain = doc.get("chain", {})
    alerts = chain.get("alerts", [])
    entities = chain.get("entities", [])

    nodes: dict[str, dict[str, Any]] = {}
    for entity in entities:
        name = entity.get("name", "")
        if not name:
            continue
        nodes[name] = {
            "id": name,
            "domain": entity.get("domain", "unknown"),
            "risk_score": entity.get("risk_score", 0),
            "identifiers": entity.get("identifiers", {}),
            "alerts": [],
            "is_primary": name == chain.get("primary_entity"),
        }

    links = []
    for alert in alerts:
        touched = [name for name in alert.get("entities", []) if name]
        for name in touched:
            # Entities can be flushed from live state; keep the graph whole.
            node = nodes.setdefault(name, {
                "id": name, "domain": "unknown", "risk_score": 0,
                "identifiers": {}, "alerts": [],
                "is_primary": name == chain.get("primary_entity"),
            })
            node["alerts"].append({
                "uid": alert.get("uid"),
                "title": alert.get("title"),
                "time_dt": alert.get("time_dt"),
                "severity": alert.get("severity"),
            })
        for source, target in combinations(sorted(set(touched)), 2):
            links.append({
                "source": source,
                "target": target,
                "alert_uid": alert.get("uid"),
                "title": alert.get("title"),
                "time_dt": alert.get("time_dt"),
                "severity": alert.get("severity"),
                "techniques": alert.get("techniques", []),
            })

    chain_nodes, chain_links = _attack_chain_graph(chain, nodes)
    return {
        "cluster_id": doc.get("cluster_id"),
        "nodes": list(nodes.values()),
        "links": links,
        "chain_nodes": chain_nodes,
        "chain_links": chain_links,
    }


def _attack_chain_graph(
    chain: dict[str, Any], entity_nodes: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Event-centric attack chain for the 2D analyst graph.

    Nodes are added only when the source evidence contains the value. This
    keeps the graph rich without fabricating missing process or persistence
    details.
    """
    nodes: dict[str, dict[str, Any]] = {}
    links: list[dict[str, Any]] = []

    def add(node_id: str, label: str, kind: str, **extra: Any) -> str:
        key = f"{kind}:{node_id}"
        nodes.setdefault(key, {"id": key, "label": label, "kind": kind, **extra})
        return key

    for entity in entity_nodes.values():
        add(
            entity["id"], entity["id"], entity.get("domain", "entity"),
            risk_score=entity.get("risk_score", 0),
            entity_id=entity["id"],
        )

    previous_event = ""
    for index, alert in enumerate(chain.get("alerts", [])):
        uid = str(alert.get("uid") or f"event-{index}")
        event_id = add(
            uid, str(alert.get("title") or uid), "event",
            alert_uid=uid, severity=alert.get("severity"),
            time_dt=alert.get("time_dt"), index=index,
        )
        if previous_event:
            links.append({"source": previous_event, "target": event_id,
                          "relationship": "then", "alert_uid": uid})
        previous_event = event_id
        for entity_name in alert.get("entities", []):
            entity = entity_nodes.get(entity_name, {})
            entity_id = add(
                entity_name, entity_name, entity.get("domain", "entity"),
                entity_id=entity_name,
                risk_score=entity.get("risk_score", 0),
            )
            links.append({"source": entity_id, "target": event_id,
                          "relationship": "observed", "alert_uid": uid})
        for technique in alert.get("techniques", []):
            technique_uid = str(technique.get("uid") or "").strip()
            if not technique_uid:
                continue
            technique_id = add(
                technique_uid,
                str(technique.get("name") or technique_uid),
                "technique", technique_uid=technique_uid,
            )
            links.append({"source": event_id, "target": technique_id,
                          "relationship": "uses", "alert_uid": uid})
        flat = _flatten(alert.get("evidence") or {})
        artifact_specs = (
            ("process", ("process.name", "process.executable", "process.parent.name")),
            ("parent_process", ("process.parent.name", "parent.process.name")),
            ("powershell", ("powershell",)),
            ("encoded_command", ("encodedcommand", "encoded_command")),
            ("downloaded_file", ("file.name", "file.path", "url.full")),
            ("registry", ("registry.path", "registry.key", "registry.value")),
            ("scheduled_task", ("task.name", "scheduled_task")),
            ("service", ("service.name", "winlog.event_data.servicename")),
            ("network", ("destination.ip", "destination.domain", "source.ip")),
        )
        command_line = _first_flat(flat, ("process.command_line", "command_line", "cmd_line"))
        if command_line:
            command_kind = "encoded_command" if re.search(
                r"(?i)(?:-enc(?:odedcommand)?\b|frombase64string)", command_line
            ) else "command"
            command_id = add(command_line, command_line, command_kind, value=command_line)
            links.append({"source": event_id, "target": command_id,
                          "relationship": "executes", "alert_uid": uid})
        for kind, suffixes in artifact_specs:
            value = _first_flat(flat, suffixes)
            if not value:
                continue
            actual_kind = "powershell" if kind == "process" and "powershell" in value.lower() else kind
            artifact_id = add(value, value, actual_kind, value=value)
            links.append({"source": event_id, "target": artifact_id,
                          "relationship": "contains", "alert_uid": uid})
    return list(nodes.values()), links


def _flatten(value: Any, prefix: str = "") -> dict[str, str]:
    result: dict[str, str] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.update(_flatten(child, f"{prefix}.{index}"))
    elif value not in (None, ""):
        result[prefix.lower()] = str(value)
    return result


def _first_flat(flat: dict[str, str], suffixes: tuple[str, ...]) -> str:
    for suffix in suffixes:
        needle = suffix.lower()
        for path, value in flat.items():
            if path == needle or path.endswith(f".{needle}"):
                return value
    return ""
