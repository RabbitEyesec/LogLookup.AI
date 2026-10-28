"""Microsoft Sentinel adapter: SecurityAlert rows -> OCSF Detection Finding.

``Entities`` and ``ExtendedProperties`` arrive as JSON-encoded strings. They
are parsed into a derived view used for mapping; the original strings stay
untouched in the preserved raw event, and an unparseable value simply yields
no derived fields (never a dropped alert).
"""

from __future__ import annotations

import json
from typing import Any

from engine.ingest import RawRecord
from engine.normalize.adapters.base import MappedAdapter
from engine.normalize.tactics import normalize_tactics


def _json_or(value: Any, default: Any) -> Any:
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default


def _split_csv(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        parsed = _json_or(value, None)
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
        return [p.strip() for p in value.split(",") if p.strip()]
    return []


def derive_entities(entities: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for ent in entities if isinstance(entities, list) else []:
        if not isinstance(ent, dict):
            continue
        kind = str(ent.get("Type", "")).lower()
        if kind == "host":
            name = ent.get("HostName") or ent.get("NetBiosName")
            domain = ent.get("DnsDomain") or ent.get("NTDomain")
            out.setdefault("host", name)
            out.setdefault("host_domain", domain)
            out.setdefault("host_id", ent.get("AzureID") or ent.get("OMSAgentID"))
            out.setdefault("os", ent.get("OSFamily"))
        elif kind == "account":
            out.setdefault("user", ent.get("Name"))
            out.setdefault("user_domain", ent.get("NTDomain") or ent.get("UPNSuffix"))
            out.setdefault("user_id", ent.get("AadUserId") or ent.get("Sid"))
        elif kind == "ip":
            out.setdefault("ip", ent.get("Address"))
        elif kind == "process":
            out.setdefault("process_id", ent.get("ProcessId"))
            out.setdefault("cmd_line", ent.get("CommandLine"))
            image = ent.get("ImageFile") or {}
            out.setdefault("process_name", image.get("Name") if isinstance(image, dict) else None)
    return {k: v for k, v in out.items() if v not in (None, "")}


class SentinelAdapter(MappedAdapter):
    name = "sentinel"
    mapping_file = "sentinel.yaml"

    def event_of(self, record: RawRecord) -> dict:
        p = record.payload
        derived = derive_entities(_json_or(p.get("Entities"), []))
        derived["tactics"] = normalize_tactics(_split_csv(p.get("Tactics")))
        derived["techniques"] = _split_csv(p.get("Techniques"))
        ext = _json_or(p.get("ExtendedProperties"), {})
        if isinstance(ext, dict):
            derived["extended"] = ext
        if p.get("CompromisedEntity") and "host" not in derived:
            derived["host"] = p["CompromisedEntity"]
        return {**p, "_derived": derived}

    def uid_fallback(self, record: RawRecord) -> str:
        return str(record.payload.get("SystemAlertId", ""))
