"""Defender XDR adapter: Graph ``alerts_v2`` -> OCSF Detection Finding.

``providerAlertId`` and ``serviceSource`` are surfaced as first-class
provenance on the envelope (see the connector), not buried in ``unmapped``.
"""

from __future__ import annotations

from typing import Any

from engine.ingest import RawRecord
from engine.normalize.adapters.base import MappedAdapter
from engine.normalize.tactics import normalize_tactics

_T = "#microsoft.graph.security."


def derive_evidence(evidence: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in evidence if isinstance(evidence, list) else []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("@odata.type", "")).removeprefix(_T)
        if kind == "deviceEvidence":
            out.setdefault("device_name", item.get("deviceDnsName"))
            out.setdefault("device_id", item.get("mdeDeviceId") or item.get("azureAdDeviceId"))
            out.setdefault("os", item.get("osPlatform"))
        elif kind == "userEvidence":
            acct = item.get("userAccount") or {}
            out.setdefault("user", acct.get("accountName") or acct.get("userPrincipalName"))
            out.setdefault("user_domain", acct.get("domainName"))
            out.setdefault("user_id", acct.get("azureAdUserId") or acct.get("userSid"))
            out.setdefault("upn", acct.get("userPrincipalName"))
        elif kind == "ipEvidence":
            out.setdefault("ip", item.get("ipAddress"))
        elif kind == "processEvidence":
            out.setdefault("process_id", item.get("processId"))
            out.setdefault("cmd_line", item.get("processCommandLine"))
            image = item.get("imageFile") or {}
            out.setdefault("process_name", image.get("fileName"))
    return {k: v for k, v in out.items() if v not in (None, "")}


class DefenderXdrAdapter(MappedAdapter):
    name = "defender_xdr"
    mapping_file = "defender_xdr.yaml"

    def event_of(self, record: RawRecord) -> dict:
        p = record.payload
        derived = derive_evidence(p.get("evidence"))
        derived["tactics"] = (
            normalize_tactics([p["category"]]) if p.get("category") else [])
        derived["techniques"] = [str(t) for t in p.get("mitreTechniques") or []]
        return {**p, "_derived": derived}

    def uid_fallback(self, record: RawRecord) -> str:
        return str(record.payload.get("id", ""))
