"""Identity enrichment: join Entra context to an investigation.

Joins are strict: a context record attaches to a chain only through a
tenant/scope-bound principal key (UPN/email) seen on one of the chain's
alerts, inside the chain's time window plus a bounded margin. Display
names, recycled IPs and geography are never join keys. Context is reported
beside the chain - it does not add to the alert count.
"""

from __future__ import annotations

from typing import Any

from engine.store.ledger import Ledger

#: how far outside the chain's own window sign-ins/changes are considered
CONTEXT_MARGIN_MS = 30 * 60_000
#: weight per *kind* of corroborating identity context (risk component)
IDENTITY_CONTEXT_WEIGHT = 2.0
MAX_CONTEXT_ITEMS = 100


def principals_of(summary: dict[str, Any]) -> list[str]:
    """UPN-shaped identifiers on a chain (lowercased, deduplicated)."""
    found: dict[str, None] = {}
    for entity in summary.get("entities", []):
        for kind in ("upn", "username"):
            for value in (entity.get("identifiers") or {}).get(kind, []):
                if "@" in str(value):
                    found[str(value).lower()] = None
    for alert in summary.get("alerts", []):
        user = alert.get("user")
        if isinstance(user, str) and "@" in user:
            found[user.lower()] = None
    return list(found)


async def identity_context(
    ledger: Ledger, scope_id: str, summary: dict[str, Any]
) -> dict[str, Any]:
    principals = principals_of(summary)
    if not principals:
        return {"principals": [], "observations": [], "kinds": [],
                "risk_contribution": 0.0, "note": "no UPN-shaped identity on this chain"}
    start = int(summary.get("first_time", 0)) - CONTEXT_MARGIN_MS
    end = int(summary.get("last_time", 0)) + CONTEXT_MARGIN_MS
    rows = await ledger.context_for_principals(
        scope_id, principals, start, end, MAX_CONTEXT_ITEMS)
    observations = [
        {"context_id": r["context_id"], "type": r["context_type"],
         "event_time": r["event_time"], "principal": r["principal_key"],
         "source_ref": r["source_ref"], "attributes": _safe(r["attributes"])}
        for r in rows
    ]
    kinds = sorted({o["type"] for o in observations})
    return {
        "principals": principals,
        "observations": observations,
        "kinds": kinds,
        # evidence-backed identity context counted once per kind
        "risk_contribution": IDENTITY_CONTEXT_WEIGHT * len(kinds),
        "note": "context observations are not detections",
    }


def _safe(attributes: dict[str, Any]) -> dict[str, Any]:
    """Drop bulky/sensitive detail from the summary view."""
    drop = {"authentication_details", "mfa_detail"}
    return {k: v for k, v in attributes.items() if k not in drop and v is not None}
