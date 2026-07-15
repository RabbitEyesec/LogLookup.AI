"""ATT&CK tactic progression over a chain deterministic, no AI, no RAG.

Alerts arrive pre-tagged with ATT&CK metadata from the normalizer; this
module only orders those pre-existing tags along the chain's timeline using
the standard MITRE ATT&CK Enterprise tactic ordering. Credential Access then
Lateral Movement on one entity = a progressing attack; a reversed /
conflicting sequence is downgraded to likely misconfiguration.

Alerts without tactic tags simply don't contribute mapping techniques to
tactics is the (out-of-scope) RAG layer's job, never guessed here.
"""

from __future__ import annotations

from typing import Iterable, Optional

from engine.normalize.ocsf import NormalizedAlert

#: MITRE ATT&CK Enterprise tactics in standard kill-chain order.
TACTIC_ORDER: tuple[tuple[str, str], ...] = (
    ("TA0043", "reconnaissance"),
    ("TA0042", "resource development"),
    ("TA0001", "initial access"),
    ("TA0002", "execution"),
    ("TA0003", "persistence"),
    ("TA0004", "privilege escalation"),
    ("TA0005", "defense evasion"),
    ("TA0006", "credential access"),
    ("TA0007", "discovery"),
    ("TA0008", "lateral movement"),
    ("TA0009", "collection"),
    ("TA0011", "command and control"),
    ("TA0010", "exfiltration"),
    ("TA0040", "impact"),
)

_RANK_BY_UID = {uid: rank for rank, (uid, _) in enumerate(TACTIC_ORDER)}
_RANK_BY_NAME = {name: rank for rank, (_, name) in enumerate(TACTIC_ORDER)}

#: Chain dispositions.
PROGRESSING = "progressing"  # tactics advance along the kill chain
REVERSED = "reversed"  # conflicting order -> likely misconfiguration
FLAT = "flat"  # activity within a single tactic (e.g. brute force burst)
UNKNOWN = "unknown"  # not enough tactic-tagged alerts to judge


def tactic_rank(uid: Optional[str], name: Optional[str]) -> Optional[int]:
    if uid and uid.upper() in _RANK_BY_UID:
        return _RANK_BY_UID[uid.upper()]
    if name and name.strip().lower() in _RANK_BY_NAME:
        return _RANK_BY_NAME[name.strip().lower()]
    return None


def alert_tactic_ranks(alert: NormalizedAlert) -> list[int]:
    ranks = []
    for attack in alert.finding_info.attacks:
        if attack.tactic is None:
            continue
        rank = tactic_rank(attack.tactic.uid, attack.tactic.name)
        if rank is not None:
            ranks.append(rank)
    return ranks


def tactic_sequence(alerts_in_order: Iterable[NormalizedAlert]) -> list[str]:
    """Time-ordered tactic names observed along the chain."""
    sequence = []
    for alert in alerts_in_order:
        for attack in alert.finding_info.attacks:
            if attack.tactic is not None and (attack.tactic.name or attack.tactic.uid):
                sequence.append(attack.tactic.name or attack.tactic.uid)
    return sequence


def progression_disposition(alerts_in_order: Iterable[NormalizedAlert]) -> str:
    """Judge the chain's tactic progression, tolerating missing links.

    Only ORDER matters — a dropped middle step (missing Priv-Esc between
    Initial Access and Exfiltration) still reads as progressing.
    """
    ranks: list[int] = []
    for alert in alerts_in_order:
        alert_ranks = alert_tactic_ranks(alert)
        if alert_ranks:
            # One alert may carry several tags; use its furthest tactic.
            ranks.append(max(alert_ranks))
    if len(ranks) < 2:
        return UNKNOWN
    increases = sum(1 for a, b in zip(ranks, ranks[1:]) if b > a)
    decreases = sum(1 for a, b in zip(ranks, ranks[1:]) if b < a)
    if decreases > increases:
        return REVERSED
    if increases > 0:
        return PROGRESSING
    return FLAT
