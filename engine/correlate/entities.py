"""Entity resolution the make-or-break part of correlation.

One host appears as agent GUID, IP, MAC, and hostname; one user as name,
UPN, or email. Unresolved, correlation is blind. This module coalesces
identifiers that co-occur on alerts into entity records, with:

- **Coalescing precedence** (config ``entity_precedence``, default
  ``process_guid > upn > mac > ip``) choosing each alert's primary anchor.
- **Temporal validity** for ephemeral IPs (the State Smearing guard): an
  IP-to-host assignment holds from the moment it is observed until the IP
  is next seen belonging to a different host, and resolution happens at the
  EVENT's timestamp never against current state.
- **In-memory state with periodic flush** of stale entities.

Merging is domain scoped: host identifiers only coalesce with host
identifiers, user with user — a user touching many hosts must never fuse
those hosts into one entity.
"""

from __future__ import annotations

import ipaddress
import logging
from bisect import bisect_right, insort
from dataclasses import dataclass, field
from typing import Iterable, Optional

from engine.normalize.ocsf import NormalizedAlert

logger = logging.getLogger(__name__)

# Identifier kinds, by domain. `ip` is ephemeral; everything else durable.
HOST_KINDS = ("agent_uid", "hostname", "mac")
USER_KINDS = ("upn", "username")
PROCESS_KINDS = ("process_guid",)

#: Fallback anchor order appended after the configured precedence, so alerts
#: carrying only e.g. a hostname still anchor deterministically.
FALLBACK_PRECEDENCE = ("agent_uid", "hostname", "username")


def _norm_mac(value: str) -> str:
    return value.strip().lower().replace("-", ":")


def _norm_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


@dataclass
class Entity:
    """A resolved real-world entity (host, user, or bare IP)."""

    uid: int
    domain: str  # "host" | "user" | "ip"
    identifiers: dict[str, set[str]] = field(default_factory=dict)
    #: original-case value per kind, for human-readable output (cluster_id);
    #: joining always uses the normalized values in ``identifiers``.
    display: dict[str, str] = field(default_factory=dict)
    first_seen_ms: int = 0
    last_seen_ms: int = 0
    risk_score: float = 0.0  # accumulated by RBA (risk module)

    def add(self, kind: str, value: str, display: Optional[str] = None) -> None:
        self.identifiers.setdefault(kind, set()).add(value)
        self.display.setdefault(kind, display or value)

    def has(self, kind: str) -> bool:
        return bool(self.identifiers.get(kind))

    @property
    def display_name(self) -> str:
        for kind in ("hostname", "username", "upn", "agent_uid", "mac",
                     "process_guid", "ip"):
            if kind in self.display:
                return self.display[kind]
            values = self.identifiers.get(kind)
            if values:
                return sorted(values)[0]
        return f"entity-{self.uid}"


@dataclass(frozen=True)
class Resolution:
    """Entities one alert touches, and its primary anchor."""

    entities: tuple[Entity, ...]
    primary: Entity


def extract_identifiers(alert: NormalizedAlert) -> dict[str, list[tuple[str, str]]]:
    """Pull correlation identifiers out of a normalized alert.

    Values are ``(normalized, original_display)`` pairs: joining uses the
    normalized form; output keeps the source's casing.
    """
    ids: dict[str, list[tuple[str, str]]] = {}

    def put(kind: str, value: Optional[str], display: Optional[str] = None) -> None:
        if value:
            ids.setdefault(kind, []).append((value, display or value))

    device = alert.device
    if device is not None:
        put("agent_uid", device.uid)
        if device.hostname:
            put("hostname", device.hostname.lower(), device.hostname)
        if device.mac:
            put("mac", _norm_mac(device.mac), device.mac)
        if device.ip:
            put("device_ip", _norm_ip(device.ip))
    actor = alert.actor
    if actor is not None:
        if actor.user is not None:
            if actor.user.email_addr:
                put("upn", actor.user.email_addr.lower(), actor.user.email_addr)
            if actor.user.name:
                put("username", actor.user.name.lower(), actor.user.name)
        if actor.process is not None:
            put("process_guid", actor.process.uid)
    if alert.src_endpoint is not None and alert.src_endpoint.ip:
        put("src_ip", _norm_ip(alert.src_endpoint.ip))
    return ids


class EntityResolver:
    """Coalescing entity resolution with temporal IP validity."""

    def __init__(
        self,
        precedence: Iterable[str] = ("process_guid", "upn", "mac", "ip"),
        *,
        retention_minutes: int = 1440,
    ) -> None:
        self._precedence = tuple(precedence) + FALLBACK_PRECEDENCE
        self._retention_ms = retention_minutes * 60_000
        self._entities: dict[int, Entity] = {}
        self._durable_index: dict[tuple[str, str], int] = {}
        #: ip -> sorted list of (start_ms, entity_uid): assignment valid from
        #: start_ms until the next assignment's start_ms.
        self._ip_assignments: dict[str, list[tuple[int, int]]] = {}
        self._next_uid = 1

    # -- internal helpers ---------------------------------------------------

    def _new_entity(self, domain: str, time_ms: int) -> Entity:
        entity = Entity(
            uid=self._next_uid,
            domain=domain,
            first_seen_ms=time_ms,
            last_seen_ms=time_ms,
        )
        self._next_uid += 1
        self._entities[entity.uid] = entity
        return entity

    def _merge(self, keep: Entity, absorb: Entity) -> Entity:
        """Fuse two records of the same real entity (same domain only)."""
        if keep.uid == absorb.uid:
            return keep
        if absorb.first_seen_ms < keep.first_seen_ms or (
            absorb.first_seen_ms == keep.first_seen_ms and absorb.uid < keep.uid
        ):
            keep, absorb = absorb, keep
        for kind, values in absorb.identifiers.items():
            for value in values:
                keep.add(kind, value, absorb.display.get(kind))
                self._durable_index[(kind, value)] = keep.uid
        keep.first_seen_ms = min(keep.first_seen_ms, absorb.first_seen_ms)
        keep.last_seen_ms = max(keep.last_seen_ms, absorb.last_seen_ms)
        keep.risk_score += absorb.risk_score
        for ip, assignments in self._ip_assignments.items():
            self._ip_assignments[ip] = [
                (start, keep.uid if uid == absorb.uid else uid)
                for start, uid in assignments
            ]
        del self._entities[absorb.uid]
        logger.debug("merged entity %d into %d", absorb.uid, keep.uid)
        return keep

    def _resolve_durable(
        self,
        domain: str,
        kinds: Iterable[tuple[str, str, str]],
        time_ms: int,
    ) -> Optional[Entity]:
        """Find-or-create the entity for a set of co-occurring durable ids."""
        triples = list(kinds)
        if not triples:
            return None
        found: list[Entity] = []
        for kind, value, _display in triples:
            uid = self._durable_index.get((kind, value))
            if uid is not None and uid in self._entities:
                entity = self._entities[uid]
                if entity not in found:
                    found.append(entity)
        if found:
            entity = found[0]
            for other in found[1:]:
                entity = self._merge(entity, other)
        else:
            entity = self._new_entity(domain, time_ms)
        for kind, value, display in triples:
            entity.add(kind, value, display)
            self._durable_index[(kind, value)] = entity.uid
        entity.first_seen_ms = min(entity.first_seen_ms, time_ms)
        entity.last_seen_ms = max(entity.last_seen_ms, time_ms)
        return entity

    def _assignment_at(self, ip: str, time_ms: int) -> Optional[Entity]:
        """The entity an IP belonged to AT time_ms (temporal validity)."""
        assignments = self._ip_assignments.get(ip)
        if not assignments:
            return None
        index = bisect_right(assignments, (time_ms, float("inf"))) - 1
        if index < 0:
            return None
        return self._entities.get(assignments[index][1])

    def _observe_ip(self, ip: str, entity: Entity, time_ms: int) -> None:
        """Record that `ip` was seen belonging to `entity` at `time_ms`."""
        current = self._assignment_at(ip, time_ms)
        if current is not None and current.uid == entity.uid:
            return
        insort(self._ip_assignments.setdefault(ip, []), (time_ms, entity.uid))
        entity.add("ip", ip)

    # -- public API ---------------------------------------------------------

    def resolve(self, alert: NormalizedAlert) -> Resolution:
        """Resolve one alert to the entities it touches, at ITS timestamp."""
        time_ms = alert.time
        ids = extract_identifiers(alert)
        touched: list[Entity] = []
        anchor_kind_by_entity: dict[int, list[str]] = {}

        def touch(entity: Optional[Entity], *kinds: str) -> None:
            if entity is None:
                return
            entity.last_seen_ms = max(entity.last_seen_ms, time_ms)
            if entity not in touched:
                touched.append(entity)
            anchor_kind_by_entity.setdefault(entity.uid, []).extend(kinds)

        # Host entity: durable ids coalesce; process GUID pins to its host.
        host_triples = [
            (kind, value, display)
            for kind in HOST_KINDS
            for value, display in ids.get(kind, ())
        ]
        process_triples = [
            ("process_guid", value, display)
            for value, display in ids.get("process_guid", ())
        ]
        host = self._resolve_durable(
            "host", host_triples + process_triples, time_ms
        )
        if host is not None:
            touch(host, *(k for k, _, _ in host_triples + process_triples))

        # Device IP: associate with the host (temporal validity), or resolve
        # to whichever entity held the IP at event time.
        for ip, _display in ids.get("device_ip", ()):
            if host is not None:
                self._observe_ip(ip, host, time_ms)
                anchor_kind_by_entity.setdefault(host.uid, []).append("ip")
            else:
                owner = self._assignment_at(ip, time_ms)
                if owner is None:
                    owner = self._new_entity("ip", time_ms)
                    owner.add("ip", ip)
                    self._observe_ip(ip, owner, time_ms)
                touch(owner, "ip")

        # User entity.
        user_triples = [
            (kind, value, display)
            for kind in USER_KINDS
            for value, display in ids.get(kind, ())
        ]
        user = self._resolve_durable("user", user_triples, time_ms)
        if user is not None:
            touch(user, *(k for k, _, _ in user_triples))

        # Source IP: resolved at the EVENT's timestamp — the state smearing
        # guard. Unknown source IPs become their own (attacker-infra) entity.
        for ip, _display in ids.get("src_ip", ()):
            owner = self._assignment_at(ip, time_ms)
            if owner is None:
                uid = self._durable_index.get(("bare_ip", ip))
                owner = self._entities.get(uid) if uid is not None else None
            if owner is None:
                owner = self._new_entity("ip", time_ms)
                owner.add("ip", ip)
                self._durable_index[("bare_ip", ip)] = owner.uid
            touch(owner, "ip")

        if not touched:
            # No identifiers at all: synthetic one-alert entity so the alert
            # still flows through correlation (explicitly inspectable).
            orphan = self._new_entity("ip", time_ms)
            orphan.add("ip", f"unidentified-{orphan.uid}")
            touch(orphan, "ip")

        primary = self._pick_primary(touched, anchor_kind_by_entity)
        return Resolution(entities=tuple(touched), primary=primary)

    def _pick_primary(
        self,
        touched: list[Entity],
        anchor_kinds: dict[int, list[str]],
    ) -> Entity:
        for kind in self._precedence:
            for entity in touched:
                if kind in anchor_kinds.get(entity.uid, ()):
                    return entity
        return touched[0]

    def flush_stale(self, now_ms: int) -> int:
        """Drop entities idle longer than the retention window."""
        cutoff = now_ms - self._retention_ms
        stale = [e for e in self._entities.values() if e.last_seen_ms < cutoff]
        for entity in stale:
            for kind, values in entity.identifiers.items():
                for value in values:
                    for key in ((kind, value), ("bare_ip", value)):
                        if self._durable_index.get(key) == entity.uid:
                            del self._durable_index[key]
            del self._entities[entity.uid]
        for ip in list(self._ip_assignments):
            kept = [
                (start, uid)
                for start, uid in self._ip_assignments[ip]
                if uid in self._entities
            ]
            if kept:
                self._ip_assignments[ip] = kept
            else:
                del self._ip_assignments[ip]
        if stale:
            logger.info("flushed %d stale entities", len(stale))
        return len(stale)

    def get(self, entity_uid: int) -> Optional[Entity]:
        return self._entities.get(entity_uid)

    @property
    def entity_count(self) -> int:
        return len(self._entities)
