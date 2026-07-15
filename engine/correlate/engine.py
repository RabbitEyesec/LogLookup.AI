"""The correlation engine  entirely deterministic; no AI touches this layer.

Groups normalized alerts into attack chains by shared resolved entity and
time proximity:

- **Event-time + watermarking**: alerts are correlated in event-time order
  once the watermark (max seen event time minus a grace period) passes them
  — never arrival order. Late stragglers within the grace period still land
  in the right place on the timeline.
- **Sliding proximity**: two consecutive alerts on the same resolved entity
  are chained when they are within ``window_minutes`` of each other, so an
  00:59 + 01:01 two-step never splits on a window boundary (no tumbling
  edge effect) and a dropped middle step still stitches start to end.
- **NetworkX DAG**: alerts are nodes; directed edges follow timestamps on
  the same resolved entity; chains are weakly-connected components.
- **cluster_id**: generated here (locked format, see cluster_id.py); a
  chain keeps its id as it grows; when chains merge, the earlier id wins.
"""

from __future__ import annotations

import logging
from bisect import insort
from dataclasses import dataclass, field
from typing import Any, Optional

import networkx as nx
import msgspec

from engine.config import CorrelationConfig
from engine.correlate import chains
from engine.correlate.cluster_id import ClusterIdGenerator
from engine.correlate.entities import Entity, EntityResolver, Resolution
from engine.normalize.ocsf import NormalizedAlert

logger = logging.getLogger(__name__)


def _alert_evidence(alert: NormalizedAlert) -> dict[str, Any]:
    """Expose the source values analysts need without lossy field-name lists."""
    raw = alert.unmapped.get("raw")
    if isinstance(raw, str):
        try:
            decoded = msgspec.json.decode(raw.encode("utf-8"))
            if isinstance(decoded, dict):
                return decoded
        except msgspec.DecodeError:
            pass
    return msgspec.to_builtins(alert)


@dataclass
class Cluster:
    """One attack chain."""

    cluster_id: str
    alert_uids: list[str] = field(default_factory=list)  # event-time order
    entity_uids: set[int] = field(default_factory=set)
    primary_entity_name: str = ""
    first_time_ms: int = 0
    last_time_ms: int = 0
    tactic_sequence: list[str] = field(default_factory=list)
    disposition: str = chains.UNKNOWN
    risk_score: float = 0.0  # RBA (risk module)
    surfaced: bool = False  # RBA (risk module)
    merged_into: Optional[str] = None

    @property
    def alert_count(self) -> int:
        return len(self.alert_uids)


class CorrelationEngine:
    """Deterministic entity + time correlation over normalized alerts."""

    def __init__(
        self,
        config: CorrelationConfig,
        resolver: Optional[EntityResolver] = None,
    ) -> None:
        from engine.correlate.risk import RiskScorer

        self._config = config
        self.resolver = resolver or EntityResolver(
            config.entity_precedence,
            retention_minutes=config.entity_retention_minutes,
        )
        self._risk = RiskScorer(config.risk)
        self._window_ms = config.window_minutes * 60_000
        self._grace_ms = config.watermark_grace_seconds * 1000
        self._graph = nx.DiGraph()
        self._alerts: dict[str, NormalizedAlert] = {}
        self._resolutions: dict[str, Resolution] = {}
        #: entity uid -> event-time-sorted [(time_ms, alert_uid)]
        self._timelines: dict[int, list[tuple[int, str]]] = {}
        self._buffer: list[tuple[int, str, NormalizedAlert]] = []
        self._buffered_uids: set[str] = set()  # O(1) dedup for the buffer
        self._max_event_time_ms: Optional[int] = None
        self._clusters: dict[str, Cluster] = {}
        self._cluster_of_alert: dict[str, str] = {}
        self._id_generator = ClusterIdGenerator()
        self._sequence = 0  # tie-break for identical timestamps: arrival order

    # -- ingest -------------------------------------------------------------

    def add(self, alert: NormalizedAlert) -> None:
        """Buffer one normalized alert for correlation."""
        uid = alert.uid or f"alert-{len(self._alerts) + len(self._buffer) + 1}"
        if uid in self._alerts or uid in self._buffered_uids:
            logger.debug("duplicate alert %s ignored", uid)
            return
        insort(self._buffer, (alert.time, uid, alert),
               key=lambda item: (item[0], item[1]))
        self._buffered_uids.add(uid)
        if self._max_event_time_ms is None or alert.time > self._max_event_time_ms:
            self._max_event_time_ms = alert.time

    @property
    def watermark_ms(self) -> Optional[int]:
        if self._max_event_time_ms is None:
            return None
        return self._max_event_time_ms - self._grace_ms

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, *, flush: bool = False) -> list[Cluster]:
        """Correlate all buffered alerts behind the watermark.

        With ``flush=True`` (batch mode / shutdown) the watermark is ignored
        and everything buffered is correlated. Returns the live clusters,
        earliest first.
        """
        if flush:
            ready = self._buffer
            self._buffer = []
            self._buffered_uids.clear()
        else:
            watermark = self.watermark_ms
            if watermark is None:
                return self.clusters()
            ready = [item for item in self._buffer if item[0] <= watermark]
            self._buffer = [item for item in self._buffer if item[0] > watermark]
            self._buffered_uids = {u for _, u, _a in self._buffer}

        touched_nodes: list[str] = []
        for time_ms, uid, alert in ready:
            self._insert_alert(time_ms, uid, alert)
            touched_nodes.append(uid)
        if touched_nodes:
            self._rebuild_clusters(touched_nodes)
            self._risk.rescore(self)
        return self.clusters()

    def _insert_alert(self, time_ms: int, uid: str, alert: NormalizedAlert) -> None:
        resolution = self.resolver.resolve(alert)
        self._alerts[uid] = alert
        self._resolutions[uid] = resolution
        self._sequence += 1
        self._graph.add_node(uid, time=time_ms, seq=self._sequence)

        for entity in resolution.entities:
            timeline = self._timelines.setdefault(entity.uid, [])
            position = self._bisect(timeline, time_ms, uid)
            # Directed edges by timestamp on the same resolved entity:
            # predecessor -> this alert -> successor, within the window.
            if position > 0:
                prev_time, prev_uid = timeline[position - 1]
                if time_ms - prev_time <= self._window_ms and prev_uid != uid:
                    self._graph.add_edge(prev_uid, uid, entity=entity.uid)
            if position < len(timeline):
                next_time, next_uid = timeline[position]
                if next_time - time_ms <= self._window_ms and next_uid != uid:
                    self._graph.add_edge(uid, next_uid, entity=entity.uid)
            timeline.insert(position, (time_ms, uid))

    @staticmethod
    def _bisect(timeline: list[tuple[int, str]], time_ms: int, uid: str) -> int:
        low, high = 0, len(timeline)
        while low < high:
            mid = (low + high) // 2
            if timeline[mid] < (time_ms, uid):
                low = mid + 1
            else:
                high = mid
        return low

    def _rebuild_clusters(self, new_nodes: list[str]) -> None:
        seen: set[str] = set()
        for node in new_nodes:
            if node in seen:
                continue
            component = nx.node_connected_component(
                self._graph.to_undirected(as_view=True), node
            )
            seen.update(component)
            self._assign_cluster(component)

    def _assign_cluster(self, component: set[str]) -> None:
        members = sorted(
            component,
            key=lambda uid: (self._alerts[uid].time, uid),
        )
        first_uid = members[0]
        first_time = self._alerts[first_uid].time

        existing_ids = {
            self._cluster_of_alert[uid]
            for uid in members
            if uid in self._cluster_of_alert
        }
        live_ids = sorted(
            cid for cid in existing_ids
            if self._clusters[cid].merged_into is None
        )
        if not live_ids:
            cluster_id = self._id_generator.next_id(
                first_time, self._primary_entity_name(members)
            )
            cluster = Cluster(cluster_id=cluster_id)
            self._clusters[cluster_id] = cluster
        else:
            # Chains merged: the id of the chain with the earliest alert wins.
            keep_id = min(
                live_ids,
                key=lambda cid: (self._clusters[cid].first_time_ms, cid),
            )
            cluster = self._clusters[keep_id]
            for cid in live_ids:
                if cid != keep_id:
                    self._clusters[cid].merged_into = keep_id
                    logger.info("chain %s merged into %s", cid, keep_id)

        cluster.alert_uids = members
        cluster.entity_uids = {
            entity.uid
            for uid in members
            for entity in self._resolutions[uid].entities
        }
        cluster.primary_entity_name = self._primary_entity_name(members)
        cluster.first_time_ms = first_time
        cluster.last_time_ms = self._alerts[members[-1]].time
        ordered_alerts = [self._alerts[uid] for uid in members]
        cluster.tactic_sequence = chains.tactic_sequence(ordered_alerts)
        cluster.disposition = chains.progression_disposition(ordered_alerts)
        for uid in members:
            self._cluster_of_alert[uid] = cluster.cluster_id

    def _primary_entity_name(self, member_uids: list[str]) -> str:
        """Most frequent alert-primary entity; ties break deterministically."""
        counts: dict[int, int] = {}
        entities: dict[int, Entity] = {}
        for uid in member_uids:
            primary = self._resolutions[uid].primary
            counts[primary.uid] = counts.get(primary.uid, 0) + 1
            entities[primary.uid] = primary
        best_uid = min(
            counts,
            key=lambda entity_uid: (
                -counts[entity_uid],
                entities[entity_uid].first_seen_ms,
                entity_uid,
            ),
        )
        return entities[best_uid].display_name

    # -- retention ------------------------------------------------------------

    def prune_before(self, cutoff_ms: int) -> int:
        """Drop whole chains that ended before ``cutoff_ms`` from live state.

        Long-running poll processes must not grow without bound: a chain
        whose last alert is older than the retention window can no longer
        gain members (the correlation window is far smaller), so its alerts,
        graph nodes, and timeline entries are released. The chain's
        write-back document remains in Elasticsearch — pruning frees memory,
        it never deletes results. Returns the number of chains pruned.
        """
        doomed = [
            cluster for cluster in self._clusters.values()
            if cluster.merged_into is None and cluster.last_time_ms < cutoff_ms
        ]
        if not doomed:
            return 0
        doomed_ids = {cluster.cluster_id for cluster in doomed}
        for cluster in doomed:
            for uid in cluster.alert_uids:
                self._alerts.pop(uid, None)
                self._resolutions.pop(uid, None)
                self._cluster_of_alert.pop(uid, None)
                if self._graph.has_node(uid):
                    self._graph.remove_node(uid)
            del self._clusters[cluster.cluster_id]
        # Merge losers that pointed at a pruned chain go with it.
        for cid in [
            cid for cid, c in self._clusters.items()
            if c.merged_into in doomed_ids
        ]:
            del self._clusters[cid]
        for entity_uid in list(self._timelines):
            kept = [
                item for item in self._timelines[entity_uid]
                if item[1] in self._alerts
            ]
            if kept:
                self._timelines[entity_uid] = kept
            else:
                del self._timelines[entity_uid]
        logger.info("pruned %d expired chain(s) from live state", len(doomed))
        return len(doomed)

    # -- accessors ----------------------------------------------------------

    def clusters(self) -> list[Cluster]:
        """Live clusters (merge losers excluded), earliest first."""
        return sorted(
            (c for c in self._clusters.values() if c.merged_into is None),
            key=lambda c: (c.first_time_ms, c.cluster_id),
        )

    def alerts_of(self, cluster: Cluster) -> list[NormalizedAlert]:
        return [self._alerts[uid] for uid in cluster.alert_uids]

    def entity_timelines(self):
        """Yield ``(entity_uid, [alerts on that entity, time-ordered])``."""
        for entity_uid, timeline in self._timelines.items():
            yield entity_uid, [self._alerts[uid] for _, uid in timeline]

    def resolution_of(self, alert_uid: str) -> Resolution:
        return self._resolutions[alert_uid]

    def cluster_summary(self, cluster: Cluster) -> dict[str, Any]:
        """JSON-serializable, inspectable chain summary."""
        return {
            "cluster_id": cluster.cluster_id,
            "alert_count": cluster.alert_count,
            "alerts": [
                {
                    "uid": alert.uid,
                    "time": alert.time,
                    "time_dt": alert.time_dt,
                    "title": alert.finding_info.title,
                    "description": alert.finding_info.desc or alert.message or "",
                    "rule": (
                        alert.finding_info.analytic.name
                        if alert.finding_info.analytic is not None else ""
                    ) or alert.finding_info.title,
                    "severity": alert.severity_label(),
                    "host": alert.device.hostname if alert.device else "",
                    "user": (
                        alert.actor.user.name
                        if alert.actor and alert.actor.user else ""
                    ),
                    "process": (
                        alert.actor.process.name
                        if alert.actor and alert.actor.process else ""
                    ),
                    "command": (
                        alert.actor.process.cmd_line
                        if alert.actor and alert.actor.process else ""
                    ),
                    "source_ip": alert.src_endpoint.ip if alert.src_endpoint else "",
                    "destination_ip": alert.dst_endpoint.ip if alert.dst_endpoint else "",
                    "evidence": _alert_evidence(alert),
                    "entities": sorted(
                        entity.display_name
                        for entity in self._resolutions[alert.uid].entities
                    ),
                    "tactics": [
                        attack.tactic.name or attack.tactic.uid
                        for attack in alert.finding_info.attacks
                        if attack.tactic is not None
                        and (attack.tactic.name or attack.tactic.uid)
                    ],
                    "techniques": [
                        {
                            "uid": attack.technique.uid,
                            "name": attack.technique.name,
                        }
                        for attack in alert.finding_info.attacks
                        if attack.technique is not None
                        and (attack.technique.uid or attack.technique.name)
                    ],
                }
                for alert in self.alerts_of(cluster)
            ],
            "entities": [
                {
                    "name": entity.display_name,
                    "domain": entity.domain,
                    "risk_score": entity.risk_score,
                    "identifiers": {
                        kind: sorted(values)
                        for kind, values in sorted(entity.identifiers.items())
                    },
                }
                for entity_uid in sorted(cluster.entity_uids)
                if (entity := self.resolver.get(entity_uid)) is not None
            ],
            "primary_entity": cluster.primary_entity_name,
            "first_time": cluster.first_time_ms,
            "last_time": cluster.last_time_ms,
            "tactic_sequence": cluster.tactic_sequence,
            "disposition": cluster.disposition,
            "risk_score": cluster.risk_score,
            "surfaced": cluster.surfaced,
        }
