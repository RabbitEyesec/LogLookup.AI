"""Risk-Based Alerting (RBA)  the real fix for alert fatigue.

Instead of one-alert-one-verdict, risk accumulates on the resolved ENTITY:
every alert contributes a severity-derived weight (config
``correlation.risk.severity_weights``) to each entity it touches, and an
attack chain is surfaced only when the cumulative risk of one of its
entities crosses ``surface_threshold``  collapsing many low-fidelity
signals into a single high-confidence incident.

Entity risk is recomputed deterministically from the entity's alert
timeline on every evaluation (idempotent: no double counting across
re-evaluations or entity merges). A chain whose ATT&CK tactic sequence is
reversed/conflicting gets its risk downgraded
(``misconfiguration_downgrade``)  likely misconfiguration, not intrusion.
Surfacing is sticky: an incident that crossed the threshold stays surfaced.
"""

from __future__ import annotations

import logging

from engine.config import RiskConfig
from engine.correlate import chains
from engine.correlate.engine import Cluster, CorrelationEngine

logger = logging.getLogger(__name__)


class RiskScorer:
    """Deterministic cumulative entity risk + threshold surfacing."""

    def __init__(self, config: RiskConfig) -> None:
        self._config = config

    def rescore(self, engine: CorrelationEngine) -> None:
        """Recompute entity risk and cluster surfacing for live state."""
        self._rescore_entities(engine)
        for cluster in engine.clusters():
            self._rescore_cluster(engine, cluster)

    def _rescore_entities(self, engine: CorrelationEngine) -> None:
        for entity_uid, alerts in engine.entity_timelines():
            entity = engine.resolver.get(entity_uid)
            if entity is None:  # flushed as stale
                continue
            entity.risk_score = sum(
                self._config.weight_for(alert.severity_id) for alert in alerts
            )

    def _rescore_cluster(self, engine: CorrelationEngine, cluster: Cluster) -> None:
        entity_risks = [
            entity.risk_score
            for entity_uid in cluster.entity_uids
            if (entity := engine.resolver.get(entity_uid)) is not None
        ]
        risk = max(entity_risks, default=0.0)
        if cluster.disposition == chains.REVERSED:
            risk *= self._config.misconfiguration_downgrade
        cluster.risk_score = risk
        if not cluster.surfaced and risk >= self._config.surface_threshold:
            cluster.surfaced = True
            logger.info(
                "chain %s surfaced: cumulative entity risk %.1f >= %.1f",
                cluster.cluster_id, risk, self._config.surface_threshold,
            )
