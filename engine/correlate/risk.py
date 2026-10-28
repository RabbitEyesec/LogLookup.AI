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

#: bump when component weights or semantics change (stored per revision)
RISK_RULE_VERSION = "2.0"


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
        severity_evidence = max(entity_risks, default=0.0)

        # Independent confirmation: each *additional* source provider that
        # contributed an alert to the chain. Duplicate representations of
        # one alert never reach the correlator (ledger alias suppression),
        # so a second API wrapping the same alert cannot add weight here.
        providers = sorted({
            (alert.unmapped.get("source") or {}).get("provider")
            for alert in engine.alerts_of(cluster)
            if (alert.unmapped.get("source") or {}).get("provider")
        })
        cluster.source_providers = providers
        confirmation = self._config.independent_source_weight * max(
            0, len(providers) - 1
        )
        subtotal = severity_evidence + confirmation
        downgrade = 0.0
        if cluster.disposition == chains.REVERSED:
            downgrade = -subtotal * (1 - self._config.misconfiguration_downgrade)
        risk = subtotal + downgrade
        cluster.risk_breakdown = {
            "rule_version": RISK_RULE_VERSION,
            "severity_evidence": severity_evidence,
            "independent_source_confirmation": confirmation,
            "supported_attack_progression": 0.0,
            "documented_benign_or_conflicting_context": downgrade,
            "independent_providers": providers,
            "total": risk,
        }
        cluster.risk_score = risk
        if not cluster.surfaced and risk >= self._config.surface_threshold:
            cluster.surfaced = True
            logger.info(
                "chain %s surfaced: cumulative entity risk %.1f >= %.1f",
                cluster.cluster_id, risk, self._config.surface_threshold,
            )
