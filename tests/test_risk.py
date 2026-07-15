"""Phase 9 checkpoint: RBA cumulative entity risk + threshold surfacing."""

from engine.config import CorrelationConfig, RiskConfig
from engine.correlate.engine import CorrelationEngine

from tests.test_correlation import T0, MIN, alert


def engine(threshold=10.0, downgrade=0.5, weights=None):
    risk = RiskConfig(
        surface_threshold=threshold,
        misconfiguration_downgrade=downgrade,
        **({"severity_weights": weights} if weights else {}),
    )
    return CorrelationEngine(CorrelationConfig(risk=risk))


def test_single_low_alert_not_surfaced():
    e = engine(threshold=10)
    e.add(alert("a1", T0, hostname="hostA", severity=3))  # weight 4
    cluster = e.evaluate(flush=True)[0]
    assert cluster.risk_score == 4
    assert cluster.surfaced is False


def test_cumulative_risk_crosses_threshold_and_surfaces():
    # Three Medium alerts (4 each) on one host: 12 >= 10 -> surfaced,
    # even though no single alert is High. The fatigue fix.
    e = engine(threshold=10)
    for i in range(3):
        e.add(alert(f"m{i}", T0 + i * MIN, hostname="hostA", severity=3))
    cluster = e.evaluate(flush=True)[0]
    assert cluster.risk_score == 12
    assert cluster.surfaced is True


def test_single_critical_surfaces_alone():
    e = engine(threshold=10)
    e.add(alert("c1", T0, hostname="hostA", severity=5))  # weight 16
    cluster = e.evaluate(flush=True)[0]
    assert cluster.surfaced is True


def test_risk_accumulates_on_entity_not_per_alert():
    # Risk rides the ENTITY: the same host's risk is the sum of everything
    # on its timeline, and the cluster reads its max-entity risk.
    e = engine(threshold=100)
    e.add(alert("a1", T0, hostname="hostA", severity=4))       # 8
    e.add(alert("a2", T0 + MIN, hostname="hostA", severity=3))  # 4
    e.add(alert("a3", T0 + 2 * MIN, hostname="hostA", severity=2))  # 2
    cluster = e.evaluate(flush=True)[0]
    host = next(
        ent for ent in (e.resolver.get(u) for u in cluster.entity_uids)
        if ent is not None and ent.domain == "host"
    )
    assert host.risk_score == 14
    assert cluster.risk_score == 14


def test_reevaluation_does_not_double_count():
    e = engine(threshold=100)
    e.add(alert("a1", T0, hostname="hostA", severity=4))
    first = e.evaluate(flush=True)[0].risk_score
    e.add(alert("a2", T0 + MIN, hostname="hostA", severity=3))
    second = e.evaluate(flush=True)[0].risk_score
    assert first == 8
    assert second == 12  # 8 + 4, not 16 + 4


def test_reversed_progression_downgrades_risk():
    e = engine(threshold=100, downgrade=0.5)
    e.add(alert("r1", T0, hostname="hostA", severity=4,
                tactic=("Exfiltration", "TA0010")))
    e.add(alert("r2", T0 + 5 * MIN, hostname="hostA", severity=4,
                tactic=("Initial Access", "TA0001")))
    cluster = e.evaluate(flush=True)[0]
    assert cluster.disposition == "reversed"
    assert cluster.risk_score == 8.0  # 16 downgraded by 0.5


def test_surfacing_is_sticky():
    e = engine(threshold=10)
    e.add(alert("s1", T0, hostname="hostA", severity=5))
    assert e.evaluate(flush=True)[0].surfaced is True
    # Later, a reversed tactic pair downgrades risk below threshold;
    # the already-surfaced incident must stay surfaced.
    e.add(alert("s2", T0 + MIN, hostname="hostA", severity=1,
                tactic=("Exfiltration", "TA0010")))
    e.add(alert("s3", T0 + 2 * MIN, hostname="hostA", severity=1,
                tactic=("Initial Access", "TA0001")))
    cluster = e.evaluate(flush=True)[0]
    assert cluster.surfaced is True


def test_custom_weights_respected():
    e = engine(threshold=5, weights={0: 0, 1: 0, 2: 0, 3: 1, 4: 2, 5: 3, 6: 4})
    e.add(alert("w1", T0, hostname="hostA", severity=6))
    cluster = e.evaluate(flush=True)[0]
    assert cluster.risk_score == 4
    assert cluster.surfaced is False


def test_shared_entity_risk_raises_both_chains():
    # Two separate chains touch the same user; the user's cumulative risk
    # surfaces BOTH clusters once it crosses the threshold.
    e = engine(threshold=15)
    e.add(alert("x1", T0, hostname="hostA", user="jdoe", severity=4))  # 8
    # far later -> separate chain, same user
    e.add(alert("x2", T0 + 300 * MIN, hostname="hostB", user="jdoe",
                severity=4))  # 8
    clusters = e.evaluate(flush=True)
    assert len(clusters) == 2
    assert all(c.risk_score == 16 for c in clusters)  # user risk = 8 + 8
    assert all(c.surfaced for c in clusters)
