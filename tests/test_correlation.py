"""Phase 8 acceptance (Build Plan 2.3 — Correlation):

- Edge-of-window two-step (00:59 + 01:01) -> still correlated.
- Dropped middle step -> start + end still stitched.
- cluster_id stable, human-readable, locked format.
- Reversed tactic progression -> downgraded to likely misconfiguration.
"""

import re

from engine.config import CorrelationConfig
from engine.correlate.chains import FLAT, PROGRESSING, REVERSED
from engine.correlate.engine import CorrelationEngine
from engine.normalize.ocsf import (
    Actor,
    Device,
    FindingInfo,
    Metadata,
    MitreAttack,
    NetworkEndpoint,
    NormalizedAlert,
    Tactic,
    Technique,
    User,
)

T0 = 1_783_728_000_000  # 2026-07-11T00:00:00Z
MIN = 60_000

CLUSTER_ID_FORMAT = re.compile(r"^CHAIN-\d{4}-\d{2}-\d{2}-[A-Za-z0-9_-]+-\d{3}$")


def alert(uid, t, hostname=None, user=None, src_ip=None, severity=3,
          tactic=None, technique=None, title="alert"):
    attacks = []
    if tactic or technique:
        attacks.append(
            MitreAttack(
                tactic=Tactic(name=tactic[0], uid=tactic[1]) if tactic else None,
                technique=Technique(name=technique, uid=technique)
                if technique else None,
            )
        )
    return NormalizedAlert(
        time=t,
        time_dt="",
        severity_id=severity,
        metadata=Metadata(),
        finding_info=FindingInfo(title=title, uid=uid, attacks=attacks),
        device=Device(hostname=hostname) if hostname else None,
        actor=Actor(user=User(name=user)) if user else None,
        src_endpoint=NetworkEndpoint(ip=src_ip) if src_ip else None,
        unmapped={"raw": "{}"},
    )


def engine(window_minutes=60, grace_seconds=60):
    return CorrelationEngine(
        CorrelationConfig(
            window_minutes=window_minutes,
            watermark_grace_seconds=grace_seconds,
        )
    )


def test_edge_of_window_two_step_still_correlated():
    # 00:59 and 01:01 — a tumbling hour window would split them.
    e = engine(window_minutes=60)
    e.add(alert("a1", T0 + 59 * MIN, hostname="hostA"))
    e.add(alert("a2", T0 + 61 * MIN, hostname="hostA"))
    clusters = e.evaluate(flush=True)
    assert len(clusters) == 1
    assert clusters[0].alert_uids == ["a1", "a2"]


def test_gap_beyond_window_breaks_chain():
    e = engine(window_minutes=60)
    e.add(alert("a1", T0, hostname="hostA"))
    e.add(alert("a2", T0 + 90 * MIN, hostname="hostA"))
    clusters = e.evaluate(flush=True)
    assert len(clusters) == 2


def test_dropped_middle_step_start_and_end_still_stitched():
    # Initial Access ... (Priv-Esc log dropped) ... Exfiltration on one host,
    # 40 minutes apart: still one incident.
    e = engine(window_minutes=60)
    e.add(alert("start", T0, hostname="hostA",
                tactic=("Initial Access", "TA0001")))
    e.add(alert("end", T0 + 40 * MIN, hostname="hostA",
                tactic=("Exfiltration", "TA0010")))
    clusters = e.evaluate(flush=True)
    assert len(clusters) == 1
    assert clusters[0].disposition == PROGRESSING


def test_cluster_id_locked_format_and_stability():
    e = engine()
    e.add(alert("a1", T0, hostname="hostA"))
    e.add(alert("a2", T0 + MIN, hostname="hostA"))
    first = e.evaluate(flush=True)[0].cluster_id
    assert CLUSTER_ID_FORMAT.match(first)
    assert first == "CHAIN-2026-07-11-hostA-001"
    # Growing the chain must NOT change its id.
    e.add(alert("a3", T0 + 2 * MIN, hostname="hostA"))
    again = e.evaluate(flush=True)
    assert len(again) == 1
    assert again[0].cluster_id == first
    assert again[0].alert_count == 3
    # A second, unrelated chain on the same host+date gets -002.
    e.add(alert("b1", T0 + 300 * MIN, hostname="hostA"))
    ids = [c.cluster_id for c in e.evaluate(flush=True)]
    assert ids == [first, "CHAIN-2026-07-11-hostA-002"]


def test_same_input_yields_same_ids():
    def run():
        e = engine()
        e.add(alert("a1", T0, hostname="hostA"))
        e.add(alert("b1", T0 + 5 * MIN, hostname="hostB"))
        e.add(alert("a2", T0 + 10 * MIN, hostname="hostA"))
        return [c.cluster_id for c in e.evaluate(flush=True)]

    assert run() == run()


def test_entity_bridging_user_links_two_hosts_chain():
    # Same user active on two hosts: lateral movement chain via user entity.
    e = engine()
    e.add(alert("h1", T0, hostname="hostA", user="jdoe",
                tactic=("Credential Access", "TA0006"), technique="T1003"))
    e.add(alert("h2", T0 + 10 * MIN, hostname="hostB", user="jdoe",
                tactic=("Lateral Movement", "TA0008"), technique="T1021"))
    clusters = e.evaluate(flush=True)
    assert len(clusters) == 1
    assert clusters[0].disposition == PROGRESSING
    assert clusters[0].tactic_sequence == [
        "Credential Access", "Lateral Movement"
    ]


def test_reversed_progression_downgraded():
    e = engine()
    e.add(alert("r1", T0, hostname="hostA",
                tactic=("Exfiltration", "TA0010")))
    e.add(alert("r2", T0 + 5 * MIN, hostname="hostA",
                tactic=("Initial Access", "TA0001")))
    clusters = e.evaluate(flush=True)
    assert clusters[0].disposition == REVERSED


def test_flat_burst_is_flat():
    e = engine()
    for i in range(3):
        e.add(alert(f"f{i}", T0 + i * MIN, hostname="hostA",
                    tactic=("Credential Access", "TA0006"), technique="T1110"))
    assert e.evaluate(flush=True)[0].disposition == FLAT


def test_two_chains_merge_keeps_earlier_id():
    e = engine(window_minutes=60)
    e.add(alert("a1", T0, hostname="hostA"))
    e.add(alert("b1", T0 + 30 * MIN, hostname="hostB"))
    clusters = e.evaluate(flush=True)
    assert len(clusters) == 2
    first_id = clusters[0].cluster_id
    # A bridging alert touches both hosts (shared src ip entity is hostless
    # here, so bridge via both hostnames? -> use an alert on hostA whose
    # source resolves nothing; instead bridge with a user seen on both).
    e.add(alert("bridge1", T0 + 40 * MIN, hostname="hostA", user="jdoe"))
    e.add(alert("bridge2", T0 + 45 * MIN, hostname="hostB", user="jdoe"))
    merged = e.evaluate(flush=True)
    assert len(merged) == 1
    assert merged[0].cluster_id == first_id
    assert merged[0].alert_count == 4


def test_watermark_holds_back_recent_alerts_until_flush():
    e = engine(grace_seconds=120)
    e.add(alert("old", T0, hostname="hostA"))
    e.add(alert("new", T0 + 10 * MIN, hostname="hostA"))  # sets max time
    clusters = e.evaluate()  # watermark = T0+10min-2min
    surfaced_uids = [uid for c in clusters for uid in c.alert_uids]
    assert "old" in surfaced_uids and "new" not in surfaced_uids
    # flush drains the buffer
    clusters = e.evaluate(flush=True)
    surfaced_uids = [uid for c in clusters for uid in c.alert_uids]
    assert "new" in surfaced_uids


def test_out_of_order_arrival_correlates_by_event_time():
    e = engine()
    e.add(alert("late-arriving-but-early", T0 + 5 * MIN, hostname="hostA"))
    e.add(alert("first-arriving-but-late", T0 + 10 * MIN, hostname="hostA"))
    e.add(alert("earliest", T0, hostname="hostA"))
    clusters = e.evaluate(flush=True)
    assert clusters[0].alert_uids == [
        "earliest", "late-arriving-but-early", "first-arriving-but-late"
    ]


def test_duplicate_alert_uid_ignored():
    e = engine()
    e.add(alert("dup", T0, hostname="hostA"))
    e.add(alert("dup", T0, hostname="hostA"))
    clusters = e.evaluate(flush=True)
    assert clusters[0].alert_count == 1


def test_cluster_summary_is_inspectable():
    e = engine()
    e.add(alert("s1", T0, hostname="hostA", user="jdoe",
                tactic=("Credential Access", "TA0006"), title="Cred dump"))
    cluster = e.evaluate(flush=True)[0]
    summary = e.cluster_summary(cluster)
    assert summary["cluster_id"] == cluster.cluster_id
    assert summary["alerts"][0]["title"] == "Cred dump"
    assert "hostA" in summary["alerts"][0]["entities"]
    assert summary["disposition"] == "unknown"  # single tagged alert
