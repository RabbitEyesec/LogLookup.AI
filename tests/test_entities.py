"""Phase 7 acceptance (Build Plan 2.3 — Correlation, entity items):

- Same host as IP + hostname -> one resolved entity.
- Reused IP across time -> attributed to host valid at event time
  (State Smearing).
"""

from engine.correlate.entities import EntityResolver
from engine.normalize.ocsf import (
    Actor,
    Device,
    FindingInfo,
    Metadata,
    NetworkEndpoint,
    NormalizedAlert,
    Process,
    User,
)

T0 = 1_783_728_000_000  # 2026-07-11T00:00:00Z
MIN = 60_000


def alert(
    t=T0,
    hostname=None,
    device_ip=None,
    mac=None,
    agent_uid=None,
    user=None,
    upn=None,
    process_guid=None,
    src_ip=None,
    uid="a",
):
    return NormalizedAlert(
        time=t,
        time_dt="2026-07-11T00:00:00.000Z",
        severity_id=3,
        metadata=Metadata(),
        finding_info=FindingInfo(title="t", uid=uid),
        device=Device(hostname=hostname, ip=device_ip, mac=mac, uid=agent_uid)
        if (hostname or device_ip or mac or agent_uid)
        else None,
        actor=Actor(
            user=User(name=user, email_addr=upn) if (user or upn) else None,
            process=Process(uid=process_guid) if process_guid else None,
        )
        if (user or upn or process_guid)
        else None,
        src_endpoint=NetworkEndpoint(ip=src_ip) if src_ip else None,
        unmapped={"raw": "{}"},
    )


def test_hostname_and_ip_resolve_to_one_entity():
    r = EntityResolver()
    # Alert 1 carries hostname + IP together (the association observation).
    first = r.resolve(alert(t=T0, hostname="hostA", device_ip="10.0.0.5"))
    # Alert 2 carries ONLY the IP; alert 3 carries ONLY the hostname.
    second = r.resolve(alert(t=T0 + MIN, device_ip="10.0.0.5", uid="b"))
    third = r.resolve(alert(t=T0 + 2 * MIN, hostname="HOSTA", uid="c"))
    assert first.primary.uid == second.primary.uid == third.primary.uid


def test_state_smearing_ip_attributed_to_host_valid_at_event_time():
    r = EntityResolver()
    # 10:00 — DHCP: 10.0.0.9 belongs to hostA.
    r.resolve(alert(t=T0, hostname="hostA", device_ip="10.0.0.9"))
    # 12:00 — lease reassigned: 10.0.0.9 now belongs to hostB.
    r.resolve(alert(t=T0 + 120 * MIN, hostname="hostB", device_ip="10.0.0.9"))
    # An event AT 10:30 (even if it arrives late) must blame hostA...
    early = r.resolve(alert(t=T0 + 30 * MIN, src_ip="10.0.0.9", uid="x"))
    assert early.primary.has("hostname")
    assert "hosta" in early.primary.identifiers["hostname"]
    # ...and an event at 13:00 must blame hostB, not hostA.
    late = r.resolve(alert(t=T0 + 180 * MIN, src_ip="10.0.0.9", uid="y"))
    assert "hostb" in late.primary.identifiers["hostname"]


def test_mac_bridges_two_partial_observations():
    r = EntityResolver()
    a = r.resolve(alert(t=T0, hostname="hostA", mac="AA-BB-CC-00-11-22"))
    b = r.resolve(alert(t=T0 + MIN, agent_uid="agent-1", mac="aa:bb:cc:00:11:22"))
    assert a.primary.uid == b.primary.uid  # merged via shared MAC


def test_user_and_host_stay_separate_entities():
    r = EntityResolver()
    res = r.resolve(alert(t=T0, hostname="hostA", user="jdoe"))
    domains = sorted(e.domain for e in res.entities)
    assert domains == ["host", "user"]


def test_same_user_on_two_hosts_does_not_fuse_hosts():
    r = EntityResolver()
    a = r.resolve(alert(t=T0, hostname="hostA", user="jdoe"))
    b = r.resolve(alert(t=T0 + MIN, hostname="hostB", user="jdoe", uid="b"))
    host_a = next(e for e in a.entities if e.domain == "host")
    host_b = next(e for e in b.entities if e.domain == "host")
    user_a = next(e for e in a.entities if e.domain == "user")
    user_b = next(e for e in b.entities if e.domain == "user")
    assert host_a.uid != host_b.uid
    assert user_a.uid == user_b.uid


def test_precedence_process_guid_wins():
    r = EntityResolver()
    res = r.resolve(
        alert(t=T0, hostname="hostA", process_guid="proc-1", user="jdoe")
    )
    assert res.primary.domain == "host"
    assert res.primary.has("process_guid")


def test_precedence_upn_beats_ip():
    r = EntityResolver()
    res = r.resolve(alert(t=T0, upn="jdoe@corp.com", src_ip="203.0.113.7"))
    assert res.primary.domain == "user"


def test_unknown_source_ip_becomes_own_entity():
    r = EntityResolver()
    a = r.resolve(alert(t=T0, src_ip="203.0.113.7"))
    b = r.resolve(alert(t=T0 + MIN, src_ip="203.0.113.7", uid="b"))
    assert a.primary.uid == b.primary.uid
    assert a.primary.domain == "ip"


def test_flush_stale_entities():
    r = EntityResolver(retention_minutes=60)
    r.resolve(alert(t=T0, hostname="hostA"))
    r.resolve(alert(t=T0 + 30 * MIN, hostname="hostB", uid="b"))
    flushed = r.flush_stale(now_ms=T0 + 90 * MIN)
    assert flushed == 1  # hostA idle > 60min; hostB retained
    assert r.entity_count == 1
    # hostA can be re-created fresh afterwards without stale linkage
    again = r.resolve(alert(t=T0 + 95 * MIN, hostname="hostA", uid="c"))
    assert again.primary.domain == "host"
