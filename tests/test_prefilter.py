"""Phase 6 checkpoint: deterministic benign suppression."""

import pytest

from engine.config import PrefilterConfig, SiemConfig
from engine.normalize.ocsf import (
    Actor,
    Device,
    FindingInfo,
    Metadata,
    NetworkEndpoint,
    NormalizedAlert,
    User,
)
from engine.prefilter import PreFilter


def alert(severity_id=4, src_ip=None, device_ip=None, hostname=None, user=None):
    return NormalizedAlert(
        time=1_783_728_000_000,
        time_dt="2026-07-11T00:00:00.000Z",
        severity_id=severity_id,
        metadata=Metadata(),
        finding_info=FindingInfo(title="t", uid="u1"),
        device=Device(hostname=hostname, ip=device_ip)
        if (hostname or device_ip)
        else None,
        actor=Actor(user=User(name=user)) if user else None,
        src_endpoint=NetworkEndpoint(ip=src_ip) if src_ip else None,
        unmapped={"raw": "{}"},
    )


def make_filter(**kwargs):
    defaults = dict(
        trusted_ips=("10.10.0.0/16", "192.0.2.99"),
        expected_service_accounts=("svc-backup",),
        approved_scanner_hosts=("vuln-scanner-01",),
    )
    defaults.update(kwargs)
    return PreFilter(PrefilterConfig(**defaults), SiemConfig(severity_floor="medium"))


def test_trusted_cidr_suppressed():
    decision = make_filter().evaluate(alert(src_ip="10.10.3.4"))
    assert decision.suppressed and decision.rule == "trusted_ip"
    assert decision.matched == "10.10.3.4"


def test_trusted_exact_ip_on_device_suppressed():
    decision = make_filter().evaluate(alert(device_ip="192.0.2.99"))
    assert decision.suppressed and decision.rule == "trusted_ip"


def test_untrusted_ip_kept():
    decision = make_filter().evaluate(alert(src_ip="203.0.113.7"))
    assert decision.kept


def test_service_account_suppressed_case_insensitive():
    decision = make_filter().evaluate(alert(user="SVC-Backup"))
    assert decision.suppressed and decision.rule == "expected_service_account"


def test_scanner_host_suppressed():
    decision = make_filter().evaluate(alert(hostname="VULN-SCANNER-01"))
    assert decision.suppressed and decision.rule == "approved_scanner_host"


def test_severity_below_floor_suppressed():
    decision = make_filter().evaluate(alert(severity_id=2))  # Low < Medium
    assert decision.suppressed and decision.rule == "severity_floor"


def test_severity_unknown_is_kept_not_assumed_benign():
    decision = make_filter().evaluate(alert(severity_id=0))
    assert decision.kept


def test_counts_accumulate():
    f = make_filter()
    f.evaluate(alert(src_ip="10.10.3.4"))
    f.evaluate(alert(src_ip="203.0.113.7"))
    assert f.suppressed_count == 1
    assert f.kept_count == 1


def test_invalid_cidr_config_rejected():
    with pytest.raises(ValueError):
        make_filter(trusted_ips=("not-an-ip",))


def test_no_rules_keeps_medium_and_above():
    f = PreFilter(PrefilterConfig(), SiemConfig(severity_floor="medium"))
    assert f.evaluate(alert(severity_id=3)).kept
    assert f.evaluate(alert(severity_id=2)).suppressed
