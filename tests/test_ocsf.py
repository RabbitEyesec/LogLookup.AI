"""Phase 2 checkpoint: OCSF DetectionFinding foundation."""

import pytest

from engine.normalize.ocsf import (
    CLASS_UID,
    Device,
    FindingInfo,
    Metadata,
    MitreAttack,
    NormalizedAlert,
    Product,
    Tactic,
    Technique,
    decode_alert,
    encode_alert,
)
from engine.normalize.ocsf_bridge import to_detection_finding
from engine.normalize.timeutil import TimestampError, coerce_time


def make_alert(**overrides) -> NormalizedAlert:
    base = dict(
        time=1752192000000,
        time_dt="2026-07-11T00:00:00.000Z",
        severity_id=4,
        metadata=Metadata(product=Product(vendor_name="Elastic"), uid="a-1"),
        finding_info=FindingInfo(
            title="Suspicious login",
            uid="a-1",
            attacks=[
                MitreAttack(
                    tactic=Tactic(name="Credential Access", uid="TA0006"),
                    technique=Technique(name="Brute Force", uid="T1110"),
                )
            ],
        ),
        device=Device(hostname="hostA", ip="10.0.0.5"),
        unmapped={"raw": '{"original": true}'},
    )
    base.update(overrides)
    return NormalizedAlert(**base)


def test_ocsf_envelope_constants():
    alert = make_alert()
    assert alert.class_uid == 2004
    assert alert.category_uid == 2
    assert alert.type_uid == 200401
    assert alert.severity_label() == "High"


def test_stable_key_order_and_roundtrip():
    alert = make_alert()
    first = encode_alert(alert)
    second = encode_alert(decode_alert(first))
    assert first == second  # byte-identical: stable key order + types


def test_raw_preserved_in_unmapped():
    alert = make_alert()
    assert alert.unmapped["raw"] == '{"original": true}'


def test_arrays_stay_arrays():
    alert = make_alert()
    assert isinstance(alert.finding_info.attacks, list)
    assert isinstance(alert.metadata.labels, list)


def test_bridge_to_py_ocsf_models():
    finding = to_detection_finding(make_alert())
    assert finding.class_uid == CLASS_UID
    assert int(finding.severity_id) == 4
    assert finding.time == 1752192000000
    assert finding.finding_info.title == "Suspicious login"
    assert finding.finding_info.attacks[0].technique.uid == "T1110"
    assert finding.metadata.product.vendor_name == "Elastic"
    assert finding.unmapped == {"raw": '{"original": true}'}


def test_time_is_required():
    with pytest.raises(TypeError):
        NormalizedAlert(severity_id=1)  # no time/time_dt


class TestCoerceTime:
    def test_iso_with_zone(self):
        ms, iso = coerce_time("2026-07-11T02:30:00+02:00")
        assert iso == "2026-07-11T00:30:00.000Z"
        assert ms == 1783729800000

    def test_iso_z(self):
        ms, iso = coerce_time("2026-07-11T00:30:00Z")
        assert iso == "2026-07-11T00:30:00.000Z"

    def test_epoch_seconds_and_millis_agree(self):
        assert coerce_time(1752192000) == coerce_time(1752192000000)

    def test_naive_iso_uses_configured_offset(self):
        # Legacy source in UTC+05:30 with no zone in the string
        ms, iso = coerce_time("2026-07-11 06:00:00",
                              default_offset_minutes=330)
        assert iso == "2026-07-11T00:30:00.000Z"

    def test_rfc3164_syslog(self):
        ms, iso = coerce_time("Oct  3 10:15:32", default_offset_minutes=-240,
                              assume_year=2025)
        assert iso == "2025-10-03T14:15:32.000Z"

    def test_garbage_raises(self):
        with pytest.raises(TimestampError):
            coerce_time("not a time")
        with pytest.raises(TimestampError):
            coerce_time(None)
