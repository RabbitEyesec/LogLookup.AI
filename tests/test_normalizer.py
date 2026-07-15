"""Phase 5 acceptance (Build Plan 2.3 — Normalizer):

- Malformed field -> event still emitted, flagged, in unmapped, no crash.
- Legacy timestamp -> UTC ISO-8601 + Z via configured offset.
- Single value for an array field -> 1-element array.
- Raw event present in unmapped, byte-for-byte.
"""

import msgspec
import pytest

from engine.ingest import RawRecord
from engine.normalize.adapters import AdapterNotImplemented, get_adapter
from engine.normalize.ocsf import PARSE_ERROR_LABEL


def record(payload: dict, source="file", raw: bytes | None = None) -> RawRecord:
    return RawRecord(
        source=source,
        payload=payload,
        raw=raw if raw is not None else msgspec.json.encode(payload),
        received_at="2026-07-11T12:00:00.000Z",
    )


BASE_EVENT = {
    "@timestamp": "2026-07-11T10:00:00Z",
    "rule": {"name": "Brute force attempt"},
    "severity": "high",
    "host": {"name": "hostA", "ip": ["10.0.0.5"]},
    "user": {"name": "jdoe"},
    "source": {"ip": "203.0.113.7", "port": 4444},
    "threat": {
        "tactic": {"name": "Credential Access", "id": "TA0006"},
        "technique": {"id": ["T1110"], "name": ["Brute Force"]},
    },
}


def test_clean_event_normalizes():
    alert = get_adapter("file").parse(record(BASE_EVENT))
    assert alert.class_uid == 2004
    assert alert.time_dt == "2026-07-11T10:00:00.000Z"
    assert alert.severity_id == 4
    assert alert.finding_info.title == "Brute force attempt"
    assert alert.device.hostname == "hostA"
    assert alert.device.ip == "10.0.0.5"
    assert alert.actor.user.name == "jdoe"
    assert alert.src_endpoint.ip == "203.0.113.7"
    assert alert.src_endpoint.port == 4444
    assert alert.finding_info.attacks[0].technique.uid == "T1110"
    assert alert.finding_info.attacks[0].tactic.name == "Credential Access"
    assert not alert.has_parse_errors
    assert alert.metadata.processed_time == "2026-07-11T12:00:00.000Z"


def test_malformed_field_flagged_routed_to_unmapped_no_crash():
    event = dict(BASE_EVENT)
    event["process"] = {"pid": "not-a-pid"}
    alert = get_adapter("file").parse(record(event))
    # event still emitted
    assert alert.finding_info.title == "Brute force attempt"
    # flagged
    assert alert.has_parse_errors
    assert PARSE_ERROR_LABEL in alert.metadata.labels
    # routed to unmapped
    assert alert.unmapped["fields"]["process.pid"] == "not-a-pid"
    assert any("process.pid" in e for e in alert.unmapped["parse_errors"])
    # the well-formed part of the process is unaffected elsewhere
    assert alert.actor.process is None or alert.actor.process.pid is None


def test_numeric_string_is_coerced_not_flagged():
    event = dict(BASE_EVENT)
    event["source"] = {"ip": "203.0.113.7", "port": "404"}  # "404" not 404
    alert = get_adapter("file").parse(record(event))
    assert alert.src_endpoint.port == 404
    assert not alert.has_parse_errors


def test_legacy_timestamp_uses_configured_offset():
    event = dict(BASE_EVENT)
    event["@timestamp"] = "Oct  3 10:15:32"  # RFC 3164: no year, no zone
    adapter = get_adapter("file", default_offset_minutes=-240, assume_year=2025)
    alert = adapter.parse(record(event))
    assert alert.time_dt == "2025-10-03T14:15:32.000Z"  # UTC ISO-8601 + Z


def test_unparseable_timestamp_flagged_falls_back_to_ingestion_time():
    event = dict(BASE_EVENT)
    event["@timestamp"] = "yesterday-ish"
    alert = get_adapter("file").parse(record(event))
    assert alert.has_parse_errors
    assert alert.time_dt == "2026-07-11T12:00:00.000Z"  # ingestion time
    assert alert.unmapped["fields"]["@timestamp"] == "yesterday-ish"


def test_single_value_for_array_field_becomes_one_element_array():
    event = dict(BASE_EVENT)
    event["threat"] = {
        "tactic": {"name": "Credential Access", "id": "TA0006"},
        "technique": {"id": "T1110", "name": "Brute Force"},  # scalar, not list
    }
    alert = get_adapter("file").parse(record(event))
    assert isinstance(alert.finding_info.attacks, list)
    assert len(alert.finding_info.attacks) == 1
    assert alert.finding_info.attacks[0].technique.uid == "T1110"


def test_raw_event_in_unmapped_byte_for_byte():
    raw = b'{"@timestamp": "2026-07-11T10:00:00Z", "rule": {"name": "x"}}'
    alert = get_adapter("file").parse(
        record(msgspec.json.decode(raw), raw=raw)
    )
    assert alert.unmapped["raw"].encode() == raw


def test_unknown_severity_flagged_not_fatal():
    event = dict(BASE_EVENT)
    event["severity"] = "ultra-mega"
    alert = get_adapter("file").parse(record(event))
    assert alert.severity_id == 0
    assert alert.has_parse_errors


def test_elastic_adapter_maps_kibana_alert():
    hit = {
        "_id": "abc123",
        "_source": {
            "@timestamp": "2026-07-11T10:05:00.000Z",
            "kibana.alert.rule.name": "Possible Credential Dumping",
            "kibana.alert.severity": "critical",
            "kibana.alert.uuid": "abc123",
            "kibana.alert.reason": "process lsass access",
            "host": {"name": "hostA", "ip": ["10.0.0.5"], "id": "agent-guid-1"},
            "user": {"name": "jdoe", "domain": "CORP"},
            "process": {"entity_id": "proc-guid-9", "pid": 512,
                        "name": "mimikatz.exe"},
            "kibana.alert.rule.threat": {
                "tactic": {"name": "Credential Access", "id": "TA0006"},
                "technique": {"id": ["T1003"], "name": ["OS Credential Dumping"]},
            },
        },
    }
    alert = get_adapter("elastic").parse(record(hit, source="elastic"))
    assert alert.finding_info.uid == "abc123"
    assert alert.severity_id == 5
    assert alert.device.uid == "agent-guid-1"
    assert alert.actor.process.uid == "proc-guid-9"
    assert alert.finding_info.attacks[0].technique.uid == "T1003"
    assert alert.metadata.product.vendor_name == "Elastic"


def test_stub_adapters_raise_clearly():
    rec = record(BASE_EVENT)
    for name in ("splunk", "sentinel"):
        with pytest.raises(AdapterNotImplemented):
            get_adapter(name).parse(rec)


def test_unknown_source_type_rejected():
    with pytest.raises(KeyError):
        get_adapter("qradar")
