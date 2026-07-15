"""Phase 4 checkpoint: raw records stream from file and Elastic sources."""

import pytest

from engine.ingest import (
    IngestError,
    hit_to_record,
    iter_elastic_batch,
    iter_file_records,
)

from tests.test_connector import FakeElastic, make_connector, make_hit


def test_ndjson_file_raw_is_byte_for_byte(tmp_path):
    line1 = b'{"@timestamp": "2026-07-11T00:00:00Z", "rule": {"name": "r1"}}'
    line2 = b'{"@timestamp": "2026-07-11T00:01:00Z", "rule": {"name": "r2"}}'
    p = tmp_path / "alerts.ndjson"
    p.write_bytes(line1 + b"\n" + line2 + b"\n")
    records = list(iter_file_records(p))
    assert len(records) == 2
    assert records[0].raw == line1  # exact original bytes
    assert records[1].payload["rule"]["name"] == "r2"
    assert records[0].received_at.endswith("Z")


def test_json_array_file(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text('[{"a": 1}, {"a": 2}]')
    records = list(iter_file_records(p))
    assert [r.payload["a"] for r in records] == [1, 2]


def test_bad_line_skipped_not_fatal(tmp_path):
    p = tmp_path / "alerts.ndjson"
    p.write_bytes(b'{"ok": 1}\nnot json at all\n{"ok": 2}\n')
    records = list(iter_file_records(p))
    assert [r.payload["ok"] for r in records] == [1, 2]


def test_csv_file(tmp_path):
    p = tmp_path / "alerts.csv"
    p.write_text("timestamp,host,rule\n2026-07-11T00:00:00Z,hostA,Brute force\n")
    records = list(iter_file_records(p))
    assert len(records) == 1
    assert records[0].payload["host"] == "hostA"
    assert records[0].raw == b"2026-07-11T00:00:00Z,hostA,Brute force"


def test_missing_file_raises():
    with pytest.raises(IngestError):
        list(iter_file_records("no-such-file.json"))


def test_hit_to_record_wraps_source():
    hit = make_hit("x1", 1000, foo="bar")
    record = hit_to_record(hit)
    assert record.source == "elastic"
    assert record.payload["_id"] == "x1"
    assert b'"foo":"bar"' in record.raw


async def test_elastic_batch_records():
    fake = FakeElastic([make_hit("e1", 1000), make_hit("e2", 2000)])
    conn = make_connector(fake)
    records = [r async for r in iter_elastic_batch(conn, 0, 10_000)]
    assert [r.payload["_id"] for r in records] == ["e1", "e2"]
    assert all(r.source == "elastic" for r in records)
