"""End-to-end pipeline checkpoint (Phase 0-9 boundary):

fixture alerts in -> normalize -> pre-filter -> resolve -> correlate ->
risk -> one surfaced attack chain with a locked-format cluster_id.
"""

from pathlib import Path

import pytest
import yaml

from engine.config import load_config
from engine.pipeline import Pipeline

from tests.test_connector import FakeElastic, make_connector, make_hit

FIXTURE = Path(__file__).parent / "fixtures" / "attack_chain.ndjson"


@pytest.fixture()
def config(tmp_path):
    cfg = {
        "siem": {"type": "elastic", "severity_floor": "medium"},
        "correlation": {
            "window_minutes": 60,
            "risk": {"surface_threshold": 10},
        },
        "prefilter": {"approved_scanner_hosts": ["vuln-scanner-01"]},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return load_config(path)


def test_batch_file_end_to_end(config):
    pipeline = Pipeline(config)
    result = pipeline.run_batch_file(FIXTURE)

    # Ingestion and pre-filtering accounting.
    assert result.ingested == 6
    assert result.normalized == 6
    assert result.suppressed == 2  # approved scanner + below severity floor
    assert result.correlated == 4

    # The attack chain: brute force -> cred dump -> lateral movement,
    # stitched across hostA and hostB via the shared user; the unrelated
    # hostC alert forms its own (unsurfaced) chain.
    assert len(result.clusters) == 2
    chain, lone = result.clusters
    assert chain.cluster_id == "CHAIN-2026-07-11-hostA-001"
    assert chain.alert_uids == ["evt-001", "evt-004", "evt-005"]
    assert chain.disposition == "progressing"
    assert chain.tactic_sequence == [
        "Credential Access", "Credential Access", "Lateral Movement",
    ]
    assert chain.surfaced is True
    assert chain.risk_score >= 10

    assert lone.alert_uids == ["evt-006"]
    assert lone.surfaced is False

    summary = pipeline.summary(result)
    assert summary["surfaced_chains"] == 1
    assert summary["suppressed_benign"] == 2


def test_batch_file_is_deterministic(config, tmp_path):
    first = Pipeline(config).run_batch_file(FIXTURE)
    # Rebuild config/pipeline from scratch: identical input, identical ids.
    second = Pipeline(config).run_batch_file(FIXTURE)
    assert [c.cluster_id for c in first.clusters] == [
        c.cluster_id for c in second.clusters
    ]
    assert [c.risk_score for c in first.clusters] == [
        c.risk_score for c in second.clusters
    ]


async def test_batch_elastic_end_to_end(config):
    hits = [
        make_hit(
            "es-1",
            1_783_764_000_000,  # 2026-07-11T10:00:00Z
            **{
                "kibana.alert.rule.name": "SSH brute force attempts",
                "kibana.alert.severity": "high",
                "kibana.alert.uuid": "es-1",
                "host": {"name": "hostA"},
                "user": {"name": "jdoe"},
            },
        ),
        make_hit(
            "es-2",
            1_783_765_200_000,  # 2026-07-11T10:20:00Z
            **{
                "kibana.alert.rule.name": "Credential dumping",
                "kibana.alert.severity": "critical",
                "kibana.alert.uuid": "es-2",
                "host": {"name": "hostA"},
                "user": {"name": "jdoe"},
            },
        ),
    ]
    fake = FakeElastic(hits)
    pipeline = Pipeline(config)
    result = await pipeline.run_batch_elastic(
        0, 2_000_000_000_000, connector=make_connector(fake)
    )
    assert result.ingested == 2
    assert len(result.clusters) == 1
    cluster = result.clusters[0]
    assert cluster.alert_uids == ["es-1", "es-2"]
    assert cluster.cluster_id.startswith("CHAIN-2026-07-11-")
    assert cluster.surfaced is True  # 8 + 16 = 24 >= 10


def test_cli_batch_file(config, tmp_path, capsys):
    from engine.pipeline import main

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "siem": {"severity_floor": "medium"},
                "prefilter": {"approved_scanner_hosts": ["vuln-scanner-01"]},
            }
        )
    )
    exit_code = main(["--config", str(cfg_path), "--input", str(FIXTURE)])
    assert exit_code == 0
    out_lines = capsys.readouterr().out.strip().splitlines()
    assert any("CHAIN-2026-07-11-hostA-001" in line for line in out_lines)
    assert '"summary"' in out_lines[-1]
