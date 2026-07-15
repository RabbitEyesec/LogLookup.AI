"""Shared fixtures: a correlated fixture cluster + a fixture ATT&CK KB."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from engine.ai.kb import AttackKB
from engine.config import Config, load_config
from engine.pipeline import Pipeline

ATTACK_CHAIN_FIXTURE = Path(__file__).parent / "fixtures" / "attack_chain.ndjson"


@pytest.fixture()
def engine_config(tmp_path) -> Config:
    """Config matching the attack-chain fixture scenario."""
    cfg = {
        "siem": {"type": "elastic", "severity_floor": "medium"},
        "correlation": {
            "window_minutes": 60,
            "risk": {"surface_threshold": 10},
        },
        "prefilter": {"approved_scanner_hosts": ["vuln-scanner-01"]},
        "ai": {"provider": "local", "rag": {"backend": "lexical"}},
        "output": {"dashboard_base_url": "http://localhost:8080"},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return load_config(path)


@pytest.fixture()
def correlated_pipeline(engine_config):
    """Pipeline after a batch run over the attack-chain fixture.

    Yields ``(pipeline, result)`` where result.clusters[0] is the surfaced
    brute-force -> credential-dump -> lateral-movement chain.
    """
    pipeline = Pipeline(engine_config)
    result = pipeline.run_batch_file(ATTACK_CHAIN_FIXTURE)
    return pipeline, result


@pytest.fixture()
def fixture_kb() -> AttackKB:
    """Small ATT&CK KB with the techniques the fixture scenario involves."""
    from tests.test_kb import _stix_technique

    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "19.1"},
            _stix_technique("T1110", "Brute Force"),
            _stix_technique("T1003", "OS Credential Dumping"),
            _stix_technique("T1021", "Remote Services",
                            tactic="lateral-movement"),
            _stix_technique("T1059.001", "PowerShell", tactic="execution"),
        ],
    }
    return AttackKB.from_bundle(bundle, source="fixture")
