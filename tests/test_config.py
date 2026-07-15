"""Phase 0/1 checkpoint: skeleton loads config."""

import pytest

from engine.config import Config, ConfigError, config_from_dict, load_config


def test_example_config_loads(monkeypatch):
    monkeypatch.setenv("LOGLOOKUP_SIEM_KEY", "test-key-123")
    cfg = load_config("config.example.yaml")
    assert isinstance(cfg, Config)
    assert cfg.siem.type == "elastic"
    assert cfg.siem.api_key == "test-key-123"  # ${ENV} interpolated
    assert cfg.siem.poll_seconds == 60
    assert cfg.siem.severity_floor_id == 3  # medium
    assert cfg.correlation.window_minutes == 60
    assert cfg.correlation.entity_precedence == ("process_guid", "upn", "mac", "ip")
    assert cfg.correlation.risk.weight_for(4) == 8
    assert cfg.correlation.risk.surface_threshold == 10
    assert cfg.prefilter.trusted_ips == ()
    assert cfg.ai.provider == "local"
    assert cfg.ai.rag.top_k == 8
    assert cfg.ai.resolved_cloud_model == ""  # local provider has no cloud model
    assert cfg.output.results_index == "loglookup-results"
    assert (
        cfg.output.dashboard_url_for("CHAIN-2026-07-11-hostA-001")
        == "http://localhost:8080/incident/CHAIN-2026-07-11-hostA-001"
    )


def test_env_var_not_set_becomes_empty(monkeypatch):
    monkeypatch.delenv("LOGLOOKUP_SIEM_KEY", raising=False)
    cfg = load_config("config.example.yaml")
    assert cfg.siem.api_key == ""


def test_missing_file_raises():
    with pytest.raises(ConfigError):
        load_config("does-not-exist.yaml")


def test_bad_severity_floor_raises(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("siem:\n  severity_floor: extreme\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_defaults_when_sections_missing(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("siem:\n  host: http://elastic:9200\n")
    cfg = load_config(p)
    assert cfg.siem.host == "http://elastic:9200"
    assert cfg.correlation.window_minutes == 60
    assert cfg.correlation.watermark_grace_seconds == 60
    assert cfg.correlation.risk.misconfiguration_downgrade == 0.5


def test_config_from_dict_does_not_mutate_caller_data():
    data = {
        "correlation": {"risk": {"surface_threshold": 12}},
        "ai": {"rag": {"top_k": 4}},
    }
    config_from_dict(data)
    assert data["correlation"]["risk"]["surface_threshold"] == 12
    assert data["ai"]["rag"]["top_k"] == 4
