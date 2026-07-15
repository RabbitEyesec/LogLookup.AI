"""Managed settings acceptance: config persisted by the app, secrets
diverted to the encrypted store, no user-facing env vars required."""

from __future__ import annotations

import pytest

from engine.config import ConfigError
from engine.secure.store import SIEM_API_KEY, ai_key_name
from engine.settings import ManagedSettings


def wizard_payload(**siem_overrides):
    siem = {
        "host": "https://elastic.internal:9200",
        "api_key": "elastic-secret",
        "alert_index": ".alerts-security",
        "poll_seconds": 60,
        "severity_floor": "medium",
        **siem_overrides,
    }
    ai = {
        "provider": "anthropic",
        "cloud_api_key": "sk-ant-secret",
        "redaction": True,
        "zero_data_retention": True,
    }
    return siem, ai


def test_setup_persists_and_reloads(tmp_path):
    settings = ManagedSettings(tmp_path)
    assert settings.setup_complete is False
    siem, ai = wizard_payload()
    config = settings.save_setup(siem, ai)
    assert settings.setup_complete is True
    # Secrets injected into the typed config...
    assert config.siem.api_key == "elastic-secret"
    assert config.ai.cloud_api_key == "sk-ant-secret"
    # ...from the encrypted store, not the YAML file.
    text = (tmp_path / "config.yaml").read_text()
    assert "elastic-secret" not in text
    assert "sk-ant-secret" not in text
    assert settings.secrets.get(SIEM_API_KEY) == "elastic-secret"
    assert settings.secrets.get(ai_key_name("anthropic")) == "sk-ant-secret"
    # A fresh instance (restart) sees the same state.
    again = ManagedSettings(tmp_path).load()
    assert again.siem.host == "https://elastic.internal:9200"
    assert again.ai.provider == "anthropic"
    assert again.ai.cloud_api_key == "sk-ant-secret"


def test_rag_paths_default_into_app_home(tmp_path):
    settings = ManagedSettings(tmp_path)
    config = settings.load()
    assert config.ai.rag.kb_path == str(tmp_path / "attack_kb.json")
    assert config.ai.rag.index_dir == str(tmp_path / "attack_index")


def test_invalid_setup_persists_nothing(tmp_path):
    settings = ManagedSettings(tmp_path)
    siem, ai = wizard_payload(severity_floor="apocalyptic")
    with pytest.raises(ConfigError):
        settings.save_setup(siem, ai)
    assert settings.setup_complete is False
    assert settings.secrets.get(SIEM_API_KEY) == ""  # nothing half-written


def test_ai_changes_persist_and_keep_keys_per_provider(tmp_path):
    settings = ManagedSettings(tmp_path)
    siem, ai = wizard_payload()
    settings.save_setup(siem, ai)
    settings.apply_ai_changes({
        "provider": "openai", "cloud_api_key": "sk-oa-secret",
    })
    config = settings.load()
    assert config.ai.provider == "openai"
    assert config.ai.cloud_api_key == "sk-oa-secret"
    # Switching back to anthropic finds its own key again.
    settings.apply_ai_changes({"provider": "anthropic"})
    assert settings.load().ai.cloud_api_key == "sk-ant-secret"
    assert "sk-oa-secret" not in (tmp_path / "config.yaml").read_text()


def test_siem_changes_persist(tmp_path):
    settings = ManagedSettings(tmp_path)
    siem, ai = wizard_payload()
    settings.save_setup(siem, ai)
    config = settings.apply_siem_changes({
        "alert_index": "wazuh-alerts-*", "api_key": "rotated-key",
    })
    assert config.siem.alert_index == "wazuh-alerts-*"
    assert config.siem.api_key == "rotated-key"
    assert settings.secrets.get(SIEM_API_KEY) == "rotated-key"


def test_invalid_ai_change_rejected_before_write(tmp_path):
    settings = ManagedSettings(tmp_path)
    siem, ai = wizard_payload()
    settings.save_setup(siem, ai)
    with pytest.raises(ConfigError):
        settings.apply_ai_changes({"provider": "skynet"})
    assert settings.load().ai.provider == "anthropic"  # unchanged
