"""Phase 11 acceptance: provider abstraction + runtime switching."""

from __future__ import annotations

import pytest

from engine.ai.provider import AIProvider, ProviderError, ProviderManager
from engine.config import AiConfig, ConfigError


def test_local_provider_routes_to_ollama():
    provider = AIProvider(AiConfig(provider="local", local_model="qwen3:8b"))
    assert provider.model_id == "ollama/qwen3:8b"
    kwargs = provider.completion_kwargs()
    assert kwargs["api_base"] == "http://localhost:11434"
    assert "api_key" not in kwargs


def test_cloud_defaults_per_provider():
    anthropic = AIProvider(AiConfig(provider="anthropic", cloud_api_key="k"))
    assert anthropic.model_id == "anthropic/claude-opus-4-8"
    openai = AIProvider(AiConfig(provider="openai", cloud_api_key="k"))
    assert openai.model_id == "openai/gpt-5"


def test_cloud_model_override():
    provider = AIProvider(
        AiConfig(provider="anthropic", cloud_model="claude-sonnet-5",
                 cloud_api_key="k")
    )
    assert provider.model_id == "anthropic/claude-sonnet-5"


def test_cloud_call_without_key_refuses():
    provider = AIProvider(AiConfig(provider="anthropic"))
    with pytest.raises(ProviderError, match="cloud_api_key"):
        provider.completion_kwargs()


def test_unknown_provider_rejected_at_config():
    with pytest.raises(ConfigError):
        AiConfig(provider="skynet")


def test_runtime_switch_without_restart():
    manager = ProviderManager(AiConfig(provider="local"))
    assert manager.current.model_id == "ollama/foundation-sec-8b"
    manager.switch(provider="anthropic", cloud_api_key="secret-key")
    assert manager.current.model_id == "anthropic/claude-opus-4-8"
    # Switch back — no restart, no config file edit.
    manager.switch(provider="local", local_model="qwen3:8b")
    assert manager.current.model_id == "ollama/qwen3:8b"


def test_failed_switch_leaves_manager_intact():
    manager = ProviderManager(AiConfig(provider="local"))
    with pytest.raises(ProviderError):
        manager.switch(provider="not-a-provider")
    with pytest.raises(ProviderError):
        manager.switch(favourite_colour="green")
    assert manager.current.model_id == "ollama/foundation-sec-8b"


def test_settings_view_never_leaks_key():
    manager = ProviderManager(
        AiConfig(provider="openai", cloud_api_key="super-secret")
    )
    view = manager.settings_view()
    assert view["cloud_api_key_set"] is True
    assert "super-secret" not in str(view)


async def test_local_health_unreachable_is_honest():
    provider = AIProvider(
        AiConfig(provider="local",
                 local_base_url="http://127.0.0.1:1")  # nothing listens here
    )
    status = provider.health()
    result = await status
    assert result.configured is True
    assert result.reachable is False
    assert "cannot reach" in result.detail


async def test_cloud_health_reports_configuration_only():
    status = await AIProvider(
        AiConfig(provider="anthropic", cloud_api_key="k")
    ).health()
    assert status.configured is True
    assert status.reachable is None  # no paid probe
    missing = await AIProvider(AiConfig(provider="anthropic")).health()
    assert missing.configured is False
