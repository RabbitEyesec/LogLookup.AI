"""AI provider abstraction LiteLLM-backed, runtime-selectable, no lock-in.

One code path serves every provider (Master Specification 5.3): the provider
choice is a LiteLLM model string plus per-provider transport arguments, and
``ProviderManager`` swaps providers at runtime without a restart or a config
file edit (AI Constitution section 5).

- ``local``      -> ``ollama/<local_model>`` against ``ai.local_base_url``
- ``anthropic``  -> ``anthropic/<cloud_model>`` (default claude-opus-4-8)
- ``openai``     -> ``openai/<cloud_model>``    (default gpt-5)

API keys come from the environment via config interpolation and are never
echoed back through status or settings responses.
"""

from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from engine.config import AiConfig, ConfigError

logger = logging.getLogger(__name__)


class ProviderError(Exception):
    """Raised when a provider is misconfigured or a call cannot be made."""


@dataclass(frozen=True)
class ProviderStatus:
    """Safe-to-serialize provider state (never contains secrets)."""

    provider: str
    model_id: str
    configured: bool
    reachable: Optional[bool]  # None = not probed (cloud: no paid probe)
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class AIProvider:
    """One configured provider: model routing + transport arguments."""

    def __init__(self, config: AiConfig) -> None:
        self._config = config
        if config.provider == "local":
            if not config.local_model:
                raise ProviderError("ai.local_model is required for provider "
                                    "'local'")
            self._model_id = f"ollama/{config.local_model}"
        else:
            model = config.resolved_cloud_model
            if not model:
                raise ProviderError(
                    f"no model configured for provider {config.provider!r}"
                )
            self._model_id = f"{config.provider}/{model}"
            if not config.cloud_api_key:
                logger.warning(
                    "provider %s selected but ai.cloud_api_key is empty "
                    "(set the LOGLOOKUP_AI_KEY environment variable)",
                    config.provider,
                )

    @property
    def config(self) -> AiConfig:
        return self._config

    @property
    def provider(self) -> str:
        return self._config.provider

    @property
    def model_id(self) -> str:
        """The LiteLLM model string, e.g. ``ollama/foundation-sec-8b``."""
        return self._model_id

    @property
    def is_local(self) -> bool:
        return self._config.provider == "local"

    def completion_kwargs(self) -> dict[str, Any]:
        """Transport arguments for a LiteLLM completion call."""
        kwargs: dict[str, Any] = {
            "model": self._model_id,
            "timeout": self._config.timeout_seconds,
        }
        if self.is_local:
            kwargs["api_base"] = self._config.local_base_url
        else:
            if not self._config.cloud_api_key:
                raise ProviderError(
                    f"ai.cloud_api_key is empty; cannot call provider "
                    f"{self._config.provider!r}"
                )
            if not self._config.zero_data_retention:
                # Cloud routing rule (Master Specification 5.3): commercial
                # APIs retain data by default; the user must acknowledge a
                # Zero Data Retention arrangement before evidence leaves
                # the machine. Local mode is never affected.
                raise ProviderError(
                    "cloud call blocked: ai.zero_data_retention is disabled. "
                    "Acknowledge ZDR in Settings, or use the local provider."
                )
            kwargs["api_key"] = self._config.cloud_api_key
        return kwargs

    async def health(self) -> ProviderStatus:
        """Provider readiness without spending tokens.

        Local: probe the Ollama endpoint and check the model is present.
        Cloud: report configuration state only (reachable=None) a health
        check must not silently bill the user's API key.
        """
        if not self.is_local:
            configured = bool(self._config.cloud_api_key)
            return ProviderStatus(
                provider=self.provider,
                model_id=self._model_id,
                configured=configured,
                reachable=None,
                detail="" if configured else "ai.cloud_api_key not set",
            )
        base = self._config.local_base_url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{base}/api/tags")
        except httpx.HTTPError as exc:
            return ProviderStatus(
                provider=self.provider, model_id=self._model_id,
                configured=True, reachable=False,
                detail=f"cannot reach Ollama at {base}: {exc}",
            )
        if response.status_code != 200:
            return ProviderStatus(
                provider=self.provider, model_id=self._model_id,
                configured=True, reachable=False,
                detail=f"Ollama returned HTTP {response.status_code}",
            )
        try:
            models = [
                entry.get("name", "")
                for entry in response.json().get("models", [])
            ]
        except ValueError:
            models = []
        wanted = self._config.local_model
        present = any(name.split(":")[0] == wanted or name == wanted
                      for name in models)
        return ProviderStatus(
            provider=self.provider, model_id=self._model_id,
            configured=True, reachable=True,
            detail="" if present else
            f"model {wanted!r} not found in Ollama (ollama pull {wanted})",
        )

    async def validate(self) -> dict[str, Any]:
        """Real inference round-trip: proves the provider actually answers.

        Sends one tiny prompt through the same LiteLLM path triage uses.
        For cloud providers this spends a few tokens of the user's key, so
        it only ever runs on an explicit user action (wizard / Settings
        "Validate"), never from a background health check.
        """
        import time

        try:
            kwargs = self.completion_kwargs()
        except ProviderError as exc:
            return {
                "ok": False, "provider": self.provider,
                "model_id": self._model_id, "error": str(exc),
            }
        import litellm

        litellm.suppress_debug_info = True
        started = time.monotonic()
        try:
            response = await litellm.acompletion(
                messages=[{
                    "role": "user",
                    "content": "Reply with exactly: OK",
                }],
                # Reasoning models (e.g. the default OpenAI gpt-5) spend
                # this budget on hidden reasoning tokens first; a tiny cap
                # yields an empty answer and a false validation failure.
                # 2048 stays a sub-cent spend while leaving reasoning room.
                max_tokens=2048,
                **kwargs,
            )
        except Exception as exc:  # transport/auth/model errors, all providers
            return {
                "ok": False, "provider": self.provider,
                "model_id": self._model_id,
                "error": str(exc).split("\n", 1)[0][:300],
            }
        latency_ms = int((time.monotonic() - started) * 1000)
        content = ""
        try:
            content = (response.choices[0].message.content or "").strip()
        except (AttributeError, IndexError):
            pass
        return {
            "ok": bool(content),
            "provider": self.provider,
            "model_id": self._model_id,
            "latency_ms": latency_ms,
            "sample": content[:80],
            "error": "" if content else "provider returned an empty response",
        }


class ProviderManager:
    """Holds the active provider; switches at runtime, atomically.

    ``switch`` builds a fresh validated provider before replacing the
    current one, so a bad update never leaves the manager broken.
    """

    def __init__(self, config: AiConfig) -> None:
        self._provider = AIProvider(config)

    @property
    def current(self) -> AIProvider:
        return self._provider

    @property
    def config(self) -> AiConfig:
        return self._provider.config

    def switch(self, **changes: Any) -> AIProvider:
        """Apply config changes and swap providers without a restart."""
        allowed = {
            "provider", "local_model", "local_base_url", "cloud_model",
            "cloud_api_key", "zero_data_retention", "redaction",
            "triage_scope", "timeout_seconds", "max_retries",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ProviderError(f"unknown ai settings: {sorted(unknown)}")
        try:
            new_config = dataclasses.replace(self.config, **changes)
        except (TypeError, ConfigError) as exc:
            raise ProviderError(str(exc)) from exc
        provider = AIProvider(new_config)  # validate before swapping
        self._provider = provider
        logger.info("AI provider switched to %s (%s)",
                    new_config.provider, provider.model_id)
        return provider

    def settings_view(self) -> dict[str, Any]:
        """Current AI settings, safe for the API (key never echoed)."""
        config = self.config
        return {
            "provider": config.provider,
            "model_id": self.current.model_id,
            "local_model": config.local_model,
            "local_base_url": config.local_base_url,
            "cloud_model": config.resolved_cloud_model or None,
            "cloud_api_key_set": bool(config.cloud_api_key),
            "zero_data_retention": config.zero_data_retention,
            "redaction": config.redaction,
            "triage_scope": config.triage_scope,
            "timeout_seconds": config.timeout_seconds,
        }
