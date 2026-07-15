"""Local LLM management: detect Ollama, list models, pull models.

The onboarding wizard and Settings use this to make "Local LLM" a
zero-terminal experience: detection is automatic (binary on PATH + HTTP
probe), installed models are enumerated from the Ollama API, and
recommended models can be downloaded with live progress — all through the
engine's own API, never a shell command the user has to run.

Only management lives here; inference goes through the LiteLLM provider
abstraction (:mod:`engine.ai.provider`) like every other provider.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from typing import Any, Optional

import httpx
import msgspec

logger = logging.getLogger(__name__)

#: Registry models the wizard offers for download. Sizes are approximate
#: (registry metadata is authoritative at pull time). Kept to well-known
#: names — nothing here is invented.
RECOMMENDED_MODELS: tuple[dict[str, Any], ...] = (
    {
        "name": "qwen3:8b",
        "approx_size_gb": 5.2,
        "note": "strong general reasoning at 8B; good default for triage",
    },
    {
        "name": "llama3.1:8b",
        "approx_size_gb": 4.9,
        "note": "widely validated baseline model",
    },
    {
        "name": "qwen3:4b",
        "approx_size_gb": 2.6,
        "note": "small machine option (lower quality, low RAM)",
    },
)


class OllamaError(Exception):
    """Raised when the Ollama endpoint cannot satisfy a request."""


@dataclass
class PullState:
    """Progress of one model download (safe to serialize)."""

    model: str = ""
    active: bool = False
    status: str = ""
    completed: int = 0
    total: int = 0
    error: str = ""
    done: bool = False

    def as_dict(self) -> dict[str, Any]:
        percent = None
        if self.total:
            percent = round(100.0 * self.completed / self.total, 1)
        return {
            "model": self.model,
            "active": self.active,
            "status": self.status,
            "completed": self.completed,
            "total": self.total,
            "percent": percent,
            "error": self.error,
            "done": self.done,
        }


class OllamaClient:
    """Async client for the Ollama management API (not inference)."""

    def __init__(
        self,
        base_url: str,
        *,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client = client
        self._owns_client = client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- detection ------------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        """Detect Ollama: binary on PATH, server reachability, models."""
        state: dict[str, Any] = {
            "base_url": self._base,
            "binary_found": shutil.which("ollama") is not None,
            "running": False,
            "version": "",
            "models": [],
            "detail": "",
            "recommended": [dict(m) for m in RECOMMENDED_MODELS],
        }
        client = await self._get_client()
        try:
            response = await client.get(f"{self._base}/api/version")
        except httpx.HTTPError as exc:
            state["detail"] = f"cannot reach Ollama at {self._base}: {exc}"
            return state
        if response.status_code != 200:
            state["detail"] = f"Ollama returned HTTP {response.status_code}"
            return state
        state["running"] = True
        try:
            state["version"] = response.json().get("version", "")
        except ValueError:
            pass
        try:
            tags = await client.get(f"{self._base}/api/tags")
            if tags.status_code == 200:
                state["models"] = [
                    {
                        "name": entry.get("name", ""),
                        "size": entry.get("size", 0),
                        "modified_at": entry.get("modified_at", ""),
                        "parameter_size": (entry.get("details") or {}).get(
                            "parameter_size", ""
                        ),
                    }
                    for entry in tags.json().get("models", [])
                ]
        except (httpx.HTTPError, ValueError) as exc:
            state["detail"] = f"model list unavailable: {exc}"
        return state

    # -- model download -----------------------------------------------------------

    async def pull(self, model: str, state: PullState) -> None:
        """Stream-download a model, updating ``state`` as chunks land."""
        state.model = model
        state.active = True
        state.status = "starting"
        state.error = ""
        state.done = False
        client = await self._get_client()
        try:
            async with client.stream(
                "POST",
                f"{self._base}/api/pull",
                json={"name": model},
                timeout=httpx.Timeout(30.0, read=None),
            ) as response:
                if response.status_code != 200:
                    body = (await response.aread())[:300]
                    raise OllamaError(
                        f"pull returned HTTP {response.status_code}: "
                        f"{body.decode('utf-8', 'replace')}"
                    )
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        update = msgspec.json.decode(line)
                    except msgspec.DecodeError:
                        continue
                    if update.get("error"):
                        raise OllamaError(str(update["error"]))
                    state.status = update.get("status", state.status)
                    if "total" in update:
                        state.total = int(update.get("total") or 0)
                        state.completed = int(update.get("completed") or 0)
        except (httpx.HTTPError, OllamaError) as exc:
            state.error = str(exc)
            logger.warning("ollama pull %s failed: %s", model, exc)
        finally:
            state.active = False
            state.done = not state.error
            if state.done:
                state.status = "success"
                logger.info("ollama pull %s complete", model)


class PullManager:
    """One download at a time, tracked so the UI can poll progress."""

    def __init__(self) -> None:
        self.state = PullState()
        self._task: Optional[asyncio.Task] = None

    @property
    def busy(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self, base_url: str, model: str) -> PullState:
        if self.busy:
            raise OllamaError(
                f"a download is already running ({self.state.model!r})"
            )
        self.state = PullState(model=model, active=True, status="queued")

        async def run() -> None:
            client = OllamaClient(base_url)
            try:
                await client.pull(model, self.state)
            finally:
                await client.aclose()

        self._task = asyncio.get_running_loop().create_task(run())
        return self.state
