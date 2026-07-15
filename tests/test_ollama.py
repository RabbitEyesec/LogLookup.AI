"""Local LLM management acceptance: Ollama detection, models, downloads."""

from __future__ import annotations

import json

import httpx
import pytest

from engine.ai.ollama import (
    OllamaClient,
    PullManager,
    PullState,
    RECOMMENDED_MODELS,
)


def make_client(handler) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    return OllamaClient(
        "http://localhost:11434",
        client=httpx.AsyncClient(transport=transport),
    )


async def test_status_detects_running_server_and_models():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.9.2"})
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [
                {"name": "qwen3:8b", "size": 5_200_000_000,
                 "modified_at": "2026-07-01T00:00:00Z",
                 "details": {"parameter_size": "8.2B"}},
            ]})
        return httpx.Response(404)

    client = make_client(handler)
    state = await client.status()
    assert state["running"] is True
    assert state["version"] == "0.9.2"
    assert state["models"][0]["name"] == "qwen3:8b"
    assert state["models"][0]["parameter_size"] == "8.2B"
    # Recommendations ship with every status response for the wizard.
    assert [m["name"] for m in state["recommended"]] == [
        m["name"] for m in RECOMMENDED_MODELS
    ]


async def test_status_when_not_running_is_honest():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    state = await make_client(handler).status()
    assert state["running"] is False
    assert "cannot reach Ollama" in state["detail"]
    assert state["models"] == []


async def test_pull_streams_progress_to_completion():
    lines = [
        {"status": "pulling manifest"},
        {"status": "downloading", "total": 100, "completed": 40},
        {"status": "downloading", "total": 100, "completed": 100},
        {"status": "success"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/pull"
        body = "\n".join(json.dumps(l) for l in lines)
        return httpx.Response(200, content=body.encode())

    state = PullState()
    await make_client(handler).pull("qwen3:8b", state)
    assert state.done is True and state.error == ""
    assert state.status == "success"
    assert state.completed == 100 and state.total == 100
    assert state.as_dict()["percent"] == 100.0


async def test_pull_reports_registry_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=json.dumps({"error": "model not found"}).encode()
        )

    state = PullState()
    await make_client(handler).pull("no-such-model:1b", state)
    assert state.done is False
    assert "model not found" in state.error


async def test_pull_manager_rejects_concurrent_downloads(monkeypatch):
    import asyncio

    manager = PullManager()
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_pull(self, model, state):
        started.set()
        await release.wait()
        state.done = True

    monkeypatch.setattr(OllamaClient, "pull", slow_pull)
    manager.start("http://localhost:11434", "qwen3:8b")
    await started.wait()
    with pytest.raises(Exception, match="already running"):
        manager.start("http://localhost:11434", "llama3.1:8b")
    release.set()
    await manager._task
    assert manager.busy is False
