"""Onboarding wizard acceptance: first-run gating, live SIEM test, index
detection, provider validation, completion, and settings persistence."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

import engine.api.setup as api_setup
from engine.ai.service import TriageService
from engine.api.server import create_app
from engine.connectors.elastic import ElasticConnector
from engine.secure.store import SIEM_API_KEY, ai_key_name
from engine.settings import ManagedSettings


@pytest.fixture()
def managed_client(engine_config, tmp_path):
    """App in managed mode with a fresh (un-setup) home directory."""
    home = tmp_path / "home"
    settings = ManagedSettings(home)
    service = TriageService(engine_config)
    app = create_app(engine_config, service, settings=settings)
    with TestClient(app) as client:
        yield client, settings


def elastic_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/":
        return httpx.Response(200, json={
            "name": "node-1", "cluster_name": "prod-siem",
            "version": {"number": "8.14.0"},
        })
    if request.url.path == "/_cat/indices":
        return httpx.Response(200, json=[
            {"index": ".alerts-security.alerts-default",
             "docs.count": "412", "store.size": "2mb"},
            {"index": "logs-app-default", "docs.count": "90000",
             "store.size": "1gb"},
            {"index": "kibana_sample", "docs.count": "7",
             "store.size": "1mb"},
        ])
    return httpx.Response(404)


@pytest.fixture()
def fake_elastic(monkeypatch):
    def connector(siem, **kwargs):
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(elastic_handler),
            base_url=siem.host or "http://test",
        )
        return ElasticConnector(siem, client=client)

    monkeypatch.setattr(api_setup, "make_connector", connector)


# -- first-run gating ---------------------------------------------------------


def test_first_run_redirects_to_wizard(managed_client):
    client, _settings = managed_client
    assert client.get("/api/setup").json() == {
        "managed": True, "needs_setup": True,
    }
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 307
    assert root.headers["location"] == "/setup"
    wizard = client.get("/setup")
    assert wizard.status_code == 200
    assert "Welcome" in wizard.text


def test_dev_mode_never_needs_setup(engine_config):
    service = TriageService(engine_config)
    app = create_app(engine_config, service)  # no managed settings
    with TestClient(app) as client:
        assert client.get("/api/setup").json()["needs_setup"] is False
        assert client.get("/", follow_redirects=False).status_code == 200
        complete = client.post("/api/setup/complete", json={
            "siem": {"host": ""}, "ai": {"provider": "local"},
        })
        assert complete.status_code == 409  # persistence requires managed mode


# -- SIEM test + index detection ---------------------------------------------------


def test_siem_test_detects_indices(managed_client, fake_elastic):
    client, _settings = managed_client
    result = client.post("/api/setup/siem/test", json={
        "host": "https://elastic.internal:9200", "api_key": "k",
    }).json()
    assert result["ok"] is True
    assert result["cluster"]["cluster_name"] == "prod-siem"
    assert result["cluster"]["version"] == "8.14.0"
    names = [i["index"] for i in result["indices"]]
    assert ".alerts-security.alerts-default" in names
    # Alert-looking indices are suggested first; unrelated ones are not.
    assert result["suggested"][0] == ".alerts-security.alerts-default"
    assert "kibana_sample" not in result["suggested"]


def test_siem_test_requires_full_url(managed_client):
    client, _settings = managed_client
    response = client.post("/api/setup/siem/test",
                           json={"host": "localhost:9200"})
    assert response.status_code == 400


def test_siem_test_reports_failure_honestly(managed_client, monkeypatch):
    def connector(siem, **kwargs):
        def refuse(request):
            raise httpx.ConnectError("connection refused")
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(refuse), base_url=siem.host
        )
        return ElasticConnector(siem, client=client)

    monkeypatch.setattr(api_setup, "make_connector", connector)
    client, _settings = managed_client
    result = client.post("/api/setup/siem/test", json={
        "host": "https://down.example:9200",
    }).json()
    assert result["ok"] is False
    assert "cannot reach" in result["error"]


# -- completion ----------------------------------------------------------------------


def test_setup_complete_persists_and_unlocks(managed_client):
    client, settings = managed_client
    response = client.post("/api/setup/complete", json={
        "siem": {"host": "", "api_key": "es-key",
                 "alert_index": ".alerts-security"},
        "ai": {"provider": "anthropic", "cloud_api_key": "sk-ant-w",
               "redaction": True, "zero_data_retention": True},
    })
    assert response.status_code == 200
    assert client.get("/api/setup").json()["needs_setup"] is False
    # Wizard no longer reachable; dashboard is.
    assert client.get("/setup", follow_redirects=False).status_code == 307
    assert client.get("/", follow_redirects=False).status_code == 200
    # Persisted: flag set, secrets encrypted, nothing leaked to YAML.
    assert settings.setup_complete is True
    assert settings.secrets.get(SIEM_API_KEY) == "es-key"
    assert settings.secrets.get(ai_key_name("anthropic")) == "sk-ant-w"
    text = settings.config_path.read_text()
    assert "es-key" not in text and "sk-ant-w" not in text
    # Live provider switched without a restart.
    assert client.get("/api/settings/ai").json()["provider"] == "anthropic"


def test_setup_complete_rejects_bad_provider(managed_client):
    client, settings = managed_client
    response = client.post("/api/setup/complete", json={
        "siem": {"host": ""}, "ai": {"provider": "skynet"},
    })
    assert response.status_code == 400
    assert settings.setup_complete is False


# -- runtime settings persistence -------------------------------------------------------


def test_ai_settings_put_persists_in_managed_mode(managed_client):
    client, settings = managed_client
    client.post("/api/setup/complete", json={
        "siem": {"host": ""}, "ai": {"provider": "local"},
    })
    updated = client.put("/api/settings/ai", json={
        "provider": "openai", "cloud_api_key": "sk-oa-w",
    }).json()
    assert updated["provider"] == "openai"
    reloaded = ManagedSettings(settings.home).load()
    assert reloaded.ai.provider == "openai"
    assert reloaded.ai.cloud_api_key == "sk-oa-w"


def test_siem_settings_put_persists(managed_client):
    client, settings = managed_client
    client.post("/api/setup/complete", json={
        "siem": {"host": ""}, "ai": {"provider": "local"},
    })
    response = client.put("/api/settings/siem", json={
        "host": "https://elastic.internal:9200", "api_key": "rotated",
        "alert_index": "wazuh-alerts-*",
    })
    body = response.json()
    assert body["api_key_set"] is True
    assert "rotated" not in str(body)
    reloaded = ManagedSettings(settings.home).load()
    assert reloaded.siem.alert_index == "wazuh-alerts-*"
    assert reloaded.siem.api_key == "rotated"


def test_siem_tls_choice_persists(managed_client):
    client, settings = managed_client
    client.post("/api/setup/complete", json={
        "siem": {"host": "https://lab-elastic:9200", "verify_tls": False},
        "ai": {"provider": "local"},
    })
    assert settings.load().siem.verify_tls is False
    body = client.get("/api/status").json()["siem"]
    assert body["verify_tls"] is False


def test_siem_test_rejects_invalid_uploaded_ca(managed_client):
    client, _settings = managed_client
    response = client.post("/api/setup/siem/test", json={
        "host": "https://elastic.internal:9200",
        "ca_cert_pem": "not a certificate",
    })
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "CA certificate" in response.json()["error"]


# -- provider validation (real-inference path, model call faked) -------------------------


def fake_completion(content="OK"):
    async def acompletion(**kwargs):
        message = SimpleNamespace(content=content)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])
    return acompletion


def test_validate_local_provider(managed_client, monkeypatch):
    import litellm

    client, _settings = managed_client
    monkeypatch.setattr(litellm, "acompletion", fake_completion())
    result = client.post("/api/ai/validate", json={}).json()
    assert result["ok"] is True
    assert result["model_id"].startswith("ollama/")
    assert result["sample"] == "OK"
    assert result["latency_ms"] >= 0


def test_validate_cloud_provider_failure_is_honest(managed_client, monkeypatch):
    import litellm

    async def boom(**kwargs):
        raise RuntimeError("invalid x-api-key")

    client, _settings = managed_client
    monkeypatch.setattr(litellm, "acompletion", boom)
    result = client.post("/api/ai/validate", json={
        "provider": "anthropic", "cloud_api_key": "bad",
    }).json()
    assert result["ok"] is False
    assert "invalid x-api-key" in result["error"]


def test_validate_cloud_without_key_fails_cleanly(managed_client):
    client, _settings = managed_client
    result = client.post("/api/ai/validate", json={
        "provider": "openai",
    }).json()
    assert result["ok"] is False
    assert "cloud_api_key" in result["error"]


# -- ollama endpoints wired through the app ------------------------------------------------


def test_local_ai_status_endpoint(managed_client, monkeypatch):
    from engine.ai import ollama as ollama_module

    async def fake_status(self):
        return {"base_url": self._base, "binary_found": False,
                "running": False, "version": "", "models": [],
                "detail": "cannot reach Ollama", "recommended": []}

    monkeypatch.setattr(ollama_module.OllamaClient, "status", fake_status)
    client, _settings = managed_client
    state = client.get("/api/ai/local").json()
    assert state["running"] is False
    assert "cannot reach" in state["detail"]


def test_pull_endpoint_validates_input(managed_client):
    client, _settings = managed_client
    assert client.post("/api/ai/local/pull",
                       json={"model": "  "}).status_code == 400
    progress = client.get("/api/ai/local/pull").json()
    assert progress["active"] is False and progress["model"] == ""


# -- managed runtime: reconfigure without restart --------------------------------------------


def test_app_runner_swaps_engine_on_setup_complete(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGLOOKUP_HOME", str(tmp_path / "apphome"))
    from engine.app import AppRunner
    from engine.appdirs import ensure_app_home

    runner = AppRunner(ManagedSettings(ensure_app_home()))
    original_service = runner.runner.service
    with TestClient(runner.app) as client:
        assert client.get("/api/setup").json()["needs_setup"] is True
        response = client.post("/api/setup/complete", json={
            "siem": {"host": ""}, "ai": {"provider": "local"},
        })
        assert response.status_code == 200
        # Engine swapped live: same process, new service/pipeline in state.
        assert runner.runner.service is not original_service
        assert runner.app.state.service is runner.runner.service
        assert client.get("/api/setup").json()["needs_setup"] is False
        assert client.get("/api/status").status_code == 200
