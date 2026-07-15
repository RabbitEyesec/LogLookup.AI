"""Onboarding + AI-management API: the wizard's backend.

Everything the first-launch wizard and the Settings surface need, so 
step of setup ever requires a terminal, a config file, or an environment
variable :

    GET  /api/setup                 first-run state
    POST /api/setup/siem/test       live SIEM connection test + index detection
    POST /api/setup/complete        persist config + secrets, go live
    GET  /api/ai/local              detect Ollama + installed models
    POST /api/ai/local/pull         download a model (progress via GET)
    GET  /api/ai/local/pull         current download progress
    POST /api/ai/validate           REAL inference round-trip (explicit action)
    PUT  /api/settings/siem         change the SIEM connection later

Managed state (secrets, persistence) is only available when the app runs
through ``loglookup serve`` (engine.app); the dev CLI serves the same
endpoints but returns 409 for persistence operations.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from engine.ai.ollama import OllamaClient, OllamaError, PullManager
from engine.ai.provider import AIProvider, ProviderError
from engine.config import SUPPORTED_AI_PROVIDERS, ConfigError, SiemConfig
from engine.connectors.elastic import ConnectorError, ElasticConnector

logger = logging.getLogger(__name__)

router = APIRouter()

#: patched in tests to inject a fake transport
make_connector = ElasticConnector

#: index patterns that usually hold alerts, in suggestion order
ALERT_INDEX_PATTERNS = (
    ".alerts-security*",
    ".internal.alerts-*",
    ".siem-signals-*",
    "wazuh-alerts-*",
    "logs-*",
    "filebeat-*",
    "winlogbeat-*",
    "auditbeat-*",
)


def _settings(request: Request):
    return getattr(request.app.state, "settings", None)


def _require_settings(request: Request):
    settings = _settings(request)
    if settings is None:
        raise HTTPException(
            status_code=409,
            detail="not running in managed mode; start the app with "
                   "'loglookup serve' to persist configuration",
        )
    return settings


# -- first-run state ------------------------------------------------------------


@router.get("/api/setup")
async def setup_state(request: Request) -> dict[str, Any]:
    settings = _settings(request)
    return {
        "managed": settings is not None,
        "needs_setup": settings is not None and not settings.setup_complete,
    }


# -- SIEM connection test + index detection ---------------------------------------


class SiemTest(BaseModel):
    host: str
    api_key: str = Field(default="", repr=False)
    alert_index: str = ""
    verify_tls: bool = True
    ca_cert_path: str = ""
    ca_cert_pem: str = Field(default="", repr=False)


@router.post("/api/setup/siem/test")
async def siem_test(request: Request, body: SiemTest) -> dict[str, Any]:
    """Live connection test; never persists anything."""
    host = body.host.strip()
    if not host.lower().startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="host must be a full URL, e.g. https://localhost:9200",
        )
    api_key = body.api_key
    settings = _settings(request)
    if not api_key and settings is not None:
        # Re-test with the stored key without ever echoing it.
        from engine.secure.store import SIEM_API_KEY

        api_key = settings.secrets.get(SIEM_API_KEY)
    siem = SiemConfig(
        host=host,
        api_key=api_key,
        verify_tls=body.verify_tls,
        ca_cert_path=body.ca_cert_path.strip(),
    )
    try:
        connector = make_connector(siem, ca_cert_pem=body.ca_cert_pem)
    except ConnectorError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        try:
            cluster = await connector.info()
            indices = await connector.list_indices()
        except ConnectorError as exc:
            return {"ok": False, "error": str(exc)}
        result: dict[str, Any] = {
            "ok": True,
            "cluster": cluster,
            "indices": indices,
            "suggested": _suggest_indices(indices),
        }
        if body.alert_index:
            try:
                result["alert_index_docs"] = await connector.count(
                    body.alert_index
                )
            except ConnectorError as exc:
                result["alert_index_error"] = str(exc)
        return result
    finally:
        await connector.aclose()


def _suggest_indices(indices: list[dict[str, Any]]) -> list[str]:
    names = [entry["index"] for entry in indices]
    suggested: list[str] = []
    for pattern in ALERT_INDEX_PATTERNS:
        for name in names:
            if fnmatch.fnmatch(name, pattern) and name not in suggested:
                suggested.append(name)
    return suggested


# -- setup completion ---------------------------------------------------------------


class SiemSetup(BaseModel):
    host: str = ""
    api_key: str = Field(default="", repr=False)
    alert_index: str = ".alerts-security"
    poll_seconds: int = 60
    severity_floor: str = "medium"
    verify_tls: bool = True
    ca_cert_path: str = ""
    ca_cert_pem: str = Field(default="", repr=False)


class AiSetup(BaseModel):
    provider: str = "local"
    local_model: str = ""
    local_base_url: str = "http://localhost:11434"
    cloud_model: Optional[str] = None
    cloud_api_key: str = Field(default="", repr=False)
    redaction: bool = True
    zero_data_retention: bool = True


class SetupComplete(BaseModel):
    siem: SiemSetup
    ai: AiSetup


@router.post("/api/setup/complete")
async def setup_complete(request: Request, body: SetupComplete) -> dict[str, Any]:
    settings = _require_settings(request)
    if body.ai.provider not in SUPPORTED_AI_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"ai.provider must be one of {list(SUPPORTED_AI_PROVIDERS)}",
        )
    siem = body.siem.model_dump()
    ai = body.ai.model_dump()
    # Unset optionals fall back to config defaults instead of persisting
    # empty strings (e.g. local_model defaults to the documented model).
    for key in ("local_model", "local_base_url", "cloud_model"):
        if ai.get(key) in (None, ""):
            ai.pop(key, None)
    if not siem["host"]:
        # SIEM postponed: keep an explicit empty host so polling stays off
        # until the user configures one from Settings. Honest, not fake.
        siem["host"] = ""
    ca_cert_pem = siem.pop("ca_cert_pem", "")
    if ca_cert_pem:
        try:
            siem["ca_cert_path"] = settings.save_ca_certificate(ca_cert_pem)
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        config = settings.save_setup(siem, ai)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    on_complete = getattr(request.app.state, "on_setup_complete", None)
    if on_complete is not None:
        await on_complete(config)
    else:  # dev server: at least apply the AI settings live
        service = request.app.state.service
        try:
            service.providers.switch(**{
                k: v for k, v in ai.items()
                if k in ("provider", "local_model", "local_base_url",
                         "cloud_model", "cloud_api_key", "redaction",
                         "zero_data_retention") and v not in (None, "")
            })
        except ProviderError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        request.app.state.config = config
    logger.info("onboarding complete (provider=%s, siem=%s)",
                body.ai.provider, siem["host"] or "not configured")
    return {"ok": True, "needs_setup": False}


# -- SIEM settings after setup ---------------------------------------------------


class SiemUpdate(BaseModel):
    host: Optional[str] = None
    api_key: Optional[str] = Field(default=None, repr=False)
    alert_index: Optional[str] = None
    poll_seconds: Optional[int] = None
    severity_floor: Optional[str] = None
    verify_tls: Optional[bool] = None
    ca_cert_path: Optional[str] = None
    ca_cert_pem: Optional[str] = Field(default=None, repr=False)


@router.put("/api/settings/siem")
async def put_siem_settings(request: Request, body: SiemUpdate) -> dict[str, Any]:
    settings = _require_settings(request)
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    if not changes:
        raise HTTPException(status_code=400, detail="no settings provided")
    ca_cert_pem = changes.pop("ca_cert_pem", "")
    if ca_cert_pem:
        try:
            changes["ca_cert_path"] = settings.save_ca_certificate(ca_cert_pem)
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        config = settings.apply_siem_changes(changes)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    apply_siem = getattr(request.app.state, "apply_siem", None)
    if apply_siem is not None:
        await apply_siem(config)
    else:
        request.app.state.config = config
    return {
        "host": config.siem.host,
        "alert_index": config.siem.alert_index,
        "poll_seconds": config.siem.poll_seconds,
        "severity_floor": config.siem.severity_floor,
        "verify_tls": config.siem.verify_tls,
        "ca_cert_path": config.siem.ca_cert_path,
        "api_key_set": bool(config.siem.api_key),
    }


# -- local LLM management ---------------------------------------------------------


@router.get("/api/ai/local")
async def local_ai_status(
    request: Request, base_url: str = ""
) -> dict[str, Any]:
    config = request.app.state.config
    url = base_url or config.ai.local_base_url
    client = OllamaClient(url)
    try:
        return await client.status()
    finally:
        await client.aclose()


class PullRequest(BaseModel):
    model: str
    base_url: str = ""


def _pull_manager(request: Request) -> PullManager:
    manager = getattr(request.app.state, "pull_manager", None)
    if manager is None:
        manager = PullManager()
        request.app.state.pull_manager = manager
    return manager


@router.post("/api/ai/local/pull", status_code=202)
async def start_pull(request: Request, body: PullRequest) -> dict[str, Any]:
    if not body.model.strip():
        raise HTTPException(status_code=400, detail="model is required")
    config = request.app.state.config
    url = body.base_url or config.ai.local_base_url
    manager = _pull_manager(request)
    try:
        state = manager.start(url, body.model.strip())
    except OllamaError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return state.as_dict()


@router.get("/api/ai/local/pull")
async def pull_progress(request: Request) -> dict[str, Any]:
    return _pull_manager(request).state.as_dict()


# -- provider validation (real inference, explicit user action) --------------------


class ValidateRequest(BaseModel):
    provider: Optional[str] = None
    local_model: Optional[str] = None
    local_base_url: Optional[str] = None
    cloud_model: Optional[str] = None
    cloud_api_key: Optional[str] = Field(default=None, repr=False)
    zero_data_retention: Optional[bool] = None


@router.post("/api/ai/validate")
async def validate_provider(
    request: Request, body: ValidateRequest
) -> dict[str, Any]:
    """Run one tiny REAL inference through the requested configuration.

    Nothing is fabricated: a failure is returned as a failure. Cloud
    validation spends a few tokens of the user's key — that is why this
    only runs on an explicit button press.
    """
    service = request.app.state.service
    overrides = {
        k: v for k, v in body.model_dump().items() if v is not None
    }
    base = service.providers.config
    if overrides.get("provider") in SUPPORTED_AI_PROVIDERS and not overrides.get(
        "cloud_api_key"
    ):
        settings = _settings(request)
        if settings is not None:
            from engine.secure.store import ai_key_name

            stored = settings.secrets.get(ai_key_name(overrides["provider"]))
            if stored:
                overrides["cloud_api_key"] = stored
    try:
        config = dataclasses.replace(base, **overrides) if overrides else base
        provider = AIProvider(config)
    except (TypeError, ConfigError, ProviderError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return await provider.validate()
