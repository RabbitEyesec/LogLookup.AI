"""Configuration loading.

Reads config.yaml (shape defined in Master Specification section 7.1),
expands ``${ENV_VAR}`` references from the environment, and exposes typed
sections for every pipeline stage, the AI layer, and the output surfaces.

Secrets rule: API keys are only ever read from environment variables via
``${...}`` interpolation, never stored in the file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from engine.connectors.base import SourceConnection

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

#: severity_floor labels -> minimum OCSF severity_id (1=Info .. 6=Fatal)
SEVERITY_FLOOR_IDS = {"low": 2, "medium": 3, "high": 4}


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


def _expand_env(value: Any) -> Any:
    """Recursively expand ${ENV_VAR} references in strings."""
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            return os.environ.get(match.group(1), "")

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass(frozen=True)
class SiemConfig:
    type: str = "elastic"
    host: str = "https://localhost:9200"
    api_key: str = ""
    alert_index: str = ".alerts-security"
    poll_seconds: int = 60
    severity_floor: str = "medium"
    verify_tls: bool = True
    ca_cert_path: str = ""

    @property
    def severity_floor_id(self) -> int:
        try:
            return SEVERITY_FLOOR_IDS[self.severity_floor.lower()]
        except KeyError:
            raise ConfigError(
                f"siem.severity_floor must be one of {sorted(SEVERITY_FLOOR_IDS)}, "
                f"got {self.severity_floor!r}"
            ) from None


@dataclass(frozen=True)
class EngineConfig:
    mode: str = "local"
    server_url: str | None = None


@dataclass(frozen=True)
class RiskConfig:
    severity_weights: dict[int, float] = field(
        default_factory=lambda: {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32}
    )
    surface_threshold: float = 10.0
    misconfiguration_downgrade: float = 0.5
    #: risk added per additional independent source provider in one chain
    independent_source_weight: float = 4.0

    def weight_for(self, severity_id: int) -> float:
        return float(self.severity_weights.get(severity_id, 0))


@dataclass(frozen=True)
class CorrelationConfig:
    window_minutes: int = 60
    evaluate_every_minutes: int = 5
    entity_precedence: tuple[str, ...] = ("process_guid", "upn", "mac", "ip")
    watermark_grace_seconds: int = 60
    entity_retention_minutes: int = 1440
    risk: RiskConfig = field(default_factory=RiskConfig)


@dataclass(frozen=True)
class PrefilterConfig:
    trusted_ips: tuple[str, ...] = ()
    expected_service_accounts: tuple[str, ...] = ()
    approved_scanner_hosts: tuple[str, ...] = ()


#: LiteLLM cloud model used when ``ai.cloud_model`` is not set explicitly.
DEFAULT_CLOUD_MODELS = {
    "anthropic": "claude-opus-4-8",
    "openai": "gpt-5",
}

#: Providers the abstraction layer supports (runtime-selectable, no lock-in).
SUPPORTED_AI_PROVIDERS = ("local", "anthropic", "openai")


@dataclass(frozen=True)
class RagConfig:
    """RAG-grounded MITRE ATT&CK mapping (FAISS + embeddings, or lexical)."""

    kb_path: str = "var/attack_kb.json"
    index_dir: str = "var/attack_index"
    #: "vector" (FAISS + embeddings), "lexical" (deterministic BM25), or
    #: "auto" (vector when the embedding stack is installed, else lexical).
    backend: str = "auto"
    top_k: int = 8
    embedding_model: str = "sentence-transformers/all-mpnet-base-v2"


@dataclass(frozen=True)
class AiConfig:
    provider: str = "local"  # local | anthropic | openai
    local_model: str = "foundation-sec-8b"
    local_base_url: str = "http://localhost:11434"  # Ollama serving endpoint
    cloud_model: str | None = None  # default per provider if unset
    cloud_api_key: str = ""
    zero_data_retention: bool = True  # required if cloud
    redaction: bool = True  # Presidio tokenization (enforced in a later phase)
    #: which formed chains the AI triages: "surfaced" (RBA-crossed) or "all"
    triage_scope: str = "surfaced"
    timeout_seconds: int = 120
    max_retries: int = 2  # instructor validation-retry attempts
    #: hard bound on the flattened evidence payload handed to the model
    max_evidence_chars: int = 24000
    rag: RagConfig = field(default_factory=RagConfig)

    def __post_init__(self) -> None:
        if self.provider not in SUPPORTED_AI_PROVIDERS:
            raise ConfigError(
                f"ai.provider must be one of {list(SUPPORTED_AI_PROVIDERS)}, "
                f"got {self.provider!r}"
            )
        if self.triage_scope not in ("surfaced", "all"):
            raise ConfigError(
                f"ai.triage_scope must be 'surfaced' or 'all', "
                f"got {self.triage_scope!r}"
            )

    @property
    def resolved_cloud_model(self) -> str:
        if self.cloud_model:
            return self.cloud_model
        return DEFAULT_CLOUD_MODELS.get(self.provider, "")


@dataclass(frozen=True)
class OutputConfig:
    results_index: str = "loglookup-results"
    dashboard_base_url: str = "http://localhost:8080"

    def dashboard_url_for(self, cluster_id: str) -> str:
        """Deep link for one attack chain: /incident/<cluster_id>."""
        return f"{self.dashboard_base_url.rstrip('/')}/incident/{cluster_id}"


@dataclass(frozen=True)
class StorageConfig:
    """Durable operational store (SQLite WAL, single writer)."""

    driver: str = "sqlite"
    db_path: str = "var/loglookup-v2.sqlite3"
    wal: bool = True
    evidence_encryption: bool = True
    raw_retention_days: int = 30

    def __post_init__(self) -> None:
        if self.driver != "sqlite":
            raise ConfigError("storage.driver must be 'sqlite' in v2")
        if not self.evidence_encryption:
            raise ConfigError(
                "storage.evidence_encryption cannot be disabled: raw vendor "
                "evidence is always encrypted at rest")
        if self.raw_retention_days < 1:
            raise ConfigError("storage.raw_retention_days must be >= 1")


@dataclass(frozen=True)
class LogicAppsConfig:
    """Azure Logic Apps SOAR channel. Off unless explicitly enabled."""

    enabled: bool = False
    auth_profile_id: str = ""
    allowed_workflows: tuple[str, ...] = ()
    require_explicit_approval: bool = True
    unknown_delivery_policy: str = "reconcile"
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.require_explicit_approval:
            raise ConfigError(
                "outputs.logic_apps.require_explicit_approval cannot be "
                "disabled: no response action runs without approval")
        if self.unknown_delivery_policy != "reconcile":
            raise ConfigError(
                "outputs.logic_apps.unknown_delivery_policy must be "
                "'reconcile': ambiguous deliveries are never auto-retried")


@dataclass(frozen=True)
class AccessConfig:
    """API access boundary beyond the loopback-only default."""

    #: peers allowed to assert identity via X-Forwarded-User (reverse proxy)
    trusted_proxy_ips: tuple[str, ...] = ()
    #: header carrying the proxy-authenticated user (trusted proxies only)
    proxy_user_header: str = "X-Forwarded-User"
    proxy_role_header: str = "X-Forwarded-Role"


@dataclass(frozen=True)
class Config:
    siem: SiemConfig = field(default_factory=SiemConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    prefilter: PrefilterConfig = field(default_factory=PrefilterConfig)
    ai: AiConfig = field(default_factory=AiConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    scope_id: str = "org-local"
    storage: StorageConfig = field(default_factory=StorageConfig)
    sources: tuple[SourceConnection, ...] = ()
    logic_apps: LogicAppsConfig = field(default_factory=LogicAppsConfig)
    access: AccessConfig = field(default_factory=AccessConfig)

    def effective_sources(self, include_legacy: bool = True) -> tuple[SourceConnection, ...]:
        """Configured sources plus the legacy single-Elastic ``siem`` block.

        The legacy block surfaces as connection ``elastic-default`` (origin
        ``legacy``): still polled by the original single-source path, but
        visible and manageable alongside the v2 connections.
        """
        if include_legacy and self.siem.host and not any(
            c.connection_id == "elastic-default" for c in self.sources
        ):
            legacy = SourceConnection(
                connection_id="elastic-default", provider="elastic",
                scope_id=self.scope_id, name="Elastic Security (default)",
                active=True, poll_seconds=self.siem.poll_seconds,
                tls_verify=self.siem.verify_tls,
                ca_bundle_path=self.siem.ca_cert_path or None,
                origin="legacy",
                options={"host": self.siem.host,
                         "alert_index": self.siem.alert_index},
            )
            return (legacy, *self.sources)
        return self.sources


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name) or {}
    if not isinstance(value, dict):
        raise ConfigError(f"config section {name!r} must be a mapping")
    return value


def load_config(path: str | Path) -> Config:
    """Load and validate a config.yaml file."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ConfigError("top-level config must be a mapping")
    return config_from_dict(_expand_env(raw))


def config_from_dict(data: dict[str, Any]) -> Config:
    """Build a validated Config from already-loaded configuration data."""
    siem = SiemConfig(**_section(data, "siem"))
    engine = EngineConfig(**_section(data, "engine"))

    corr_raw = dict(_section(data, "correlation"))
    risk_raw = dict(corr_raw.pop("risk", {}) or {})
    weights_raw = risk_raw.pop("severity_weights", None)
    risk_kwargs: dict[str, Any] = dict(risk_raw)
    if weights_raw is not None:
        risk_kwargs["severity_weights"] = {
            int(k): float(v) for k, v in weights_raw.items()
        }
    precedence = corr_raw.pop("entity_precedence", None)
    corr_kwargs: dict[str, Any] = dict(corr_raw)
    if precedence is not None:
        corr_kwargs["entity_precedence"] = tuple(precedence)
    correlation = CorrelationConfig(risk=RiskConfig(**risk_kwargs), **corr_kwargs)

    pre_raw = _section(data, "prefilter")
    prefilter = PrefilterConfig(
        trusted_ips=tuple(pre_raw.get("trusted_ips") or ()),
        expected_service_accounts=tuple(
            pre_raw.get("expected_service_accounts") or ()
        ),
        approved_scanner_hosts=tuple(pre_raw.get("approved_scanner_hosts") or ()),
    )

    ai_raw = dict(_section(data, "ai"))
    rag_raw = dict(ai_raw.pop("rag", {}) or {})
    try:
        ai = AiConfig(rag=RagConfig(**rag_raw), **ai_raw)
        output = OutputConfig(**_section(data, "output"))
    except TypeError as exc:
        raise ConfigError(f"invalid ai/output configuration: {exc}") from None

    # Validate severity floor eagerly so a bad value fails at load time.
    siem.severity_floor_id  # noqa: B018 - intentional validation access

    app_raw = data.get("app") if isinstance(data.get("app"), dict) else {}
    scope_id = str(app_raw.get("scope_id") or "org-local")
    try:
        storage = StorageConfig(**_section(data, "storage"))
        access = AccessConfig(**{
            **_section(data, "access"),
            **({"trusted_proxy_ips": tuple(
                _section(data, "access").get("trusted_proxy_ips") or ())}
               if "trusted_proxy_ips" in _section(data, "access") else {}),
        })
        outputs_raw = _section(data, "outputs")
        la_raw = dict(outputs_raw.get("logic_apps") or {})
        if "allowed_workflows" in la_raw:
            la_raw["allowed_workflows"] = tuple(la_raw["allowed_workflows"] or ())
        logic_apps = LogicAppsConfig(**la_raw)
    except TypeError as exc:
        raise ConfigError(f"invalid storage/access/outputs configuration: {exc}") from None
    sources = _parse_sources(data.get("sources"), scope_id)

    return Config(
        siem=siem,
        engine=engine,
        correlation=correlation,
        prefilter=prefilter,
        ai=ai,
        output=output,
        scope_id=scope_id,
        storage=storage,
        sources=sources,
        logic_apps=logic_apps,
        access=access,
    )


def _parse_sources(raw: Any, default_scope: str) -> tuple[SourceConnection, ...]:
    if raw in (None, []):
        return ()
    if not isinstance(raw, list):
        raise ConfigError("config 'sources' must be a list")
    out: list[SourceConnection] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ConfigError("each entry in 'sources' must be a mapping")
        tls = item.get("tls") or {}
        try:
            conn = SourceConnection(
                connection_id=str(item.get("id", "")),
                provider=str(item.get("provider", "")),
                scope_id=str(item.get("scope_id") or default_scope),
                name=str(item.get("name", "")),
                mode=str(item.get("mode", "poll")),
                active=bool(item.get("enabled", item.get("active", False))),
                poll_seconds=int(item.get("poll_seconds", 60)),
                lookback_seconds=int(item.get("lookback_seconds", 300)),
                max_page_size=int(item.get("max_page_size", 500)),
                auth_profile_id=str(item.get("auth_profile_id", "")),
                tls_verify=bool(tls.get("verify", True)),
                ca_bundle_path=tls.get("ca_bundle_path"),
                origin="config",
                options=dict(item.get("options") or {}),
            )
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"invalid source {item.get('id')!r}: {exc}") from None
        if conn.connection_id in seen:
            raise ConfigError(f"duplicate source id {conn.connection_id!r}")
        seen.add(conn.connection_id)
        out.append(conn)
    return tuple(out)
