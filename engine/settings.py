"""Managed settings: app-owned config.yaml + encrypted secrets, one API.

The installed application never asks the user to edit a file or export an
environment variable (AI Constitution 3: configuration is performed
entirely through the UI). The onboarding wizard and the Settings drawer
write here; the engine reads a fully-typed :class:`engine.config.Config`
back out with secrets injected from the encrypted store.

Layout under the app home (see :mod:`engine.appdirs`):

    config.yaml   non-secret settings + ``app.setup_complete`` flag
    secrets.key   machine-local encryption key (0600)
    secrets.enc   AES-256-GCM encrypted credentials (0600)

``config.yaml`` written by this module NEVER contains an API key; loading
still honours ``${ENV}`` interpolation for operators who insist, but no
user-facing flow requires an environment variable.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import ssl
from pathlib import Path
from typing import Any

import yaml

from engine.config import (
    Config,
    ConfigError,
    SUPPORTED_AI_PROVIDERS,
    config_from_dict,
)
from engine.secure.store import SIEM_API_KEY, SecretStore, ai_key_name

logger = logging.getLogger(__name__)

CONFIG_FILE = "config.yaml"
STATE_FILE = "state.json"
ELASTIC_CA_FILE = "elastic-ca.pem"

#: ai-section fields that are secrets and must go to the store, never YAML.
_AI_SECRET_FIELDS = ("cloud_api_key",)
_SIEM_SECRET_FIELDS = ("api_key",)


class ManagedSettings:
    """Owns persisted configuration for one app home directory."""

    def __init__(self, home: str | Path) -> None:
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.config_path = self.home / CONFIG_FILE
        self.secrets = SecretStore(self.home)

    # -- state ---------------------------------------------------------------

    @property
    def setup_complete(self) -> bool:
        data = self._read_yaml()
        app = data.get("app") or {}
        return bool(isinstance(app, dict) and app.get("setup_complete"))

    def _read_yaml(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        try:
            data = yaml.safe_load(self.config_path.read_text("utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(
                f"cannot read managed config {self.config_path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ConfigError(
                f"managed config {self.config_path} must be a mapping"
            )
        return data

    def _write_yaml(self, data: dict[str, Any]) -> None:
        self.config_path.write_text(
            "# LogLookup AI — managed by the application. Secrets are never\n"
            "# stored here; they live encrypted in secrets.enc.\n"
            + yaml.safe_dump(data, sort_keys=False),
            "utf-8",
        )

    # -- load ------------------------------------------------------------------

    def load(self) -> Config:
        """Typed config with secrets injected and paths rooted in the home."""
        data = self._read_yaml()
        data.pop("app", None)

        ai_section = data.setdefault("ai", {})
        rag = ai_section.setdefault("rag", {})
        rag.setdefault("kb_path", str(self.home / "attack_kb.json"))
        rag.setdefault("index_dir", str(self.home / "attack_index"))

        config = config_from_dict(data)
        return self._inject_secrets(config)

    def _inject_secrets(self, config: Config) -> Config:
        siem, ai = config.siem, config.ai
        if not siem.api_key:
            stored = self.secrets.get(SIEM_API_KEY)
            if stored:
                siem = dataclasses.replace(siem, api_key=stored)
        if ai.provider in SUPPORTED_AI_PROVIDERS and not ai.cloud_api_key:
            stored = self.secrets.get(ai_key_name(ai.provider))
            if stored:
                ai = dataclasses.replace(ai, cloud_api_key=stored)
        if siem is config.siem and ai is config.ai:
            return config
        return dataclasses.replace(config, siem=siem, ai=ai)

    # -- save -------------------------------------------------------------------

    def _split_secrets(
        self, section: dict[str, Any], secret_fields: tuple[str, ...],
        name_for: dict[str, str],
    ) -> dict[str, str]:
        """Pop secret fields out of a section; return {store name: value}."""
        secrets: dict[str, str] = {}
        for field_name in secret_fields:
            value = section.pop(field_name, None)
            if value:
                secrets[name_for[field_name]] = str(value)
        return secrets

    def save_setup(
        self, siem: dict[str, Any], ai: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> Config:
        """Persist the wizard result and mark onboarding complete.

        ``siem`` / ``ai`` are plain dicts of the respective config sections;
        secret fields are diverted to the encrypted store. Validation runs
        BEFORE anything is written, so a bad payload cannot half-persist.
        """
        siem, ai = dict(siem), dict(ai)
        provider = str(ai.get("provider") or "local")
        secrets = self._split_secrets(
            siem, _SIEM_SECRET_FIELDS, {"api_key": SIEM_API_KEY}
        )
        secrets.update(self._split_secrets(
            ai, _AI_SECRET_FIELDS, {"cloud_api_key": ai_key_name(provider)}
        ))

        data = self._read_yaml()
        data.pop("app", None)
        data["siem"] = {**(data.get("siem") or {}), **siem}
        merged_ai = {**(data.get("ai") or {}), **ai}
        merged_ai.pop("cloud_api_key", None)  # never persisted to YAML
        data["ai"] = merged_ai
        for section, values in (extra or {}).items():
            data[section] = {**(data.get(section) or {}), **values}

        candidate = dict(data)
        config_from_dict(_deep_copy(candidate))  # validate before writing

        if secrets:
            self.secrets.set_many(secrets)
        data["app"] = {"setup_complete": True}
        self._write_yaml(data)
        logger.info("setup complete; configuration persisted to %s",
                    self.config_path)
        return self.load()

    def apply_ai_changes(self, changes: dict[str, Any]) -> None:
        """Persist runtime AI settings changes (Settings drawer / API)."""
        changes = dict(changes)
        data = self._read_yaml()
        ai_section = dict(data.get("ai") or {})
        key = changes.pop("cloud_api_key", None)
        provider = str(
            changes.get("provider") or ai_section.get("provider") or "local"
        )
        ai_section.update(changes)
        ai_section.pop("cloud_api_key", None)
        data["ai"] = ai_section
        candidate = _deep_copy(data)
        candidate.pop("app", None)
        config_from_dict(candidate)  # validate before writing
        if key:
            self.secrets.set(ai_key_name(provider), str(key))
        self._write_yaml(data)

    def apply_siem_changes(self, changes: dict[str, Any]) -> Config:
        """Persist SIEM connection changes; returns the reloaded config."""
        changes = dict(changes)
        key = changes.pop("api_key", None)
        data = self._read_yaml()
        data["siem"] = {**(data.get("siem") or {}), **changes}
        candidate = _deep_copy(data)
        candidate.pop("app", None)
        config_from_dict(candidate)  # validate before writing
        if key:
            self.secrets.set(SIEM_API_KEY, str(key))
        self._write_yaml(data)
        return self.load()

    def save_ca_certificate(self, pem: str) -> str:
        """Validate and persist an uploaded Elastic CA certificate."""
        value = pem.strip()
        if not value:
            raise ConfigError("the uploaded CA certificate is empty")
        try:
            ssl.create_default_context(cadata=value)
        except ssl.SSLError as exc:
            raise ConfigError(f"invalid CA certificate: {exc}") from exc
        path = self.home / ELASTIC_CA_FILE
        tmp = path.with_suffix(".pem.tmp")
        try:
            tmp.write_text(value + "\n", "utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(path)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise ConfigError(f"cannot store CA certificate: {exc}") from exc
        return str(path)


class PollCursorStore:
    """Durable SIEM poll cursor, so a restart resumes where polling stopped.

    Without this, a restarted service would start polling from "now" and
    silently skip every alert that arrived while it was down. Re-reading an
    overlap is safe: the correlation engine dedups alerts by uid and the
    write-back is idempotent by cluster_id.
    """

    def __init__(self, home: str | Path) -> None:
        self._path = Path(home) / STATE_FILE

    def load(self) -> int | None:
        try:
            data = json.loads(self._path.read_text("utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            logger.warning("cannot read %s: %s", self._path, exc)
            return None
        cursor = data.get("poll_cursor_ms") if isinstance(data, dict) else None
        return int(cursor) if isinstance(cursor, (int, float)) else None

    def save(self, cursor_ms: int) -> None:
        tmp = self._path.with_suffix(".json.tmp")
        try:
            tmp.write_text(
                json.dumps({"poll_cursor_ms": int(cursor_ms)}), "utf-8"
            )
            tmp.replace(self._path)
        except OSError as exc:
            logger.warning("cannot persist poll cursor: %s", exc)


def _deep_copy(data: dict[str, Any]) -> dict[str, Any]:
    """Cheap deep copy for validation passes (config data is plain YAML)."""
    return yaml.safe_load(yaml.safe_dump(data)) or {}
