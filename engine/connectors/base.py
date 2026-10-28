"""Connector contracts: connection config, page results, health taxonomy."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from engine.envelope import SourceEnvelope

PROVIDERS = ("elastic", "sentinel", "splunk", "defender_xdr", "entra_id")

#: Operator-visible source states; each is a distinct, non-healthy-looking
#: condition except ``healthy`` itself.
STATUS_HEALTHY = "healthy"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_PAUSED = "paused"
STATUS_PERMISSION_DENIED = "permission_denied"
STATUS_LIMITED_BY_LICENSE = "limited_by_license"
STATUS_THROTTLED = "throttled"
STATUS_UNAVAILABLE = "temporarily_unavailable"
STATUS_STARTING = "starting"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class ConnectorError(Exception):
    """A source failure with an operator-visible status classification."""

    def __init__(self, message: str, *, status: str = STATUS_UNAVAILABLE,
                 code: str = "source_error", retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.retry_after = retry_after


class ConfigurationError(ConnectorError):
    def __init__(self, message: str):
        super().__init__(message, status=STATUS_NOT_CONFIGURED,
                         code="not_configured")


@dataclass(frozen=True)
class SourceConnection:
    """One configured source instance (never holds secret values)."""

    connection_id: str
    provider: str
    scope_id: str = "org-local"
    name: str = ""
    mode: str = "poll"
    active: bool = False
    read_only: bool = True
    poll_seconds: int = 60
    lookback_seconds: int = 300
    max_page_size: int = 500
    auth_profile_id: str = ""
    tls_verify: bool = True
    ca_bundle_path: str | None = None
    origin: str = "managed"  # managed | config | legacy
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _ID_RE.match(self.connection_id):
            raise ValueError(f"invalid connection_id {self.connection_id!r}")
        if self.provider not in PROVIDERS:
            raise ValueError(
                f"unknown provider {self.provider!r}; expected one of "
                f"{list(PROVIDERS)}"
            )
        if not self.read_only:
            raise ValueError("source connections are read-only in v2")
        if self.poll_seconds < 5:
            raise ValueError("poll_seconds must be >= 5")
        if not 1 <= self.max_page_size <= 5000:
            raise ValueError("max_page_size must be within 1..5000")
        if self.lookback_seconds < 0:
            raise ValueError("lookback_seconds must be >= 0")

    def public_view(self) -> dict[str, Any]:
        """Safe metadata for the API: options minus anything secret-shaped."""
        return {
            "connection_id": self.connection_id,
            "provider": self.provider,
            "scope_id": self.scope_id,
            "name": self.name or self.connection_id,
            "mode": self.mode,
            "active": self.active,
            "read_only": self.read_only,
            "poll_seconds": self.poll_seconds,
            "lookback_seconds": self.lookback_seconds,
            "max_page_size": self.max_page_size,
            "auth_profile_id": self.auth_profile_id,
            "tls_verify": self.tls_verify,
            "origin": self.origin,
            "options": {
                k: v for k, v in self.options.items()
                if not re.search(r"secret|password|token|key|credential", k, re.I)
            },
        }


@dataclass(frozen=True)
class PageResult:
    records: list[dict[str, Any]]
    next_cursor: dict[str, Any] | None
    window_complete: bool
    source_warnings: list[str] = field(default_factory=list)


@dataclass
class RecordIdentity:
    """What a connector knows about one record, before envelope assembly."""

    record_kind: str
    source_event_id: str
    namespace: str
    event_time: str | None = None
    source_updated_at: str | None = None
    source_incident_id: str | None = None
    source_url: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    aliases: tuple[tuple[str, str], ...] = ()
    #: set by connectors that emit incident-link rows
    links: list[dict[str, Any]] = field(default_factory=list)


class SourceConnector(Protocol):
    provider: str
    streams: tuple[str, ...]

    async def open(self) -> None: ...

    async def fetch_page(
        self, cursor: dict[str, Any] | None, stream: str = "default"
    ) -> PageResult: ...

    def identify(self, record: dict[str, Any], stream: str) -> RecordIdentity: ...

    async def close(self) -> None: ...


def envelope_cls() -> type[SourceEnvelope]:  # pragma: no cover - typing aid
    return SourceEnvelope
