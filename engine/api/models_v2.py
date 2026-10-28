"""Typed request models for the v2 API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectionCreate(_Strict):
    connection_id: str = Field(min_length=1, max_length=64)
    provider: str
    name: str = ""
    enabled: bool = False
    poll_seconds: int = Field(default=60, ge=5, le=86400)
    lookback_seconds: int = Field(default=300, ge=0, le=86400)
    max_page_size: int = Field(default=500, ge=1, le=5000)
    tls_verify: bool = True
    ca_bundle_path: Optional[str] = None
    options: dict[str, Any] = Field(default_factory=dict)
    #: write-only; stored encrypted, never returned
    credentials: Optional[dict[str, Any]] = Field(default=None, repr=False)


class ConnectionPatch(_Strict):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    poll_seconds: Optional[int] = Field(default=None, ge=5, le=86400)
    lookback_seconds: Optional[int] = Field(default=None, ge=0, le=86400)
    max_page_size: Optional[int] = Field(default=None, ge=1, le=5000)
    options: Optional[dict[str, Any]] = None
    credentials: Optional[dict[str, Any]] = Field(default=None, repr=False)


class NoteCreate(_Strict):
    body: str = Field(min_length=1, max_length=5000)
    expected_revision: int = Field(ge=0)


class AssignRequest(_Strict):
    owner: Optional[str] = Field(default=None, max_length=128)
    expected_revision: int = Field(ge=0)


class ActionCreate(_Strict):
    workflow_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list, max_length=200)
    rationale: str = Field(default="", max_length=1000)
    expected_revision: int = Field(ge=0)


class ActionDecision(_Strict):
    rationale: str = Field(default="", max_length=1000)


class ReconcileRequest(_Strict):
    outcome: str
    #: what a person verified downstream (separate from the workflow status)
    downstream_effect: Optional[str] = None
    run_id: Optional[str] = Field(default=None, max_length=200)
    note: str = Field(default="", max_length=1000)


class BackfillRequest(_Strict):
    """Explicit, bounded re-read of one stream. Never touches the live cursor."""

    stream: str = Field(min_length=1, max_length=64)
    start: datetime
    end: datetime
    reason: str = Field(default="", max_length=500)
    #: Splunk only: event-time floor for this backfill in seconds, 0 = none
    event_time_floor_seconds: Optional[int] = Field(default=None, ge=0, le=31536000)


class CursorDecision(_Strict):
    """Administrator confirms a new scan after a query-defining change."""

    stream: str = Field(min_length=1, max_length=64)
    #: where the new scan starts (default: now); at most 7 days back
    start_from: Optional[datetime] = None
    reason: str = Field(min_length=5, max_length=500)


class RecoveryRequest(_Strict):
    reason: str = Field(min_length=5, max_length=500)
