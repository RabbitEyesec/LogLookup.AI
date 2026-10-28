"""Response action model and state machine."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class ActionState(str, enum.Enum):
    PROPOSED = "proposed"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    QUEUED = "queued"
    DISPATCHING = "dispatching"
    ACKNOWLEDGED = "acknowledged"
    COMPLETED = "completed"
    EXPIRED = "expired"
    FAILED_WITHOUT_EFFECT = "failed_without_effect"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    CANCELLED = "cancelled"


S = ActionState
#: legal transitions; anything else is a bug or an attack and is refused.
TRANSITIONS: dict[ActionState, frozenset[ActionState]] = {
    S.PROPOSED: frozenset({S.APPROVAL_REQUIRED, S.CANCELLED}),
    S.APPROVAL_REQUIRED: frozenset({S.APPROVED, S.REJECTED, S.EXPIRED, S.CANCELLED}),
    S.APPROVED: frozenset({S.QUEUED, S.EXPIRED, S.CANCELLED}),
    S.QUEUED: frozenset({S.DISPATCHING, S.EXPIRED, S.CANCELLED}),
    S.DISPATCHING: frozenset({S.ACKNOWLEDGED, S.FAILED_WITHOUT_EFFECT,
                              S.RECONCILIATION_REQUIRED}),
    S.ACKNOWLEDGED: frozenset({S.COMPLETED}),
    S.RECONCILIATION_REQUIRED: frozenset({S.ACKNOWLEDGED, S.FAILED_WITHOUT_EFFECT}),
    # terminal: rejected, completed, expired, failed_without_effect, cancelled
}
TERMINAL = frozenset({S.REJECTED, S.COMPLETED, S.EXPIRED,
                      S.FAILED_WITHOUT_EFFECT, S.CANCELLED})

ROLES = ("viewer", "analyst", "responder", "administrator")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}


class ResponseError(Exception):
    """Base for response-layer failures; carries an HTTP-ish status hint."""

    status = 400

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        if status is not None:
            self.status = status


class Forbidden(ResponseError):
    status = 403


class Conflict(ResponseError):
    status = 409


class NotFound(ResponseError):
    status = 404


@dataclass
class DispatchResult:
    """Transport verdict. ``unknown`` means the effect cannot be ruled out."""

    outcome: str  # "accepted" | "rejected" | "unknown"
    run_id: str | None = None
    detail: str = ""
    http_status: int | None = None


@dataclass
class ResponseAction:
    action_id: str
    scope_id: str
    cluster_id: str
    revision: int
    workflow_id: str
    requested_by: str
    payload: dict[str, Any]
    canonical_payload_hash: str
    idempotency_key: str
    state: ActionState
    approvals_required: int = 1
    approvals: list[dict[str, Any]] = field(default_factory=list)
    rejected_by: str | None = None
    rationale: str | None = None
    provider_run_id: str | None = None
    last_remote_observation: str | None = None
    expires_at: str | None = None
    transitions: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    #: last thing Azure said about the workflow run (not our own state)
    remote_status: str | None = None
    remote_status_at: str | None = None
    remote_run: dict[str, Any] | None = None
    #: only ever set by a person: not_observed | confirmed_effect | confirmed_no_effect
    downstream_effect: str = "not_observed"

    def view(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id, "cluster_id": self.cluster_id,
            "revision": self.revision, "workflow_id": self.workflow_id,
            "requested_by": self.requested_by, "state": self.state.value,
            "approvals_required": self.approvals_required,
            "approvals": self.approvals, "rejected_by": self.rejected_by,
            "rationale": self.rationale, "payload": self.payload,
            "canonical_payload_hash": self.canonical_payload_hash,
            "provider_run_id": self.provider_run_id,
            "last_remote_observation": self.last_remote_observation,
            "expires_at": self.expires_at, "transitions": self.transitions,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "remote_status": self.remote_status,
            "remote_status_at": self.remote_status_at,
            "remote_run": self.remote_run,
            # three distinct layers, never conflated
            "status_layers": {
                "loglookup_dispatch": self.state.value,
                "workflow_run": (self.remote_status
                                 or ("run_reference_recorded" if self.provider_run_id
                                     else "unknown")),
                "downstream_effect": self.downstream_effect,
            },
        }
