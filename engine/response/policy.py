"""Workflow allowlist and typed payload schemas.

Only workflows named in config *and* defined here can ever be dispatched.
Payload fields are typed and bounded; model output never selects a URL,
identity, Azure resource id, or command.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from engine.response.models import ROLE_RANK, Forbidden, ResponseError

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class FieldSpec:
    type: str = "str"  # str | enum
    required: bool = True
    max_len: int = 500
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkflowDef:
    workflow_id: str
    label: str
    operation: str
    fields: dict[str, FieldSpec]
    approvals_required: int = 1
    separation_of_duties: bool = False
    ttl_seconds: int = 3600
    #: high-impact containment is never offered by default
    material_side_effect: bool = False

    def view(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id, "label": self.label,
            "operation": self.operation,
            "approvals_required": self.approvals_required,
            "separation_of_duties": self.separation_of_duties,
            "ttl_seconds": self.ttl_seconds,
            "fields": {k: {"type": f.type, "required": f.required,
                           "max_len": f.max_len, "choices": list(f.choices)}
                       for k, f in self.fields.items()},
        }


_SEV = ("low", "medium", "high", "critical")
BUILTIN_WORKFLOWS: dict[str, WorkflowDef] = {
    w.workflow_id: w for w in (
        WorkflowDef("notify-soc-v1", "Notify SOC analyst", "notify_analyst",
                    {"message": FieldSpec(max_len=1000),
                     "severity": FieldSpec("enum", choices=_SEV)}),
        WorkflowDef("create-incident-v1", "Create/update downstream incident",
                    "create_or_update_incident",
                    {"title": FieldSpec(max_len=200),
                     "severity": FieldSpec("enum", choices=_SEV),
                     "summary": FieldSpec(max_len=2000, required=False)},
                    separation_of_duties=True, material_side_effect=True),
        WorkflowDef("request-enrichment-v1", "Request enrichment",
                    "request_enrichment",
                    {"entity_type": FieldSpec("enum",
                                              choices=("user", "device", "ip")),
                     "entity_value": FieldSpec(max_len=256)}),
        WorkflowDef("handoff-escalation-v1", "Hand off escalation summary",
                    "hand_off_escalation",
                    {"team": FieldSpec(max_len=100),
                     "summary": FieldSpec(max_len=2000)},
                    separation_of_duties=True),
    )
}


class ResponsePolicy:
    def __init__(self, allowed: tuple[str, ...] | list[str] = (),
                 definitions: dict[str, WorkflowDef] | None = None) -> None:
        defs = definitions or BUILTIN_WORKFLOWS
        unknown = [w for w in allowed if w not in defs]
        if unknown:
            raise ResponseError(f"unknown workflow ids in allowlist: {unknown}")
        self._defs = {w: defs[w] for w in allowed}

    def workflows(self) -> list[WorkflowDef]:
        return list(self._defs.values())

    def get(self, workflow_id: str) -> WorkflowDef:
        try:
            return self._defs[workflow_id]
        except KeyError:
            raise Forbidden(
                f"workflow {workflow_id!r} is not on the allowlist") from None

    @staticmethod
    def require_role(role: str, minimum: str) -> None:
        if ROLE_RANK.get(role, -1) < ROLE_RANK[minimum]:
            raise Forbidden(f"role {role!r} cannot perform this action "
                            f"(requires {minimum})")

    def validate_payload(self, workflow: WorkflowDef,
                         payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ResponseError("payload must be an object")
        extra = set(payload) - set(workflow.fields)
        if extra:
            raise ResponseError(f"unexpected payload fields: {sorted(extra)}")
        clean: dict[str, Any] = {}
        for name, spec in workflow.fields.items():
            value = payload.get(name)
            if value in (None, ""):
                if spec.required:
                    raise ResponseError(f"payload field {name!r} is required")
                continue
            if not isinstance(value, str):
                raise ResponseError(f"payload field {name!r} must be a string")
            value = _CONTROL.sub("", value).strip()
            if len(value) > spec.max_len:
                raise ResponseError(
                    f"payload field {name!r} exceeds {spec.max_len} characters")
            if spec.type == "enum" and value not in spec.choices:
                raise ResponseError(
                    f"payload field {name!r} must be one of {list(spec.choices)}")
            if not value and spec.required:
                raise ResponseError(f"payload field {name!r} is required")
            clean[name] = value
        return clean
