"""Entra ID sign-in / directory-audit records -> ContextObservation.

Absent fields (Conditional Access details, risk data on unlicensed
tenants) are recorded as *unavailable*, never inferred. A directory change
is described, not judged: nothing here declares an event malicious.
"""

from __future__ import annotations

from typing import Any

from engine.envelope import KIND_DIRECTORY_AUDIT, KIND_SIGNIN, SourceEnvelope
from engine.normalize.context import ContextObservation, base_context


def _get(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


class EntraContextAdapter:
    name = "entra_id"

    def parse_context(
        self, payload: dict[str, Any], envelope: SourceEnvelope
    ) -> list[ContextObservation]:
        if envelope.record_kind == KIND_SIGNIN:
            return [self._signin(payload, envelope)]
        if envelope.record_kind == KIND_DIRECTORY_AUDIT:
            return self._audit(payload, envelope)
        return []

    def _signin(self, p: dict[str, Any], env: SourceEnvelope) -> ContextObservation:
        upn = p.get("userPrincipalName") or None
        warnings: list[str] = []
        ca = p.get("conditionalAccessStatus")
        if ca is None:
            warnings.append("conditional_access_unavailable")
        if p.get("riskLevelDuringSignIn") is None and p.get("riskState") is None:
            warnings.append("risk_data_unavailable")
        entities = []
        if upn:
            entities.append({"type": "user", "key": upn.lower(), "display": upn})
        if p.get("userId"):
            entities.append({"type": "user_object", "key": p["userId"],
                             "display": p.get("userDisplayName") or p["userId"]})
        if p.get("ipAddress"):
            entities.append({"type": "ip", "key": p["ipAddress"],
                             "display": p["ipAddress"]})
        if _get(p, "deviceDetail", "deviceId"):
            entities.append({"type": "device",
                             "key": p["deviceDetail"]["deviceId"],
                             "display": p["deviceDetail"].get("displayName")
                             or p["deviceDetail"]["deviceId"]})
        status = p.get("status") or {}
        attributes = {
            "app": p.get("appDisplayName"), "app_id": p.get("appId"),
            "resource": p.get("resourceDisplayName"),
            "client_app": p.get("clientAppUsed"),
            "ip": p.get("ipAddress"),
            "location": p.get("location"),
            "device": p.get("deviceDetail"),
            "result": "success" if status.get("errorCode") == 0 else "failure",
            "error_code": status.get("errorCode"),
            "failure_reason": status.get("failureReason"),
            "authentication_requirement": p.get("authenticationRequirement"),
            "mfa_detail": p.get("mfaDetail"),
            "authentication_details": p.get("authenticationDetails"),
            "conditional_access_status": ca,
            "risk_level": p.get("riskLevelDuringSignIn"),
            "risk_state": p.get("riskState"),
            "correlation_id": p.get("correlationId"),
        }
        return base_context(env, "signin", upn, p.get("createdDateTime"),
                            entities, attributes, warnings)

    def _audit(self, p: dict[str, Any], env: SourceEnvelope) -> list[ContextObservation]:
        init_user = _get(p, "initiatedBy", "user", "userPrincipalName")
        init_app = _get(p, "initiatedBy", "app", "displayName")
        targets = p.get("targetResources") or []
        attributes = {
            "activity": p.get("activityDisplayName"),
            "category": p.get("category"),
            "result": p.get("result"),
            "result_reason": p.get("resultReason"),
            "initiated_by_user": init_user, "initiated_by_app": init_app,
            "targets": [
                {"id": t.get("id"), "type": t.get("type"),
                 "name": t.get("displayName"),
                 "upn": t.get("userPrincipalName"),
                 "modified_properties": t.get("modifiedProperties")}
                for t in targets if isinstance(t, dict)
            ],
            "correlation_id": p.get("correlationId"),
        }
        principals: list[str] = []
        if init_user:
            principals.append(init_user)
        for t in targets:
            upn = t.get("userPrincipalName") if isinstance(t, dict) else None
            if upn and upn not in principals:
                principals.append(upn)
        if not principals:
            principals = [None]  # type: ignore[list-item]
        out = []
        for principal in principals:
            entities = [{"type": "user", "key": principal.lower(),
                         "display": principal}] if principal else []
            attributes_p = dict(attributes,
                                role=("initiator" if principal == init_user else "target"))
            out.append(base_context(
                env, "directory_audit", principal,
                p.get("activityDateTime"), entities, attributes_p))
        return out
