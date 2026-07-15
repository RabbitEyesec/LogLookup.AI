"""Hybrid declarative field mapping: YAML rules + Python transform hooks.

Standard field-to-field translation is declared in a per-source YAML file
(add a source without recompiling); the hard cases — type coercion, array
handling, severity scales, timestamps — are named Python hooks referenced
from the YAML.

Failure contract (non-negotiable): a field that cannot be coerced is flagged
(``metadata.labels += ["parse_error"]``), routed to ``unmapped`` with its
original value, and the event is still emitted. One bad field never stops
ingestion.

Structural guarantees enforced here by construction:
- expected leaf types come from the OCSF structs themselves (introspected),
  so mapped output always type-checks;
- a field typed as an array is ALWAYS an array, even with one element.
"""

from __future__ import annotations

import functools
import types
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import msgspec
import yaml

from engine.normalize import ocsf
from engine.normalize.timeutil import TimestampError, coerce_time

SEVERITY_NAME_TO_ID = {
    "unknown": 0,
    "informational": 1,
    "info": 1,
    "low": 2,
    "medium": 3,
    "med": 3,
    "high": 4,
    "critical": 5,
    "fatal": 6,
}


class CoercionError(ValueError):
    """A value could not be coerced to its target type."""


# --------------------------------------------------------------------------
# Dotted-path lookup over source events (nested dicts AND flat dotted keys;
# lists encountered mid-path are mapped over).
# --------------------------------------------------------------------------

_MISSING = object()


def lookup(event: Any, path: str) -> Any:
    if isinstance(event, dict) and path in event:
        return event[path]
    current: Any = event
    segments = path.split(".")
    for i, segment in enumerate(segments):
        if isinstance(current, list):
            rest = ".".join(segments[i:])
            values = [
                v for item in current
                if (v := lookup(item, rest)) is not _MISSING
            ]
            return values if values else _MISSING
        if not isinstance(current, dict):
            return _MISSING
        if segment in current:
            current = current[segment]
            continue
        # Flat dotted keys, e.g. {"host.name": "x"} or a flat prefix with a
        # nested remainder, e.g. {"kibana.alert.rule.threat": {"tactic": ...}}.
        for j in range(len(segments), i, -1):
            prefix = ".".join(segments[i:j])
            if prefix in current:
                rest = ".".join(segments[j:])
                node = current[prefix]
                return lookup(node, rest) if rest else node
        return _MISSING
    return current


def first_present(event: Any, paths: list[str]) -> tuple[Any, Optional[str]]:
    for path in paths:
        value = lookup(event, path)
        if value is not _MISSING and value is not None and value != []:
            return value, path
    return _MISSING, None


# --------------------------------------------------------------------------
# Transform hooks (the "code hooks" half of the hybrid strategy)
# --------------------------------------------------------------------------

def _hook_first(value: Any) -> Any:
    if isinstance(value, list):
        if not value:
            raise CoercionError("empty array")
        return value[0]
    return value


def _hook_int(value: Any) -> int:
    if isinstance(value, bool):
        raise CoercionError(f"boolean is not an int: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError:
            raise CoercionError(f"not an integer: {value!r}") from None
    raise CoercionError(f"not an integer: {value!r}")


def _hook_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    raise CoercionError(f"not a string scalar: {value!r}")


def _hook_as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _hook_lower(value: Any) -> str:
    return _hook_str(value).lower()


TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "first": _hook_first,
    "int": _hook_int,
    "str": _hook_str,
    "as_list": _hook_as_list,
    "lower": _hook_lower,
}


def to_severity_id(value: Any) -> int:
    """Cast any vendor severity scale to OCSF severity_id (0-6)."""
    if isinstance(value, list):
        value = _hook_first(value)
    if isinstance(value, bool):
        raise CoercionError(f"not a severity: {value!r}")
    if isinstance(value, (int, float)):
        iv = int(value)
        if 0 <= iv <= 6 and float(value) == iv:
            return iv
        raise CoercionError(f"severity_id out of OCSF range 0-6: {value!r}")
    if isinstance(value, str):
        text = value.strip().lower()
        if text in SEVERITY_NAME_TO_ID:
            return SEVERITY_NAME_TO_ID[text]
        if text.isdigit():
            return to_severity_id(int(text))
        raise CoercionError(f"unknown severity label: {value!r}")
    raise CoercionError(f"not a severity: {value!r}")


# --------------------------------------------------------------------------
# Expected-leaf-type introspection from the OCSF msgspec structs
# --------------------------------------------------------------------------

def _unwrap_optional(annotation: Any) -> Any:
    origin = typing.get_origin(annotation)
    if origin in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


@functools.lru_cache(maxsize=None)
def _struct_hints(struct: type) -> dict[str, Any]:
    """get_type_hints per struct class — it recompiles annotations every
    call, which dominated the parse hot path before caching."""
    return typing.get_type_hints(struct)


@functools.lru_cache(maxsize=None)
def leaf_type(path: str) -> Any:
    """Resolve the annotation for a dotted target path on NormalizedAlert.

    Cached: target paths come from a fixed YAML mapping vocabulary, and the
    struct schema never changes at runtime.
    """
    current: Any = ocsf.NormalizedAlert
    for segment in path.split("."):
        current = _unwrap_optional(current)
        if not (isinstance(current, type) and issubclass(current, msgspec.Struct)):
            raise KeyError(f"cannot descend into {current!r} at {segment!r} of {path}")
        hints = _struct_hints(current)
        if segment not in hints:
            raise KeyError(f"unknown OCSF target field: {path}")
        current = hints[segment]
    return _unwrap_optional(current)


def coerce_to_leaf_type(path: str, value: Any) -> Any:
    """Coerce a mapped value to the struct-declared type of its target."""
    expected = leaf_type(path)
    origin = typing.get_origin(expected)
    if origin is list:
        items = _hook_as_list(value)  # arrays stay arrays; scalars become one
        (item_type,) = typing.get_args(expected) or (Any,)
        if item_type is str:
            return [_hook_str(v) for v in items]
        if item_type is int:
            return [_hook_int(v) for v in items]
        return items
    if expected is str:
        return _hook_str(value)
    if expected is int:
        return _hook_int(value)
    return value


# --------------------------------------------------------------------------
# Mapping specification (loaded from YAML)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldRule:
    target: str
    sources: tuple[str, ...]
    transform: Optional[str] = None
    default: Any = None


@dataclass(frozen=True)
class MappingSpec:
    source_name: str
    timestamp_fields: tuple[str, ...]
    severity_fields: tuple[str, ...]
    field_rules: tuple[FieldRule, ...]
    attacks: dict[str, tuple[str, ...]] = field(default_factory=dict)
    default_offset_minutes: int = 0

    @classmethod
    def from_yaml(cls, path: str | Path) -> "MappingSpec":
        with Path(path).open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        rules = tuple(
            FieldRule(
                target=r["target"],
                sources=tuple(r.get("sources", ())),
                transform=r.get("transform"),
                default=r.get("default"),
            )
            for r in data.get("fields", ())
        )
        # Fail fast on unknown targets/transforms at load time, not per event.
        for rule in rules:
            leaf_type(rule.target)
            if rule.transform is not None and rule.transform not in TRANSFORMS:
                raise KeyError(f"unknown transform hook: {rule.transform}")
        attacks = {
            key: tuple(paths)
            for key, paths in (data.get("attacks") or {}).items()
        }
        ts = data.get("timestamp") or {}
        sev = data.get("severity") or {}
        return cls(
            source_name=data.get("source", "unknown"),
            timestamp_fields=tuple(ts.get("fields", ())),
            severity_fields=tuple(sev.get("fields", ())),
            field_rules=rules,
            attacks=attacks,
            default_offset_minutes=int(ts.get("default_offset_minutes", 0)),
        )


# --------------------------------------------------------------------------
# Mapping execution
# --------------------------------------------------------------------------

def _set_path(tree: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    node = tree
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _build_attacks(event: Any, spec: MappingSpec) -> list[dict[str, Any]]:
    def values_for(key: str) -> list[Any]:
        raw, _ = first_present(event, list(spec.attacks.get(key, ())))
        if raw is _MISSING:
            return []
        return _hook_as_list(raw)

    technique_uids = values_for("technique_uid")
    technique_names = values_for("technique_name")
    tactic_names = values_for("tactic_name")
    tactic_uids = values_for("tactic_uid")
    count = max(
        len(technique_uids), len(technique_names),
        len(tactic_names), len(tactic_uids),
    )
    attacks = []
    for i in range(count):
        def at(items: list[Any]) -> Optional[str]:
            if i < len(items):
                return _hook_str(items[i])
            return items[0] if items and count > 1 and len(items) == 1 else None

        entry: dict[str, Any] = {}
        technique = {
            k: v
            for k, v in (
                ("uid", at(technique_uids)), ("name", at(technique_names))
            )
            if v is not None
        }
        tactic = {
            k: v
            for k, v in (("uid", at(tactic_uids)), ("name", at(tactic_names)))
            if v is not None
        }
        if technique:
            entry["technique"] = technique
        if tactic:
            entry["tactic"] = tactic
        if entry:
            attacks.append(entry)
    return attacks


@dataclass
class MappingResult:
    alert: ocsf.NormalizedAlert
    parse_errors: list[str]


def apply_mapping(
    spec: MappingSpec,
    event: dict[str, Any],
    *,
    raw: bytes,
    received_at: str,
    uid_fallback: str = "",
    default_offset_minutes: Optional[int] = None,
    assume_year: Optional[int] = None,
) -> MappingResult:
    """Map one source event into a NormalizedAlert, never raising per-field."""
    offset = (
        default_offset_minutes
        if default_offset_minutes is not None
        else spec.default_offset_minutes
    )
    parse_errors: list[str] = []
    failed_fields: dict[str, Any] = {}
    tree: dict[str, Any] = {}

    # Event time (the moment it happened at source) -> UTC epoch ms + ISO Z.
    # If the source time is missing/unparseable: flag and fall back to
    # ingestion time so the event is still emitted, never dropped.
    raw_time, time_path = first_present(event, list(spec.timestamp_fields))
    original_time: Optional[str] = None
    if raw_time is _MISSING:
        parse_errors.append("event time missing; used ingestion time")
        time_ms, time_iso = coerce_time(received_at)
    else:
        original_time = raw_time if isinstance(raw_time, str) else str(raw_time)
        try:
            time_ms, time_iso = coerce_time(
                raw_time,
                default_offset_minutes=offset,
                assume_year=assume_year,
            )
        except TimestampError as exc:
            parse_errors.append(f"{time_path}: {exc}; used ingestion time")
            failed_fields[str(time_path)] = raw_time
            time_ms, time_iso = coerce_time(received_at)

    # Severity: cast every vendor scale to severity_id 1-6 (0 = unknown).
    severity_id = ocsf.SEVERITY_UNKNOWN
    severity_label: Optional[str] = None
    raw_severity, severity_path = first_present(event, list(spec.severity_fields))
    if raw_severity is not _MISSING:
        try:
            severity_id = to_severity_id(raw_severity)
            if isinstance(raw_severity, str):
                severity_label = raw_severity
        except CoercionError as exc:
            parse_errors.append(f"{severity_path}: {exc}")
            failed_fields[str(severity_path)] = raw_severity

    # Declarative field rules.
    for rule in spec.field_rules:
        value, source_path = first_present(event, list(rule.sources))
        if value is _MISSING:
            if rule.default is not None:
                _set_path(tree, rule.target, rule.default)
            continue
        try:
            if rule.transform is not None:
                value = TRANSFORMS[rule.transform](value)
            value = coerce_to_leaf_type(rule.target, value)
        except CoercionError as exc:
            parse_errors.append(f"{source_path} -> {rule.target}: {exc}")
            failed_fields[str(source_path)] = value
            continue
        _set_path(tree, rule.target, value)

    # MITRE pre-tags (arrays always).
    try:
        attacks = _build_attacks(event, spec)
    except CoercionError as exc:
        parse_errors.append(f"attacks: {exc}")
        attacks = []
    if attacks:
        _set_path(tree, "finding_info.attacks", attacks)

    finding = tree.setdefault("finding_info", {})
    finding.setdefault("title", "Unknown finding")
    finding.setdefault("uid", uid_fallback)
    metadata = tree.setdefault("metadata", {})
    metadata.setdefault("uid", finding["uid"] or None)
    metadata["original_time"] = original_time
    metadata["processed_time"] = received_at
    if parse_errors:
        metadata["labels"] = list(metadata.get("labels", [])) + [
            ocsf.PARSE_ERROR_LABEL
        ]

    unmapped: dict[str, Any] = {"raw": raw.decode("utf-8", errors="replace")}
    if parse_errors:
        unmapped["parse_errors"] = parse_errors
    if failed_fields:
        unmapped["fields"] = failed_fields

    tree["time"] = time_ms
    tree["time_dt"] = time_iso
    tree["severity_id"] = severity_id
    if severity_label is not None:
        tree["severity"] = severity_label
    tree["unmapped"] = unmapped

    alert = msgspec.convert(tree, ocsf.NormalizedAlert, strict=False)
    return MappingResult(alert=alert, parse_errors=parse_errors)
