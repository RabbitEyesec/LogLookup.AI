"""Internal OCSF representation: DetectionFinding (class_uid 2004).

msgspec Structs on the hot parse path ("msgspec in, Pydantic out"): field
names and semantics follow the OCSF DetectionFinding event class, so this is
a faithful OCSF carrier, not a custom schema. ``ocsf_bridge`` converts into
py-ocsf-models' Pydantic ``DetectionFinding`` for typed OCSF interop.

Structural guarantees the correlation engine depends on:
- ``time`` is epoch milliseconds UTC; ``time_dt`` is ISO-8601 with ``Z``.
- Array-typed fields are ALWAYS arrays, even with one element.
- The raw source event is preserved byte-for-byte in ``unmapped.raw``.
- Struct field order is fixed by definition -> stable key order on encode.
"""

from __future__ import annotations

from typing import Any, Optional

import msgspec

OCSF_VERSION = "1.1.0"
CLASS_UID = 2004
CLASS_NAME = "Detection Finding"
CATEGORY_UID = 2
CATEGORY_NAME = "Findings"

#: OCSF severity_id values (base event): 0=Unknown .. 6=Fatal.
SEVERITY_UNKNOWN = 0
SEVERITY_LABELS = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}

#: Flag label applied to metadata.labels when any field failed coercion.
PARSE_ERROR_LABEL = "parse_error"


class Product(msgspec.Struct, kw_only=True, omit_defaults=True):
    vendor_name: str = "unknown"
    name: Optional[str] = None
    version: Optional[str] = None


class Metadata(msgspec.Struct, kw_only=True, omit_defaults=True):
    product: Product = msgspec.field(default_factory=Product)
    version: str = OCSF_VERSION
    uid: Optional[str] = None
    original_time: Optional[str] = None
    #: ingestion time (when WE received the event), UTC ISO-8601 Z. The gap
    #: vs event time flags clock skew / delayed telemetry.
    processed_time: Optional[str] = None
    log_name: Optional[str] = None
    event_code: Optional[str] = None
    labels: list[str] = msgspec.field(default_factory=list)


class Tactic(msgspec.Struct, kw_only=True, omit_defaults=True):
    name: Optional[str] = None
    uid: Optional[str] = None


class Technique(msgspec.Struct, kw_only=True, omit_defaults=True):
    name: Optional[str] = None
    uid: Optional[str] = None


class MitreAttack(msgspec.Struct, kw_only=True, omit_defaults=True):
    tactic: Optional[Tactic] = None
    technique: Optional[Technique] = None
    version: Optional[str] = None


class Analytic(msgspec.Struct, kw_only=True, omit_defaults=True):
    name: Optional[str] = None
    uid: Optional[str] = None
    type: Optional[str] = None


class FindingInfo(msgspec.Struct, kw_only=True, omit_defaults=True):
    title: str = "Unknown finding"
    uid: str = ""
    desc: Optional[str] = None
    analytic: Optional[Analytic] = None
    attacks: list[MitreAttack] = msgspec.field(default_factory=list)
    types: list[str] = msgspec.field(default_factory=list)
    data_sources: list[str] = msgspec.field(default_factory=list)


class OperatingSystem(msgspec.Struct, kw_only=True, omit_defaults=True):
    name: Optional[str] = None
    type: Optional[str] = None


class Device(msgspec.Struct, kw_only=True, omit_defaults=True):
    hostname: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    #: durable asset / agent identifier (e.g. EDR agent GUID)
    uid: Optional[str] = None
    name: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[OperatingSystem] = None


class User(msgspec.Struct, kw_only=True, omit_defaults=True):
    name: Optional[str] = None
    uid: Optional[str] = None
    domain: Optional[str] = None
    email_addr: Optional[str] = None


class Process(msgspec.Struct, kw_only=True, omit_defaults=True):
    #: process GUID / entity id — highest-precedence correlation identifier
    uid: Optional[str] = None
    pid: Optional[int] = None
    name: Optional[str] = None
    cmd_line: Optional[str] = None


class Actor(msgspec.Struct, kw_only=True, omit_defaults=True):
    user: Optional[User] = None
    process: Optional[Process] = None


class NetworkEndpoint(msgspec.Struct, kw_only=True, omit_defaults=True):
    ip: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None


class NormalizedAlert(msgspec.Struct, kw_only=True, omit_defaults=True):
    """OCSF DetectionFinding-shaped normalized alert.

    ``unmapped`` always contains at least ``{"raw": <original event,
    byte-for-byte>}``; fields that failed coercion are routed to
    ``unmapped["fields"]`` with messages in ``unmapped["parse_errors"]``.
    """

    # event time: the moment it happened at source
    time: int  # epoch milliseconds, UTC
    time_dt: str  # ISO-8601 UTC with Z — same instant as `time`
    severity_id: int = SEVERITY_UNKNOWN
    severity: Optional[str] = None
    metadata: Metadata = msgspec.field(default_factory=Metadata)
    finding_info: FindingInfo = msgspec.field(default_factory=FindingInfo)
    message: Optional[str] = None
    device: Optional[Device] = None
    actor: Optional[Actor] = None
    src_endpoint: Optional[NetworkEndpoint] = None
    dst_endpoint: Optional[NetworkEndpoint] = None
    unmapped: dict[str, Any] = msgspec.field(default_factory=dict)
    # fixed OCSF envelope
    class_uid: int = CLASS_UID
    class_name: str = CLASS_NAME
    category_uid: int = CATEGORY_UID
    category_name: str = CATEGORY_NAME
    activity_id: int = 1  # Create
    type_uid: int = CLASS_UID * 100 + 1  # 200401 = Detection Finding: Create

    @property
    def uid(self) -> str:
        return self.finding_info.uid

    @property
    def has_parse_errors(self) -> bool:
        return PARSE_ERROR_LABEL in self.metadata.labels

    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity_id, "Unknown")


def encode_alert(alert: NormalizedAlert) -> bytes:
    """Serialize with stable key order (struct definition order)."""
    return msgspec.json.encode(alert)


def decode_alert(data: bytes | str) -> NormalizedAlert:
    return msgspec.json.decode(data, type=NormalizedAlert)
