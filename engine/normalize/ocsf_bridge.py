"""Bridge from the internal msgspec alert to py-ocsf-models' DetectionFinding.

Confirms the OCSF target (DetectionFinding, class_uid 2004) against the typed
Pydantic models from py-ocsf-models. The bridge is NOT on the hot parse path
— msgspec structs are; it exists for typed OCSF interop and validation.

Note: py-ocsf-models 0.9.0 does not model ``device``/``actor``/
``src_endpoint`` on DetectionFinding (a subset of the OCSF spec), so those
travel only on the internal struct; the envelope, finding_info, MITRE
attacks, severity, time, and unmapped round-trip through the typed model.
"""

from __future__ import annotations

from py_ocsf_models.events.base_event import SeverityID
from py_ocsf_models.events.findings.detection_finding import (
    DetectionFinding,
    DetectionFindingTypeID,
)
from py_ocsf_models.events.findings.finding import ActivityID
from py_ocsf_models.objects.finding_info import FindingInformation
from py_ocsf_models.objects.metadata import Metadata as OcsfMetadata
from py_ocsf_models.objects.mitre_attack import (
    MITREAttack,
    Tactic as OcsfTactic,
    Technique as OcsfTechnique,
)
from py_ocsf_models.objects.product import Product as OcsfProduct

from engine.normalize.ocsf import NormalizedAlert


def to_detection_finding(alert: NormalizedAlert) -> DetectionFinding:
    """Build a validated py-ocsf-models DetectionFinding from an alert."""
    attacks = []
    for attack in alert.finding_info.attacks:
        tactic = None
        technique = None
        if attack.tactic is not None:
            tactic = OcsfTactic(name=attack.tactic.name, uid=attack.tactic.uid)
        if attack.technique is not None and attack.technique.uid is not None:
            technique = OcsfTechnique(
                name=attack.technique.name or attack.technique.uid,
                uid=attack.technique.uid,
            )
        attacks.append(
            MITREAttack(tactic=tactic, technique=technique, version=attack.version)
        )

    finding_info = FindingInformation(
        title=alert.finding_info.title,
        uid=alert.finding_info.uid,
        desc=alert.finding_info.desc,
        attacks=attacks or None,
        types=list(alert.finding_info.types) or None,
        data_sources=list(alert.finding_info.data_sources) or None,
    )
    metadata = OcsfMetadata(
        product=OcsfProduct(
            vendor_name=alert.metadata.product.vendor_name,
            name=alert.metadata.product.name,
            version=alert.metadata.product.version,
        ),
        version=alert.metadata.version,
        uid=alert.metadata.uid,
        original_time=alert.metadata.original_time,
        labels=list(alert.metadata.labels) or None,
        log_name=alert.metadata.log_name,
        event_code=alert.metadata.event_code,
    )
    return DetectionFinding(
        activity_id=ActivityID(alert.activity_id),
        category_uid=alert.category_uid,
        category_name=alert.category_name,
        class_uid=alert.class_uid,
        class_name=alert.class_name,
        type_uid=DetectionFindingTypeID(alert.type_uid),
        time=alert.time,
        severity_id=SeverityID(alert.severity_id),
        severity=alert.severity_label(),
        message=alert.message,
        finding_info=finding_info,
        metadata=metadata,
        unmapped=alert.unmapped,
    )
