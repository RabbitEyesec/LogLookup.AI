"""MITRE ATT&CK knowledge base the ground truth for technique mapping.

The KB is compiled from the official MITRE ATT&CK Enterprise STIX bundle
(mitre-attack/attack-stix-data). Techniques are NEVER authored by hand or
recalled from model memory: build the KB from MITRE's published data, then
every technique the AI may return must exist in this KB and be present in
the retrieved candidate payload (see validator.py).

Build once (downloads ~50MB, writes a compact local KB):

    python -m engine.ai.kb --build [--source FILE_OR_URL] [--out PATH]
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

import httpx
import msgspec

logger = logging.getLogger(__name__)

#: Official MITRE ATT&CK Enterprise STIX 2.1 bundle (mitre-attack org).
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class KBError(Exception):
    """Raised when the knowledge base cannot be built or loaded."""


class TechniqueRecord(msgspec.Struct, kw_only=True, omit_defaults=True):
    """One ATT&CK technique, compiled from the official STIX bundle."""

    uid: str  # e.g. "T1110" or "T1059.001"
    name: str
    tactics: list[str] = msgspec.field(default_factory=list)  # phase names
    description: str = ""
    platforms: list[str] = msgspec.field(default_factory=list)
    detection: str = ""
    url: str = ""
    is_subtechnique: bool = False

    def document(self) -> str:
        """Retrieval document: the text the technique is matched against."""
        parts = [self.uid, self.name, " ".join(self.tactics),
                 " ".join(self.platforms), self.description, self.detection]
        return "\n".join(p for p in parts if p)


class KBFile(msgspec.Struct, kw_only=True):
    """On-disk KB shape."""

    source: str
    attack_version: str = ""
    built_at: str = ""
    techniques: list[TechniqueRecord] = msgspec.field(default_factory=list)


def normalize_technique_id(value: str) -> Optional[str]:
    """Uppercased canonical technique id, or None if not id-shaped."""
    candidate = value.strip().upper()
    return candidate if TECHNIQUE_ID_PATTERN.match(candidate) else None


def _mitre_external_ref(obj: dict[str, Any]) -> tuple[str, str]:
    for ref in obj.get("external_references") or ():
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id") or "", ref.get("url") or ""
    return "", ""


def compile_stix_bundle(bundle: dict[str, Any], *, source: str) -> KBFile:
    """Compile a STIX bundle into technique records.

    Revoked and deprecated attack-patterns are excluded; nothing is added
    that MITRE has not published.
    """
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise KBError("not a STIX bundle: missing 'objects' list")

    attack_version = ""
    techniques: list[TechniqueRecord] = []
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            attack_version = obj.get("x_mitre_version", "") or attack_version
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id, url = _mitre_external_ref(obj)
        uid = normalize_technique_id(external_id or "")
        if uid is None:
            continue
        tactics = [
            phase.get("phase_name", "").replace("-", " ")
            for phase in obj.get("kill_chain_phases") or ()
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            TechniqueRecord(
                uid=uid,
                name=obj.get("name", ""),
                tactics=[t for t in tactics if t],
                description=obj.get("description", "") or "",
                platforms=list(obj.get("x_mitre_platforms") or ()),
                detection=obj.get("x_mitre_detection", "") or "",
                url=url,
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
            )
        )
    if not techniques:
        raise KBError("STIX bundle contained no usable attack-patterns")
    techniques.sort(key=lambda t: t.uid)

    from engine.normalize.timeutil import now_utc_iso

    return KBFile(
        source=source,
        attack_version=attack_version,
        built_at=now_utc_iso(),
        techniques=techniques,
    )


class AttackKB:
    """In-memory ATT&CK technique lookup."""

    def __init__(self, kb_file: KBFile) -> None:
        self._meta = kb_file
        self._by_uid: dict[str, TechniqueRecord] = {
            t.uid: t for t in kb_file.techniques
        }

    # -- lookups --------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._by_uid)

    def __contains__(self, uid: str) -> bool:
        return self.get(uid) is not None

    def get(self, uid: str) -> Optional[TechniqueRecord]:
        normalized = normalize_technique_id(uid or "")
        if normalized is None:
            return None
        return self._by_uid.get(normalized)

    def techniques(self) -> list[TechniqueRecord]:
        """All techniques, uid-sorted (deterministic iteration order)."""
        return list(self._meta.techniques)

    @property
    def attack_version(self) -> str:
        return self._meta.attack_version

    @property
    def source(self) -> str:
        return self._meta.source

    @property
    def built_at(self) -> str:
        return self._meta.built_at

    # -- persistence ----------------------------------------------------------

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(msgspec.json.encode(self._meta))
        return path

    @classmethod
    def load(cls, path: str | Path) -> "AttackKB":
        path = Path(path)
        if not path.exists():
            raise KBError(
                f"ATT&CK knowledge base not found at {path}; build it with "
                f"'python -m engine.ai.kb --build'"
            )
        try:
            kb_file = msgspec.json.decode(path.read_bytes(), type=KBFile)
        except msgspec.DecodeError as exc:
            raise KBError(f"cannot decode knowledge base {path}: {exc}") from exc
        return cls(kb_file)

    @classmethod
    def from_bundle(cls, bundle: dict[str, Any], *, source: str) -> "AttackKB":
        return cls(compile_stix_bundle(bundle, source=source))


def _read_bundle(source: str) -> dict[str, Any]:
    """Load a STIX bundle from a local file or an https URL."""
    if source.startswith(("http://", "https://")):
        logger.info("downloading ATT&CK STIX bundle from %s", source)
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            response = client.get(source)
            if response.status_code != 200:
                raise KBError(
                    f"bundle download failed: HTTP {response.status_code}"
                )
            return msgspec.json.decode(response.content)
    path = Path(source)
    if not path.exists():
        raise KBError(f"bundle file not found: {path}")
    return msgspec.json.decode(path.read_bytes())


def build_kb(source: str = ATTACK_STIX_URL,
             out_path: str | Path = "var/attack_kb.json") -> AttackKB:
    """Download/compile the official bundle and persist the compact KB."""
    kb = AttackKB.from_bundle(_read_bundle(source), source=source)
    saved = kb.save(out_path)
    logger.info(
        "ATT&CK KB built: %d techniques (ATT&CK v%s) -> %s",
        len(kb), kb.attack_version or "?", saved,
    )
    return kb


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m engine.ai.kb",
        description="Build the local MITRE ATT&CK knowledge base.",
    )
    parser.add_argument("--build", action="store_true",
                        help="compile the KB from the official STIX bundle")
    parser.add_argument("--source", default=ATTACK_STIX_URL,
                        help="STIX bundle file path or URL")
    parser.add_argument("--out", default="var/attack_kb.json",
                        help="output KB path")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.build:
        parser.error("nothing to do; pass --build")

    from engine.log import setup_logging

    setup_logging("INFO")
    kb = build_kb(args.source, args.out)
    print(f"built {len(kb)} techniques (ATT&CK v{kb.attack_version or '?'}) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
