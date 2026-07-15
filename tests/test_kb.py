"""Phase 10 acceptance: ATT&CK knowledge base build/load/lookup."""

from __future__ import annotations

import msgspec
import pytest

from engine.ai.kb import (
    AttackKB,
    KBError,
    compile_stix_bundle,
    normalize_technique_id,
)


def _stix_technique(uid: str, name: str, *, tactic: str = "credential-access",
                    revoked: bool = False, deprecated: bool = False) -> dict:
    return {
        "type": "attack-pattern",
        "name": name,
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "x_mitre_platforms": ["Linux", "Windows"],
        "x_mitre_detection": f"Monitor for {name} behaviour.",
        "x_mitre_is_subtechnique": "." in uid,
        "description": f"{name} technique description.",
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": tactic},
        ],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": uid,
             "url": f"https://attack.mitre.org/techniques/{uid.replace('.', '/')}"},
        ],
    }


@pytest.fixture()
def bundle() -> dict:
    """Small STIX-bundle-shaped fixture using real, well-known technique ids."""
    return {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "19.1"},
            _stix_technique("T1110", "Brute Force"),
            _stix_technique("T1003", "OS Credential Dumping"),
            _stix_technique("T1021", "Remote Services", tactic="lateral-movement"),
            _stix_technique("T1059.001", "PowerShell", tactic="execution"),
            _stix_technique("T9999", "Old Revoked Thing", revoked=True),
            _stix_technique("T9998", "Old Deprecated Thing", deprecated=True),
            {"type": "intrusion-set", "name": "not-a-technique"},
        ],
    }


def test_compile_excludes_revoked_and_deprecated(bundle):
    kb_file = compile_stix_bundle(bundle, source="fixture")
    uids = [t.uid for t in kb_file.techniques]
    assert uids == ["T1003", "T1021", "T1059.001", "T1110"]  # uid-sorted
    assert kb_file.attack_version == "19.1"
    assert kb_file.built_at.endswith("Z")


def test_lookup_normalizes_case_and_rejects_garbage(bundle):
    kb = AttackKB.from_bundle(bundle, source="fixture")
    assert kb.get("t1110").name == "Brute Force"
    assert kb.get("T1059.001").is_subtechnique is True
    assert "T1021" in kb
    assert kb.get("T0000") is None
    assert kb.get("DROP TABLE") is None
    assert normalize_technique_id("t1003.001") == "T1003.001"
    assert normalize_technique_id("TA0006") is None  # tactic id, not technique


def test_tactic_names_are_denormalized(bundle):
    kb = AttackKB.from_bundle(bundle, source="fixture")
    assert kb.get("T1021").tactics == ["lateral movement"]


def test_save_load_roundtrip(tmp_path, bundle):
    kb = AttackKB.from_bundle(bundle, source="fixture")
    path = kb.save(tmp_path / "kb" / "attack_kb.json")
    loaded = AttackKB.load(path)
    assert len(loaded) == len(kb) == 4
    assert loaded.attack_version == "19.1"
    assert loaded.get("T1110").document().startswith("T1110\nBrute Force")


def test_load_missing_or_corrupt(tmp_path):
    with pytest.raises(KBError, match="not found"):
        AttackKB.load(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"{not json")
    with pytest.raises(KBError, match="cannot decode"):
        AttackKB.load(bad)


def test_empty_bundle_rejected():
    with pytest.raises(KBError):
        compile_stix_bundle({"objects": []}, source="fixture")
    with pytest.raises(KBError):
        compile_stix_bundle({}, source="fixture")


def test_kb_file_is_stable_json(tmp_path, bundle):
    kb = AttackKB.from_bundle(bundle, source="fixture")
    path = kb.save(tmp_path / "kb.json")
    decoded = msgspec.json.decode(path.read_bytes())
    assert decoded["source"] == "fixture"
    assert decoded["techniques"][0]["uid"] == "T1003"
