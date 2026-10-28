"""Vendor tactic labels -> canonical ATT&CK tactic names.

Microsoft products emit ``CredentialAccess`` / ``CommandAndControl``; ATT&CK
(and the progression logic in ``engine.correlate.chains``) uses
"Credential Access" / "Command and Control". Without this, a Sentinel
``Execution`` followed by a Defender ``CredentialAccess`` would never be
recognised as a progressing chain.
"""

from __future__ import annotations

import re

from engine.correlate.chains import TACTIC_ORDER

_CANONICAL = {name: name for _uid, name in TACTIC_ORDER}
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")
_MINOR = {"and", "of", "the"}


def _display(name: str) -> str:
    return " ".join(
        w if w in _MINOR else w.capitalize() for w in name.split()
    )


def normalize_tactic(value: object) -> str:
    """Canonical display name, or the cleaned input if it is not a known
    tactic (never dropped: unknown labels such as Sentinel's ``PreAttack``
    pass through unchanged)."""
    text = str(value).strip()
    spaced = re.sub(r"[_\-\s]+", " ", _CAMEL.sub(" ", text)).strip().lower()
    return _display(spaced) if spaced in _CANONICAL else text


def normalize_tactics(values: object) -> list[str]:
    items = values if isinstance(values, (list, tuple)) else [values]
    return [normalize_tactic(v) for v in items if str(v).strip()]
