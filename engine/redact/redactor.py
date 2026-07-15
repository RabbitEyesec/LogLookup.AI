"""Context-preserving redaction: tokenize sensitive values, restore on return.

Master Specification 5.3: before any cloud AI call, sensitive telemetry is
tokenized (never deleted) — ``192.168.1.50`` becomes ``[IP_INTERNAL_1]``,
the same value always becomes the same token, and real values are restored
in the model's answer. The model reasons over stable placeholders, so
correlation utility is preserved while raw identifiers never leave the
machine. Local mode never redacts and never needs to: no data leaves.

Recognition is deterministic and dependency-free:

- IPv4 addresses (split into internal RFC-1918/loopback/link-local vs
  external),
- e-mail addresses,
- exact entity values the pipeline itself extracted from the cluster
  (usernames, hostnames) — the highest-signal identifiers, known precisely
  because the deterministic engine resolved them.

Microsoft Presidio can be layered in front of this as an optional extra;
the tokenize/restore contract here is the same one it would use. IPv6 and
free-text PII beyond the recognizers above are NOT detected — that
limitation is documented, not hidden.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from engine.ai.payload import EvidencePayload
from engine.ai.schema import AlertTriageVerdict

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

#: "internal" = the ranges an analyst means by it: RFC-1918, loopback,
#: link-local. Explicit list — newer Pythons fold documentation TEST-NETs
#: into ``is_private``, which would mislabel textbook attacker IPs.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "127.0.0.0/8", "169.254.0.0/16")
)

#: payload field-key fragments that identify user / host values.
_USER_KEY_HINTS = ("user.name", "username", "user_name", ".upn")
_HOST_KEY_HINTS = ("hostname", "host.name", "device.name", "computer_name")

_SKIP_VALUES = {"", "null", "none", "unknown", "-"}


class Redactor:
    """One redaction session: consistent tokens, reversible mapping."""

    def __init__(self, extra_values: dict[str, str] | None = None) -> None:
        #: real value -> token, e.g. "192.168.1.50" -> "[IP_INTERNAL_1]"
        self._tokens: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        #: exact known-sensitive values from the cluster: value -> kind
        self._extra = {
            value: kind
            for value, kind in (extra_values or {}).items()
            if value and value.strip().lower() not in _SKIP_VALUES
            and len(value.strip()) >= 2
        }

    # -- construction from the evidence payload ------------------------------

    @classmethod
    def for_payload(cls, payload: EvidencePayload) -> "Redactor":
        """Seed exact-match values from the fields the engine extracted."""
        extra: dict[str, str] = {}
        for key, entries in payload.field_values.items():
            lowered = key.lower()
            kind = None
            if any(hint in lowered for hint in _USER_KEY_HINTS):
                kind = "USER"
            elif any(hint in lowered for hint in _HOST_KEY_HINTS):
                kind = "HOST"
            if kind is None:
                continue
            for _uid, value in entries:
                extra[value] = kind
        return cls(extra)

    # -- tokenization -----------------------------------------------------------

    def _token_for(self, value: str, kind: str) -> str:
        token = self._tokens.get(value)
        if token is None:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            token = f"[{kind}_{self._counters[kind]}]"
            self._tokens[value] = token
        return token

    def redact(self, text: str) -> str:
        """Tokenize every recognized sensitive value in ``text``."""
        # E-mails first (they may embed a username we also match exactly).
        text = _EMAIL.sub(
            lambda m: self._token_for(m.group(0), "EMAIL"), text
        )
        # Exact entity values, longest first so substrings cannot shadow.
        for value in sorted(self._extra, key=len, reverse=True):
            if value in text:
                text = text.replace(
                    value, self._token_for(value, self._extra[value])
                )
        # IPv4 last (never overlaps the token alphabet).
        def ip_sub(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                return raw
            kind = (
                "IP_INTERNAL"
                if any(addr in net for net in _INTERNAL_NETS)
                else "IP_EXTERNAL"
            )
            return self._token_for(raw, kind)

        return _IPV4.sub(ip_sub, text)

    def redact_messages(
        self, messages: Iterable[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Redact user-role content (the evidence payload lives there).

        The system prompt is static persona text with synthetic few-shot
        examples — no telemetry — and stays byte-identical for cacheability.
        """
        redacted = []
        for message in messages:
            if message.get("role") == "user" and isinstance(
                message.get("content"), str
            ):
                message = {**message, "content": self.redact(message["content"])}
            redacted.append(message)
        return redacted

    # -- restoration -------------------------------------------------------------

    @property
    def token_count(self) -> int:
        return len(self._tokens)

    def restore(self, text: str) -> str:
        """Replace tokens back with their real values (best-effort)."""
        for value, token in self._tokens.items():
            if token in text:
                text = text.replace(token, value)
        return text

    def _restore_any(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, list):
            return [self._restore_any(item) for item in value]
        if isinstance(value, dict):
            return {k: self._restore_any(v) for k, v in value.items()}
        return value

    def restore_verdict(self, verdict: AlertTriageVerdict) -> AlertTriageVerdict:
        """Restore real values across every string field of the verdict."""
        if not self._tokens:
            return verdict
        restored = self._restore_any(verdict.model_dump())
        return AlertTriageVerdict(**restored)
