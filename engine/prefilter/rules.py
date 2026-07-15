"""Benign-suppression rules — entirely deterministic, allowlist-driven.

Suppresses the known-benign before attention (and, in a later phase, the AI)
sees it: trusted source IPs/CIDRs, expected service accounts, approved
scanner hosts, and alerts below the configured severity floor. Every
decision is inspectable: it names the rule and the matched value.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional

from engine.config import PrefilterConfig, SiemConfig
from engine.normalize.ocsf import NormalizedAlert

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Decision:
    """Outcome of pre-filtering one alert."""

    suppressed: bool
    rule: Optional[str] = None  # which rule fired
    matched: Optional[str] = None  # the value that matched

    @property
    def kept(self) -> bool:
        return not self.suppressed


class PreFilter:
    """Deterministic known-benign suppression."""

    def __init__(self, config: PrefilterConfig, siem: SiemConfig) -> None:
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in config.trusted_ips:
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise ValueError(
                    f"prefilter.trusted_ips entry is not an IP or CIDR: {entry!r}"
                ) from None
        self._service_accounts = {
            name.lower() for name in config.expected_service_accounts
        }
        self._scanner_hosts = {
            host.lower() for host in config.approved_scanner_hosts
        }
        self._severity_floor_id = siem.severity_floor_id
        self.kept_count = 0
        self.suppressed_count = 0

    def _trusted_ip_match(self, alert: NormalizedAlert) -> Optional[str]:
        candidates = []
        if alert.src_endpoint is not None and alert.src_endpoint.ip:
            candidates.append(alert.src_endpoint.ip)
        if alert.device is not None and alert.device.ip:
            candidates.append(alert.device.ip)
        for candidate in candidates:
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                continue  # unparseable IP is never "trusted"
            if any(addr in network for network in self._networks):
                return candidate
        return None

    def evaluate(self, alert: NormalizedAlert) -> Decision:
        """Decide keep/suppress for one normalized alert."""
        # Severity routing floor (siem.severity_floor). Severity 0 (unknown)
        # is always kept: unknown is ambiguous, not benign.
        if 0 < alert.severity_id < self._severity_floor_id:
            return self._record(Decision(
                suppressed=True,
                rule="severity_floor",
                matched=alert.severity_label(),
            ))

        matched_ip = self._trusted_ip_match(alert)
        if matched_ip is not None:
            return self._record(Decision(
                suppressed=True, rule="trusted_ip", matched=matched_ip
            ))

        user = alert.actor.user if alert.actor is not None else None
        if user is not None and user.name and (
            user.name.lower() in self._service_accounts
        ):
            return self._record(Decision(
                suppressed=True,
                rule="expected_service_account",
                matched=user.name,
            ))

        device = alert.device
        if device is not None and device.hostname and (
            device.hostname.lower() in self._scanner_hosts
        ):
            return self._record(Decision(
                suppressed=True,
                rule="approved_scanner_host",
                matched=device.hostname,
            ))

        return self._record(Decision(suppressed=False))

    def _record(self, decision: Decision) -> Decision:
        if decision.suppressed:
            self.suppressed_count += 1
            logger.debug(
                "suppressed by %s (matched %r)", decision.rule, decision.matched
            )
        else:
            self.kept_count += 1
        return decision
