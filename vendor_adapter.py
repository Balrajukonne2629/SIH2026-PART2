"""NTRO PS26155 — Vendor Adapter Contract & Cisco Adapter Implementation.

Defines the vendor-extensible configuration interpretation boundary:
1. VendorAdapter (ABC): Interface contract for vendor-specific configuration handling,
   CSM normalization, and detection hooks.
2. CiscoVendorAdapter: Concrete vendor adapter wrapping existing verified Cisco IOS-XE
   parsing and legacy baseline evaluation logic.

Hard Invariants:
- Pure Python standard library only (strictly AST-safe: zero subprocess, socket, or exec).
- Vendor adapters handle configuration interpretation and CSM normalization; compliance
  evaluation remains vendor-neutral in compliance_framework.py.
- UNKNOWN preservation: missing or unconfigured sections are preserved as Unknown.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Sequence
import re

import cisco_auditor
import juniper_auditor


class VendorAdapter(ABC):
    """Abstract interface defining vendor-specific configuration parsing and normalization.

    Each vendor adapter is responsible for:
    - Interpreting raw CLI / text configuration for its vendor / platform syntax.
    - Normalizing extracted state into the Common Security Model (CSM) dictionary.
    - Providing vendor detection heuristics (detect_confidence).
    """

    @property
    @abstractmethod
    def vendor_id(self) -> str:
        """Stable, unique identifier for the vendor (e.g. 'cisco', 'juniper')."""
        pass

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Human-readable vendor name (e.g. 'Cisco Systems', 'Juniper Networks')."""
        pass

    @property
    @abstractmethod
    def supported_platforms(self) -> Sequence[str]:
        """List of supported operating system platforms (e.g. ('IOS-XE',), ('Junos',))."""
        pass

    @abstractmethod
    def parse(
        self,
        text: str,
        filename: str = "config.txt",
        trusted_rules: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        """Parses raw vendor configuration into the Common Security Model (CSM).

        Args:
            text: Raw configuration text content.
            filename: Source configuration filename for provenance tracking.
            trusted_rules: Optional list of approved custom rule specifications.

        Returns:
            Normalized CSM dictionary conforming to normalized_config_schema.json.
        """
        pass

    @abstractmethod
    def detect_confidence(self, text: str) -> float:
        """Evaluates whether the provided raw configuration text belongs to this vendor.

        Args:
            text: Raw configuration text snippet or full content.

        Returns:
            Confidence score from 0.0 (definitely not this vendor) to 1.0 (certain match).
        """
        pass

    def evaluate_legacy_rules(
        self,
        csm: Dict[str, Any],
        rules: List[dict],
        trusted_rules: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        """Backward-compatibility hook evaluating vendor baseline rules for legacy upload endpoints.

        Core multi-framework compliance evaluation lives in compliance_framework.py.
        This hook delegates to vendor-specific legacy evaluators where supported.
        """
        raise NotImplementedError(
            f"Vendor adapter '{self.vendor_id}' does not implement legacy baseline rule evaluation."
        )


class CiscoVendorAdapter(VendorAdapter):
    """Cisco IOS-XE vendor adapter wrapping verified cisco_auditor parsing logic.

    Preserves 100% behavioral parity with existing Cisco MVP baseline.
    """

    # Distinctive Cisco IOS / IOS-XE CLI syntactic markers
    _CISCO_STRONG_PATTERNS = [
        re.compile(r"^\s*boot-start-marker\b", re.MULTILINE),
        re.compile(r"^\s*version\s+1[567]\.\d+", re.MULTILINE),
        re.compile(r"^\s*interface\s+(?:Gigabit|TenGigabit|Fast|Ethernet|Loopback|Vlan|Serial|Port-channel)\S*", re.MULTILINE | re.IGNORECASE),
        re.compile(r"^\s*line\s+(?:vty|con|aux)\s+\d+", re.MULTILINE),
        re.compile(r"^\s*ip\s+ssh\s+(?:version|time-out|authentication-retries)", re.MULTILINE),
        re.compile(r"^\s*aaa\s+(?:new-model|authentication|authorization|accounting)", re.MULTILINE),
        re.compile(r"^\s*service\s+(?:timestamps|password-encryption|call-home)", re.MULTILINE),
        re.compile(r"^\s*spanning-tree\s+(?:mode|portfast|bpduguard)", re.MULTILINE),
    ]

    _CISCO_MEDIUM_PATTERNS = [
        re.compile(r"^\s*hostname\s+\S+", re.MULTILINE),
        re.compile(r"^\s*snmp-server\s+(?:community|host|location|contact)", re.MULTILINE),
        re.compile(r"^\s*router\s+(?:bgp|ospf|eigrp|rip)\s+\d+", re.MULTILINE),
        re.compile(r"^\s*ip\s+route\s+\S+", re.MULTILINE),
        re.compile(r"^\s*ip\s+access-list\s+(?:standard|extended)\s+\S+", re.MULTILINE),
    ]

    # Explicit signatures of other vendors that indicate this is NOT Cisco
    _NON_CISCO_PATTERNS = [
        re.compile(r"^\s*set\s+system\s+", re.MULTILINE),           # Juniper set syntax
        re.compile(r"^\s*(?:system|interfaces|protocols)\s*\{", re.MULTILINE),  # Juniper bracket syntax
        re.compile(r"^\s*##\s*Last\s+changed:", re.MULTILINE),       # Juniper header
        re.compile(r"^\s*config\s+system\s+", re.MULTILINE),         # FortiOS
    ]

    @property
    def vendor_id(self) -> str:
        return "cisco"

    @property
    def vendor_name(self) -> str:
        return "Cisco Systems"

    @property
    def supported_platforms(self) -> Sequence[str]:
        return ("IOS-XE",)

    def parse(
        self,
        text: str,
        filename: str = "labeled_test_config.txt",
        trusted_rules: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        """Parses Cisco configuration into CSM via verified cisco_auditor."""
        return cisco_auditor.parse_cisco(
            text=text,
            filename=filename,
            trusted_rules=trusted_rules or [],
        )

    def detect_confidence(self, text: str) -> float:
        """Determines confidence that the text represents Cisco configuration.

        Scores based on presence of distinctive Cisco CLI syntax, while actively
        penalizing indicators of other vendors (e.g. Junos set/bracket syntax).
        """
        if not text or not text.strip():
            return 0.0

        # Disqualify if obvious non-Cisco vendor syntax is present
        for pattern in self._NON_CISCO_PATTERNS:
            if pattern.search(text):
                return 0.0

        score = 0.0

        # Check strong markers
        strong_matches = sum(1 for p in self._CISCO_STRONG_PATTERNS if p.search(text))
        if strong_matches >= 3:
            return 1.0
        elif strong_matches >= 1:
            score += 0.5 + (0.2 * strong_matches)

        # Check medium markers
        medium_matches = sum(1 for p in self._CISCO_MEDIUM_PATTERNS if p.search(text))
        score += 0.15 * medium_matches

        # Check bang comment convention common to Cisco
        bang_count = len(re.findall(r"^\s*!\s*$", text, re.MULTILINE))
        if bang_count >= 2:
            score += 0.2

        return min(1.0, max(0.0, score))

    def evaluate_legacy_rules(
        self,
        csm: Dict[str, Any],
        rules: List[dict],
        trusted_rules: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        """Evaluates Cisco baseline rules via verified cisco_auditor."""
        return cisco_auditor.evaluate_rules(
            csm=csm,
            rules=rules,
            trusted_rules=trusted_rules or [],
        )


class JuniperVendorAdapter(VendorAdapter):
    """Juniper Networks vendor adapter wrapping verified juniper_auditor logic.

    Implements:
    - vendor_id = 'juniper'
    - vendor_name = 'Juniper Networks'
    - supported_platforms = ('Junos',)
    - Canonical parsing and CSM normalization via juniper_auditor.parse_juniper
    - Heuristic detection for hierarchical { ... } and flat set Junos configuration syntax
    - Legacy baseline rule evaluation via juniper_auditor.evaluate_rules
    """

    # Strong Junos syntax indicators
    _JUNOS_STRONG_PATTERNS = (
        re.compile(r"^\s*set\s+(system|interfaces|protocols|snmp|firewall|routing-options|routing-instances)\b", re.MULTILINE),
        re.compile(r"^\s*(system|interfaces|protocols|snmp|firewall|routing-options|routing-instances)\s*\{", re.MULTILINE),
        re.compile(r"\bprotocol-version\s+v[12]\b"),
        re.compile(r"\bauthentication-order\s*\["),
        re.compile(r"\b(ge|xe|et|fxp|lo)\-\d+/\d+/\d+"),
    )

    # Medium Junos indicators
    _JUNOS_MEDIUM_PATTERNS = (
        re.compile(r"\bhost-name\s+\S+;"),
        re.compile(r"\b(tacplus-server|radius-server)\b"),
        re.compile(r"\b(protect-control-plane)\b"),
        re.compile(r"\b(instance-type\s+virtual-router)\b"),
        re.compile(r"/\*.*?\*/", re.DOTALL),
        re.compile(r"^\s*##", re.MULTILINE),
    )

    # Disqualifying Cisco-specific patterns
    _NON_JUNOS_PATTERNS = (
        re.compile(r"^\s*!\s*$", re.MULTILINE),
        re.compile(r"^\s*service\s+timestamps\b", re.MULTILINE),
        re.compile(r"^\s*aaa\s+new-model\b", re.MULTILINE),
        re.compile(r"^\s*line\s+vty\b", re.MULTILINE),
        re.compile(r"^\s*ip\s+access-list\b", re.MULTILINE),
        re.compile(r"^\s*interface\s+(GigabitEthernet|Loopback|TenGigabitEthernet)\b", re.MULTILINE),
    )

    @property
    def vendor_id(self) -> str:
        return "juniper"

    @property
    def vendor_name(self) -> str:
        return "Juniper Networks"

    @property
    def supported_platforms(self) -> Sequence[str]:
        return ("Junos",)

    def parse(
        self,
        text: str,
        filename: str = "juniper.conf",
        trusted_rules: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        """Parses raw Juniper Junos configuration into the Common Security Model (CSM)."""
        return juniper_auditor.parse_juniper(
            text=text,
            filename=filename,
            trusted_rules=trusted_rules or [],
        )

    def detect_confidence(self, text: str) -> float:
        """Determines confidence that the text represents Juniper Junos configuration.

        Scores based on presence of distinctive Junos syntax (hierarchical blocks,
        'set ...' commands, Junos interface naming), and immediately returns 0.0
        if Cisco IOS-XE syntax markers are detected.
        """
        if not text or not text.strip():
            return 0.0

        # Disqualify immediately if Cisco syntax is present
        for pattern in self._NON_JUNOS_PATTERNS:
            if pattern.search(text):
                return 0.0

        score = 0.0

        # Check strong markers
        strong_matches = sum(1 for p in self._JUNOS_STRONG_PATTERNS if p.search(text))
        if strong_matches >= 2:
            return 1.0
        elif strong_matches >= 1:
            score += 0.6

        # Check medium markers
        medium_matches = sum(1 for p in self._JUNOS_MEDIUM_PATTERNS if p.search(text))
        score += 0.15 * medium_matches

        return min(1.0, max(0.0, score))

    def evaluate_legacy_rules(
        self,
        csm: Dict[str, Any],
        rules: List[dict],
        trusted_rules: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        """Evaluates Juniper baseline rules via verified juniper_auditor."""
        return juniper_auditor.evaluate_rules(
            csm=csm,
            rules=rules,
            trusted_rules=trusted_rules or [],
        )

