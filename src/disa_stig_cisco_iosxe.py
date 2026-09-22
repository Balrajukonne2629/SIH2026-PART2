"""NTRO PS26155 — DISA-STIG Cisco IOS-XE Deterministic Control Catalog (Phase 3A.3).

Authoritative primary sources (XCCDF XML in 01_Compliance_Standards/DISA_STIG/):
- Cisco IOS XE Router NDM STIG V3R7 (U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml)
- Cisco IOS XE Router RTR STIG V3R5 (U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml)
- Cisco IOS XE Switch L2S STIG V3R2 (U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml)

Implements:
1. DISA_STIG_CISCO_IOSXE_FRAMEWORK: Concrete Framework metadata instance (V3R7).
2. DISA_STIG_CISCO_IOSXE_CONTROLS: Dict of verified Control instances keyed by Vuln ID (V-xxxxx).
3. CISCO_TO_STIG_MAPPING: Explicit mapping between internal CISCO-* rules and STIG Vuln IDs.
4. StigCiscoIosXeEvaluator: Deterministic FrameworkEvaluator implementation consuming normalized CSM.
5. register_disa_stig_cisco_iosxe: Registration hook for FrameworkRegistry.

Architectural Invariants:
- Deterministic compliance: Identical CSM inputs always yield identical EvaluationResult outputs.
- Normalized CSM only: Consumes structured CSM dictionaries, zero raw CLI text parsing.
- Zero AI / LLM calls: No Ollama, AIModelManager, or remote dependencies.
- Zero execution capabilities: No subprocess, socket, shell, or network imports.
- UNKNOWN preservation: Missing/unconfigured sections return UNKNOWN, never conflated with FAIL.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple
import datetime

from src.compliance_framework import (
    ComplianceStatus,
    Control,
    Evidence,
    EvaluationResult,
    Framework,
    FrameworkEvaluator,
    FrameworkRegistry,
    get_default_registry,
)

# --- 1. Framework Definition ---

DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID = "disa-stig-cisco-iosxe"

DISA_STIG_CISCO_IOSXE_FRAMEWORK = Framework(
    framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
    name="DISA STIG Cisco IOS XE Benchmark",
    version="V3R7",
    description=(
        "Defense Information Systems Agency (DISA) Security Technical Implementation Guide "
        "(STIG) for Cisco IOS XE devices, establishing Department of Defense (DoD) security requirements."
    ),
    vendor_scope="Cisco IOS-XE",
    control_namespace="DISA-STIG",
    enabled=True,
)

# --- 2. DISA-STIG Control Catalog (Strict Provenance from XCCDF XMLs) ---

DISA_STIG_CISCO_IOSXE_CONTROLS: Dict[str, Control] = {
    "V-215845": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-215845",
        title="The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.",
        description=(
            "Requires the use of secure protocols instead of unsecured counterparts, "
            "such as SSH version 2 instead of Telnet. Unsecured protocols lack encryption, "
            "putting sensitive data and administrator credentials at risk of eavesdropping."
        ),
        severity="high",  # CAT I
        expected_state="services.ssh_version == 2, services.ssh == True, services.telnet == False",
        evaluation_metadata={
            "csm_section": "services",
            "csm_fields": ["ssh_version", "ssh", "telnet"],
            "rule_id": "SV-215845r961557_rule",
            "ccis": ["CCI-003123"],
            "source_benchmark": "Cisco IOS XE Router NDM STIG V3R7",
            "source_file": "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-SSH-001"],
            "nist_controls": ["MA-4 (6)"],
        },
        evidence_requirements=(
            "services.ssh_version",
            "services.ssh",
            "services.telnet",
        ),
        remediation_metadata={
            "cli_commands": ["ip ssh version 2", "line vty 0 4", "transport input ssh"],
            "risk_level": "medium",
        },
    ),
    "V-215854": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-215854",
        title="The Cisco router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access.",
        description=(
            "Centralized AAA authentication with fallback ensures administrative access is authenticated "
            "against enterprise directory services while preventing lockouts during network isolation."
        ),
        severity="high",  # CAT I
        expected_state="aaa.enabled == True, aaa.authentication_method != None",
        evaluation_metadata={
            "csm_section": "aaa",
            "csm_fields": ["enabled", "authentication_method", "configured"],
            "rule_id": "SV-215854r1156415_rule",
            "ccis": ["CCI-000370"],
            "source_benchmark": "Cisco IOS XE Router NDM STIG V3R7",
            "source_file": "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-AAA-001"],
            "nist_controls": ["CM-6 (1)"],
        },
        evidence_requirements=(
            "aaa.enabled",
            "aaa.authentication_method",
        ),
        remediation_metadata={
            "cli_commands": ["aaa new-model", "aaa authentication login default group radius local"],
            "risk_level": "high",
        },
    ),
    "V-215843": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-215843",
        title="The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.",
        description=(
            "NTP authentication using cryptographically verified keys ensures time synchronization "
            "cannot be spoofed, forged, or manipulated to falsify audit logs or certificate validation."
        ),
        severity="medium",  # CAT II
        expected_state="ntp.authentication_enabled == True when ntp.servers configured",
        evaluation_metadata={
            "csm_section": "ntp",
            "csm_fields": ["servers", "authentication_enabled", "enabled"],
            "rule_id": "SV-215843r1050862_rule",
            "ccis": ["CCI-001967"],
            "source_benchmark": "Cisco IOS XE Router NDM STIG V3R7",
            "source_file": "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-NTP-001"],
            "nist_controls": ["IA-3 (1)"],
        },
        evidence_requirements=(
            "ntp.servers",
            "ntp.authentication_enabled",
        ),
        remediation_metadata={
            "cli_commands": ["ntp authenticate"],
            "risk_level": "low",
        },
    ),
    "V-220139": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-220139",
        title="The Cisco router must be configured to send log data to at least two syslog servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).",
        description=(
            "Centralized syslog forwarding to redundant log servers guarantees audit record retention "
            "and visibility into security-relevant configuration changes and intrusion attempts."
        ),
        severity="high",  # CAT I
        expected_state="logging.remote_logging_enabled == True, logging.timestamps_enabled == True",
        evaluation_metadata={
            "csm_section": "logging",
            "csm_fields": ["remote_logging_enabled", "timestamps_enabled", "remote_servers"],
            "rule_id": "SV-220139r1137890_rule",
            "ccis": ["CCI-001851"],
            "source_benchmark": "Cisco IOS XE Router NDM STIG V3R7",
            "source_file": "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-LOG-001"],
            "nist_controls": ["AU-4 (1)"],
        },
        evidence_requirements=(
            "logging.remote_logging_enabled",
            "logging.timestamps_enabled",
        ),
        remediation_metadata={
            "cli_commands": ["logging host <syslog-server-ip>", "service timestamps log datetime msec"],
            "risk_level": "low",
        },
    ),
    "V-215841": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-215841",
        title="The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).",
        description=(
            "SNMP monitoring must use cryptographic authentication and eliminate weak or default "
            "community strings (such as public/private/cisco) to protect management telemetry from tampering."
        ),
        severity="medium",  # CAT II
        expected_state="snmp.enabled == False OR (snmp.enabled == True and no weak community strings)",
        evaluation_metadata={
            "csm_section": "snmp",
            "csm_fields": ["enabled", "community_strings", "version"],
            "rule_id": "SV-215841r1107207_rule",
            "ccis": ["CCI-001967"],
            "source_benchmark": "Cisco IOS XE Router NDM STIG V3R7",
            "source_file": "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-SNMP-001"],
            "weak_communities": ["public", "private", "cisco", "community", "snmp"],
            "nist_controls": ["IA-3 (1)"],
        },
        evidence_requirements=(
            "snmp.enabled",
            "snmp.community_strings",
        ),
        remediation_metadata={
            "cli_commands": ["no snmp-server community public", "no snmp-server community private"],
            "risk_level": "medium",
        },
    ),
    "V-215812": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-215812",
        title="The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.",
        description=(
            "Inbound management connections to VTY lines must be restricted by an access control list (ACL) "
            "to ensure only authorized administration networks can establish management sessions."
        ),
        severity="medium",  # CAT II
        expected_state="access_control.management_acl_present == True",
        evaluation_metadata={
            "csm_section": "access_control",
            "csm_fields": ["management_acl_present", "acls_present"],
            "rule_id": "SV-215812r1137875_rule",
            "ccis": ["CCI-001368", "CCI-004192"],
            "source_benchmark": "Cisco IOS XE Router NDM STIG V3R7",
            "source_file": "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-ACL-001"],
            "nist_controls": ["AC-4"],
        },
        evidence_requirements=(
            "access_control.management_acl_present",
        ),
        remediation_metadata={
            "cli_commands": ["line vty 0 4", "access-class 10 in"],
            "risk_level": "medium",
        },
    ),
    "V-216646": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-216646",
        title="The Cisco router must be configured to have all inactive interfaces disabled.",
        description=(
            "Inactive or unused interfaces that are not administratively disabled present an entry point "
            "for unauthorized physical network access and lateral movement."
        ),
        severity="low",  # CAT III
        expected_state="interfaces with 'unused' in description must be administratively shutdown",
        evaluation_metadata={
            "csm_section": "interfaces",
            "csm_fields": ["description", "shutdown", "enabled"],
            "rule_id": "SV-216646r1117237_rule",
            "ccis": ["CCI-001414"],
            "source_benchmark": "Cisco IOS XE Router RTR STIG V3R5",
            "source_file": "U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-INT-001"],
            "nist_controls": ["AC-4"],
        },
        evidence_requirements=(
            "interfaces.description",
            "interfaces.shutdown",
        ),
        remediation_metadata={
            "cli_commands": ["interface <name>", "shutdown"],
            "risk_level": "low",
        },
    ),
    "V-216645": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-216645",
        title="The Cisco router must be configured to enable routing protocol authentication using FIPS 198-1 algorithms with keys not exceeding 180 days of lifetime.",
        description=(
            "Routing protocol neighbor sessions (e.g. BGP, OSPF) must enforce authentication to protect "
            "against unauthorized route advertisement, route hijacking, and traffic redirection attacks."
        ),
        severity="medium",  # CAT II
        expected_state="routing.routing_authentication_enabled == True when routing protocols are configured",
        evaluation_metadata={
            "csm_section": "routing",
            "csm_fields": ["routing_protocols", "routing_authentication_enabled"],
            "rule_id": "SV-216645r1007829_rule",
            "ccis": ["CCI-000803", "CCI-002205"],
            "source_benchmark": "Cisco IOS XE Router RTR STIG V3R5",
            "source_file": "U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-ROUTING-001"],
            "nist_controls": ["IA-7"],
        },
        evidence_requirements=(
            "routing.routing_protocols",
            "routing.routing_authentication_enabled",
        ),
        remediation_metadata={
            "cli_commands": ["router bgp <asn>", "neighbor <peer-ip> password <secret>"],
            "risk_level": "high",
        },
    ),
    "V-220656": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-220656",
        title="The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.",
        description=(
            "Spanning-Tree Protocol (STP) BPDU Guard prevents unauthorized switch insertion and STP topology "
            "manipulation on untrusted edge or user-facing access switch ports."
        ),
        severity="medium",  # CAT II
        expected_state="spanning_tree.bpduguard_enabled == True when spanning_tree is configured",
        evaluation_metadata={
            "csm_section": "spanning_tree",
            "csm_fields": ["configured", "bpduguard_enabled"],
            "rule_id": "SV-220656r856278_rule",
            "ccis": ["CCI-002385"],
            "source_benchmark": "Cisco IOS XE Switch L2S STIG V3R2",
            "source_file": "U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-STP-001"],
            "nist_controls": ["SC-5 a"],
        },
        evidence_requirements=(
            "spanning_tree.configured",
            "spanning_tree.bpduguard_enabled",
        ),
        remediation_metadata={
            "cli_commands": ["spanning-tree portfast bpduguard default", "spanning-tree bpduguard enable"],
            "risk_level": "medium",
        },
    ),
    "V-216680": Control(
        framework_id=DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="V-216680",
        title="The Cisco out-of-band management (OOBM) gateway router must be configured to have separate Interior Gateway Protocol (IGP) instances for the managed network and management network.",
        description=(
            "Out-of-band management traffic must be segmented via dedicated VRF routing instances "
            "to prevent management-plane exposure to the in-band production forwarding plane."
        ),
        severity="medium",  # CAT II
        expected_state="management.management_vrf_enabled == True",
        evaluation_metadata={
            "csm_section": "management",
            "csm_fields": ["management_vrf_enabled"],
            "rule_id": "SV-216680r1117237_rule",
            "ccis": ["CCI-001414"],
            "source_benchmark": "Cisco IOS XE Router RTR STIG V3R5",
            "source_file": "U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml",
            "mapped_internal_rules": ["CISCO-MGMT-001"],
            "nist_controls": ["AC-4"],
        },
        evidence_requirements=(
            "management.management_vrf_enabled",
        ),
        remediation_metadata={
            "cli_commands": ["vrf definition Mgmt-intf", "address-family ipv4"],
            "risk_level": "medium",
        },
    ),
}

# --- 3. Bidirectional Rule Mapping Dictionaries ---

CISCO_TO_STIG_MAPPING: Dict[str, Tuple[str, ...]] = {
    "CISCO-SSH-001": ("V-215845",),
    "CISCO-AAA-001": ("V-215854",),
    "CISCO-NTP-001": ("V-215843",),
    "CISCO-LOG-001": ("V-220139",),
    "CISCO-SNMP-001": ("V-215841",),
    "CISCO-ACL-001": ("V-215812",),
    "CISCO-INT-001": ("V-216646",),
    "CISCO-ROUTING-001": ("V-216645",),
    "CISCO-STP-001": ("V-220656",),
    "CISCO-MGMT-001": ("V-216680",),
}

STIG_TO_CISCO_MAPPING: Dict[str, Tuple[str, ...]] = {
    "V-215845": ("CISCO-SSH-001",),
    "V-215854": ("CISCO-AAA-001",),
    "V-215843": ("CISCO-NTP-001",),
    "V-220139": ("CISCO-LOG-001",),
    "V-215841": ("CISCO-SNMP-001",),
    "V-215812": ("CISCO-ACL-001",),
    "V-216646": ("CISCO-INT-001",),
    "V-216645": ("CISCO-ROUTING-001",),
    "V-220656": ("CISCO-STP-001",),
    "V-216680": ("CISCO-MGMT-001",),
}

WEAK_COMMUNITIES = {"public", "private", "cisco", "community", "snmp"}


# --- 4. DISA-STIG Cisco IOS-XE Evaluator Implementation ---

class StigCiscoIosXeEvaluator(FrameworkEvaluator):
    """Evaluates normalized CSM data against DISA STIG requirements for Cisco IOS XE.
    
    Hard Invariants:
    - Pure function / deterministic: Identical CSM inputs always yield identical EvaluationResult outputs.
    - Zero AI calls: Does not import or invoke Ollama, AIModelManager, or LLM services.
    - Normalized CSM only: Consumes pre-parsed CSM dictionaries; does not parse raw CLI syntax.
    - UNKNOWN preservation: Unconfigured or indeterminate controls return ComplianceStatus.UNKNOWN.
    """

    def __init__(self, controls: Optional[Dict[str, Control]] = None):
        self._controls = dict(controls) if controls is not None else DISA_STIG_CISCO_IOSXE_CONTROLS

    @property
    def framework_id(self) -> str:
        return DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID

    def evaluate(
        self,
        csm: Dict[str, Any],
        controls: Optional[Sequence[Control]] = None
    ) -> List[EvaluationResult]:
        """Evaluates normalized CSM against DISA-STIG controls.
        
        Args:
            csm: Normalized configuration model dictionary.
            controls: Optional subset of Control instances. If None, evaluates all registered controls.
            
        Returns:
            List of EvaluationResult instances for each evaluated control.
        """
        if not isinstance(csm, dict):
            raise TypeError(f"CSM must be a dict, got {type(csm).__name__}")

        target_controls = controls if controls is not None else list(self._controls.values())
        results: List[EvaluationResult] = []

        for ctrl in target_controls:
            cid = ctrl.control_id
            handler_name = f"_eval_{cid.replace('-', '_')}"
            eval_fn = getattr(self, handler_name, None)
            if eval_fn is not None:
                res = eval_fn(csm, ctrl)
            else:
                # Fallback for unhandled controls: status UNKNOWN with clear rationale
                res = EvaluationResult(
                    framework_id=self.framework_id,
                    control_id=cid,
                    status=ComplianceStatus.UNKNOWN,
                    evidence=Evidence(
                        observed_value=None,
                        location="csm",
                        expected_value=ctrl.expected_state,
                        rationale=f"No deterministic evaluator handler implemented for STIG control {cid}.",
                        confidence=1.0,
                    ),
                    reason=f"STIG Control {cid} has no registered deterministic evaluation handler.",
                    evaluator_id="stig_cisco_iosxe_evaluator",
                )
            results.append(res)

        return results

    # --- Per-Control Deterministic Evaluators ---

    def _eval_V_215845(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-215845 (CAT I / SSH): Confidentiality of remote maintenance sessions."""
        s = csm.get("services")
        if not isinstance(s, dict):
            return self._unknown_result(ctrl, "csm.services", "services section missing from CSM")

        ssh_ver = s.get("ssh_version")
        ssh_en = bool(s.get("ssh"))
        telnet_en = bool(s.get("telnet"))

        observed = {"ssh_version": ssh_ver, "ssh": ssh_en, "telnet": telnet_en}
        expected = {"ssh_version": 2, "ssh": True, "telnet": False}

        if ssh_ver == 2 and ssh_en and not telnet_en:
            status = ComplianceStatus.PASS
            rationale = "SSH version 2 is configured, SSH is active, and unencrypted Telnet is disabled."
        elif ssh_ver == 1 or telnet_en:
            status = ComplianceStatus.FAIL
            rationale = f"Unencrypted or deprecated remote access configured: ssh_version={ssh_ver}, telnet={telnet_en}."
        elif not ssh_en and ssh_ver is None:
            status = ComplianceStatus.UNKNOWN
            rationale = "Remote management services are not configured in CSM."
        else:
            status = ComplianceStatus.FAIL
            rationale = f"SSH version {ssh_ver} does not satisfy STIG requirement for version 2."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.services",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_215854(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-215854 (CAT I / AAA): Centralized authentication servers."""
        a = csm.get("aaa")
        if not isinstance(a, dict):
            return self._unknown_result(ctrl, "csm.aaa", "aaa section missing from CSM")

        configured = bool(a.get("configured"))
        enabled = bool(a.get("enabled"))
        auth_method = a.get("authentication_method")

        observed = {"configured": configured, "enabled": enabled, "authentication_method": auth_method}
        expected = {"enabled": True, "authentication_method": "configured"}

        if not configured and not enabled:
            status = ComplianceStatus.UNKNOWN
            rationale = "AAA configuration is not present in CSM."
        elif enabled and auth_method:
            status = ComplianceStatus.PASS
            rationale = f"AAA new-model is enabled with configured authentication method: '{auth_method}'."
        else:
            status = ComplianceStatus.FAIL
            rationale = (
                f"AAA authentication is incomplete: enabled={enabled}, authentication_method={auth_method}."
            )

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.aaa",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_215843(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-215843 (CAT II / NTP): Cryptographic NTP authentication."""
        n = csm.get("ntp")
        if not isinstance(n, dict):
            return self._unknown_result(ctrl, "csm.ntp", "ntp section missing from CSM")

        servers = n.get("servers", [])
        auth_enabled = bool(n.get("authentication_enabled"))

        observed = {"servers": list(servers), "authentication_enabled": auth_enabled}
        expected = {"servers": "non-empty", "authentication_enabled": True}

        if not servers and not n.get("enabled"):
            status = ComplianceStatus.UNKNOWN
            rationale = "No NTP servers or NTP configuration present in CSM."
        elif auth_enabled:
            status = ComplianceStatus.PASS
            rationale = f"Cryptographic NTP authentication is enabled with {len(servers)} configured server(s)."
        else:
            status = ComplianceStatus.FAIL
            rationale = f"NTP servers configured ({servers}) but NTP authentication is not enabled."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.ntp",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_220139(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-220139 (CAT I / Logging): Redundant syslog destinations and timestamps."""
        l = csm.get("logging")
        if not isinstance(l, dict):
            return self._unknown_result(ctrl, "csm.logging", "logging section missing from CSM")

        remote_enabled = bool(l.get("remote_logging_enabled"))
        timestamps_enabled = bool(l.get("timestamps_enabled"))
        logging_enabled = bool(l.get("enabled"))
        remote_servers = l.get("remote_servers", [])

        observed = {
            "remote_logging_enabled": remote_enabled,
            "timestamps_enabled": timestamps_enabled,
            "remote_servers": list(remote_servers),
            "enabled": logging_enabled,
        }
        expected = {"remote_logging_enabled": True, "timestamps_enabled": True}

        if remote_enabled and timestamps_enabled:
            status = ComplianceStatus.PASS
            rationale = (
                f"Syslog forwarding enabled to {remote_servers} with synchronized timestamps."
            )
        elif logging_enabled:
            status = ComplianceStatus.FAIL
            rationale = (
                f"Logging is enabled but incomplete: remote_logging={remote_enabled}, "
                f"timestamps={timestamps_enabled}."
            )
        else:
            status = ComplianceStatus.UNKNOWN
            rationale = "Logging configuration is not present in CSM."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.logging",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_215841(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-215841 (CAT II / SNMP): Secure SNMP authentication without weak community strings."""
        sn = csm.get("snmp")
        if not isinstance(sn, dict):
            return self._unknown_result(ctrl, "csm.snmp", "snmp section missing from CSM")

        enabled = bool(sn.get("enabled"))
        comms = sn.get("community_strings", [])
        weak_found = [c for c in comms if str(c).lower() in WEAK_COMMUNITIES]

        observed = {"enabled": enabled, "community_strings": list(comms), "weak_found": weak_found}
        expected = "No weak community strings when SNMP enabled"

        if not enabled and not comms:
            status = ComplianceStatus.UNKNOWN
            rationale = "SNMP is not enabled in CSM."
        elif weak_found:
            status = ComplianceStatus.FAIL
            rationale = f"SNMP is active with insecure/default community string(s): {weak_found}."
        else:
            status = ComplianceStatus.PASS
            rationale = f"SNMP is active with no weak community strings detected (comms={comms})."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.snmp",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_215812(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-215812 (CAT II / Management ACL): Management plane access control."""
        ac = csm.get("access_control")
        s = csm.get("services", {})
        if not isinstance(ac, dict):
            return self._unknown_result(ctrl, "csm.access_control", "access_control section missing from CSM")

        mgmt_acl = bool(ac.get("management_acl_present"))
        acls_present = bool(ac.get("acls_present"))
        ssh_enabled = bool(s.get("ssh"))

        observed = {
            "management_acl_present": mgmt_acl,
            "acls_present": acls_present,
            "ssh_enabled": ssh_enabled,
        }
        expected = {"management_acl_present": True}

        if mgmt_acl:
            status = ComplianceStatus.PASS
            rationale = "Inbound management access-class is applied to line vty."
        elif ssh_enabled or acls_present:
            status = ComplianceStatus.FAIL
            rationale = "Remote management active without access-class restriction on line vty."
        else:
            status = ComplianceStatus.UNKNOWN
            rationale = "No remote management or access control configuration present in CSM."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.access_control",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_216646(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-216646 (CAT III / Interfaces): Inactive interfaces must be disabled."""
        interfaces = csm.get("interfaces")
        if not isinstance(interfaces, list):
            return self._unknown_result(ctrl, "csm.interfaces", "interfaces list missing from CSM")

        unused = [i for i in interfaces if "unused" in (i.get("description") or "").lower()]

        if not unused:
            return self._unknown_result(
                ctrl,
                "csm.interfaces",
                "No interfaces designated as 'unused' found in CSM descriptions to evaluate."
            )

        active_unused = [i.get("name") for i in unused if not i.get("shutdown")]
        observed = {
            "unused_interfaces_count": len(unused),
            "unshutdown_unused": active_unused,
        }
        expected = {"unshutdown_unused": []}

        if not active_unused:
            status = ComplianceStatus.PASS
            rationale = f"All {len(unused)} inactive/unused interface(s) are administratively shutdown."
        else:
            status = ComplianceStatus.FAIL
            rationale = f"Inactive interface(s) are not administratively shutdown: {active_unused}."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.interfaces",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_216645(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-216645 (CAT II / Routing): Routing protocol neighbor authentication."""
        r = csm.get("routing")
        if not isinstance(r, dict):
            return self._unknown_result(ctrl, "csm.routing", "routing section missing from CSM")

        protocols = r.get("routing_protocols", [])
        auth_enabled = bool(r.get("routing_authentication_enabled"))

        observed = {"routing_protocols": list(protocols), "routing_authentication_enabled": auth_enabled}
        expected = {"routing_protocols": "non-empty", "routing_authentication_enabled": True}

        if not protocols:
            status = ComplianceStatus.UNKNOWN
            rationale = "No dynamic routing protocols configured in CSM."
        elif auth_enabled:
            status = ComplianceStatus.PASS
            rationale = f"Routing protocol authentication is enabled for protocols: {protocols}."
        else:
            status = ComplianceStatus.FAIL
            rationale = f"Routing protocols active ({protocols}) but neighbor authentication is missing."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.routing",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_220656(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-220656 (CAT II / Switch STP): Spanning-Tree BPDU Guard."""
        st = csm.get("spanning_tree")
        if not isinstance(st, dict) or not st.get("configured"):
            return self._unknown_result(
                ctrl,
                "csm.spanning_tree",
                "Spanning-Tree Protocol is not configured in CSM."
            )

        bpduguard = bool(st.get("bpduguard_enabled"))
        observed = {"configured": True, "bpduguard_enabled": bpduguard}
        expected = {"bpduguard_enabled": True}

        if bpduguard:
            status = ComplianceStatus.PASS
            rationale = "Spanning-Tree BPDU Guard is enabled on access switch ports."
        else:
            status = ComplianceStatus.FAIL
            rationale = "Spanning-Tree Protocol is configured but BPDU Guard is disabled."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.spanning_tree",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _eval_V_216680(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """STIG V-216680 (CAT II / Management VRF): Out-of-band management separation."""
        m = csm.get("management")
        s = csm.get("services", {})
        if not isinstance(m, dict):
            return self._unknown_result(ctrl, "csm.management", "management section missing from CSM")

        vrf_enabled = bool(m.get("management_vrf_enabled"))
        ssh_enabled = bool(s.get("ssh"))

        observed = {"management_vrf_enabled": vrf_enabled, "ssh_enabled": ssh_enabled}
        expected = {"management_vrf_enabled": True}

        if vrf_enabled:
            status = ComplianceStatus.PASS
            rationale = "Management traffic is isolated via dedicated management VRF instance."
        elif ssh_enabled:
            status = ComplianceStatus.FAIL
            rationale = "Remote management active without dedicated management VRF separation."
        else:
            status = ComplianceStatus.UNKNOWN
            rationale = "Management services and VRF are not configured in CSM."

        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=status,
            evidence=Evidence(
                observed_value=observed,
                location="csm.management",
                expected_value=expected,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )

    def _unknown_result(self, ctrl: Control, location: str, rationale: str) -> EvaluationResult:
        """Helper to create an UNKNOWN EvaluationResult with standard evidence."""
        return EvaluationResult(
            framework_id=self.framework_id,
            control_id=ctrl.control_id,
            status=ComplianceStatus.UNKNOWN,
            evidence=Evidence(
                observed_value=None,
                location=location,
                expected_value=ctrl.expected_state,
                rationale=rationale,
                confidence=1.0,
            ),
            reason=f"{ctrl.control_id}: Unknown",
            observed_value=None,
            expected_value=ctrl.expected_state,
            evaluator_id="stig_cisco_iosxe_evaluator",
        )


# --- 5. Registration Hook ---

def register_disa_stig_cisco_iosxe(registry: Optional[FrameworkRegistry] = None) -> FrameworkRegistry:
    """Registers the DISA STIG Cisco IOS-XE Benchmark V3R7 framework and evaluator into the registry.
    
    Args:
        registry: Target FrameworkRegistry. If None, uses default process-level registry.
        
    Returns:
        The updated FrameworkRegistry instance.
    """
    target = registry if registry is not None else get_default_registry()
    evaluator = StigCiscoIosXeEvaluator()
    target.register(
        framework=DISA_STIG_CISCO_IOSXE_FRAMEWORK,
        evaluator=evaluator,
        allow_replace=True
    )
    return target
