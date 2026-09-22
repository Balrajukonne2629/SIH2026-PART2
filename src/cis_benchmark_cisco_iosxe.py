"""NTRO PS26155 — CIS Benchmark Cisco IOS-XE Deterministic Control Catalog (Phase 3A.2).

Authoritative source:
CIS Cisco IOS XE 17.x Benchmark v2.2.1
(01_Compliance_Standards/CIS/CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf)

Implements:
1. CIS_CISCO_IOSXE_FRAMEWORK: Concrete Framework metadata instance (v2.2.1).
2. CIS_CISCO_IOSXE_CONTROLS: Dict of verified Control instances keyed by CIS section ID.
3. CISCO_TO_CIS_MAPPING: Bidirectional mapping between internal CISCO-* rules and CIS controls.
4. CisCiscoIosXeEvaluator: Deterministic FrameworkEvaluator implementation consuming normalized CSM.
5. register_cis_cisco_iosxe: Registration hook for FrameworkRegistry.

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

CIS_CISCO_IOSXE_FRAMEWORK_ID = "cis-cisco-iosxe"

CIS_CISCO_IOSXE_FRAMEWORK = Framework(
    framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
    name="CIS Cisco IOS XE 17.x Benchmark",
    version="v2.2.1",
    description=(
        "Center for Internet Security (CIS) Benchmark for Cisco IOS XE 17.x "
        "providing prescriptive guidance for establishing a secure configuration posture."
    ),
    vendor_scope="Cisco IOS-XE",
    control_namespace="CIS",
    enabled=True,
)

# --- 2. CIS Control Catalog (Strict Provenance from Benchmark v2.2.1) ---

CIS_CISCO_IOSXE_CONTROLS: Dict[str, Control] = {
    "2.1.1.2": Control(
        framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="2.1.1.2",
        title="Set version 2 for 'ip ssh version'",
        description=(
            "Configure SSH version 2 to ensure secure remote management encryption "
            "and disable insecure legacy SSH version 1 and unencrypted Telnet."
        ),
        severity="high",
        expected_state="services.ssh_version == 2, services.ssh == True, services.telnet == False",
        evaluation_metadata={
            "csm_section": "services",
            "csm_fields": ["ssh_version", "ssh", "telnet"],
            "source_ref": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §2.1.1.2",
            "mapped_internal_rules": ["CISCO-SSH-001"],
            "remediation_command": "ip ssh version 2\nline vty 0 4\n transport input ssh",
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
    "1.1.1": Control(
        framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="1.1.1",
        title="Enable 'aaa new-model'",
        description=(
            "Enable AAA new-model to activate modern authentication, authorization, "
            "and accounting features and configure an approved authentication method."
        ),
        severity="high",
        expected_state="aaa.enabled == True, aaa.authentication_method != None",
        evaluation_metadata={
            "csm_section": "aaa",
            "csm_fields": ["enabled", "authentication_method", "configured"],
            "source_ref": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §1.1.1",
            "mapped_internal_rules": ["CISCO-AAA-001"],
            "remediation_command": "aaa new-model\naaa authentication login default group radius local",
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
    "2.3.1.1": Control(
        framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="2.3.1.1",
        title="Set 'ntp authenticate'",
        description=(
            "Ensure NTP authentication is enabled when NTP servers are configured "
            "to prevent time-synchronization spoofing and manipulation."
        ),
        severity="medium",
        expected_state="ntp.authentication_enabled == True when ntp.servers configured",
        evaluation_metadata={
            "csm_section": "ntp",
            "csm_fields": ["servers", "authentication_enabled", "enabled"],
            "source_ref": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §2.3.1.1",
            "mapped_internal_rules": ["CISCO-NTP-001"],
            "remediation_command": "ntp authenticate",
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
    "2.2.4": Control(
        framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="2.2.4",
        title="Set IP address for 'logging host'",
        description=(
            "Configure a remote syslog logging host and enable timestamps on log messages "
            "for centralized security monitoring and reliable log correlation."
        ),
        severity="medium",
        expected_state="logging.remote_logging_enabled == True, logging.timestamps_enabled == True",
        evaluation_metadata={
            "csm_section": "logging",
            "csm_fields": ["remote_logging_enabled", "timestamps_enabled", "remote_servers"],
            "source_ref": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §2.2.4",
            "mapped_internal_rules": ["CISCO-LOG-001"],
            "remediation_command": "logging host <syslog-ip>\nservice timestamps log datetime msec",
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
    "1.5.7": Control(
        framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="1.5.7",
        title="Set 'snmp-server host' when using SNMP",
        description=(
            "When SNMP is enabled, restrict access to authorized management hosts "
            "and eliminate weak or default community strings (such as public/private/cisco)."
        ),
        severity="medium",
        expected_state="snmp.enabled == False OR (snmp.enabled == True and no weak community strings)",
        evaluation_metadata={
            "csm_section": "snmp",
            "csm_fields": ["enabled", "community_strings", "version"],
            "source_ref": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §1.5.7",
            "mapped_internal_rules": ["CISCO-SNMP-001"],
            "weak_communities": ["public", "private", "cisco", "community", "snmp"],
            "remediation_command": "no snmp-server community <weak-string>\nsnmp-server host <mgmt-ip> ...",
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
    "1.2.5": Control(
        framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="1.2.5",
        title="Set 'access-class' for 'line vty'",
        description=(
            "Restrict access to terminal lines (VTY) by applying an access-class (management ACL) "
            "limiting remote administration to authorized source subnets."
        ),
        severity="high",
        expected_state="access_control.management_acl_present == True",
        evaluation_metadata={
            "csm_section": "access_control",
            "csm_fields": ["management_acl_present", "acls_present"],
            "source_ref": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §1.2.5",
            "mapped_internal_rules": ["CISCO-ACL-001", "CISCO-MGMT-001"],
            "remediation_command": "line vty 0 4\n access-class 10 in",
        },
        evidence_requirements=(
            "access_control.management_acl_present",
        ),
        remediation_metadata={
            "cli_commands": ["line vty 0 4", "access-class 10 in"],
            "risk_level": "medium",
        },
    ),
    "3.3.3.1": Control(
        framework_id=CIS_CISCO_IOSXE_FRAMEWORK_ID,
        control_id="3.3.3.1",
        title="Set 'neighbor password'",
        description=(
            "Configure neighbor authentication for dynamic routing protocols (e.g., BGP neighbor password) "
            "to prevent unauthorized route injection and session hijacking."
        ),
        severity="high",
        expected_state="routing.routing_authentication_enabled == True when routing protocols are configured",
        evaluation_metadata={
            "csm_section": "routing",
            "csm_fields": ["routing_protocols", "routing_authentication_enabled"],
            "source_ref": "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf §3.3.3.1",
            "mapped_internal_rules": ["CISCO-ROUTING-001"],
            "remediation_command": "router bgp <asn>\n neighbor <peer-ip> password <secret>",
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
}

# --- 3. Internal Rule to CIS Control Mapping Dictionary ---

CISCO_TO_CIS_MAPPING: Dict[str, Tuple[str, ...]] = {
    "CISCO-SSH-001": ("2.1.1.2",),
    "CISCO-AAA-001": ("1.1.1",),
    "CISCO-NTP-001": ("2.3.1.1",),
    "CISCO-LOG-001": ("2.2.4",),
    "CISCO-SNMP-001": ("1.5.7",),
    "CISCO-ACL-001": ("1.2.5",),
    "CISCO-ROUTING-001": ("3.3.3.1",),
    "CISCO-MGMT-001": ("1.2.5",),  # Secondary CIS mapping for management restriction
    # Note: CISCO-INT-001 and CISCO-STP-001 are explicitly unmapped in CIS 17.x Benchmark
    # per mapping_log.md and vendor_rule_mapping.json (they map to DISA-STIG).
}

CIS_TO_CISCO_MAPPING: Dict[str, Tuple[str, ...]] = {
    "2.1.1.2": ("CISCO-SSH-001",),
    "1.1.1": ("CISCO-AAA-001",),
    "2.3.1.1": ("CISCO-NTP-001",),
    "2.2.4": ("CISCO-LOG-001",),
    "1.5.7": ("CISCO-SNMP-001",),
    "1.2.5": ("CISCO-ACL-001", "CISCO-MGMT-001"),
    "3.3.3.1": ("CISCO-ROUTING-001",),
}

WEAK_COMMUNITIES = {"public", "private", "cisco", "community", "snmp"}


# --- 4. CIS Cisco IOS-XE Evaluator Implementation ---

class CisCiscoIosXeEvaluator(FrameworkEvaluator):
    """Evaluates normalized CSM data against the CIS Cisco IOS-XE Benchmark v2.2.1.
    
    Hard Invariants:
    - Pure function / deterministic: Identical CSM inputs always yield identical EvaluationResult outputs.
    - Zero AI calls: Does not import or invoke Ollama, AIModelManager, or LLM services.
    - Normalized CSM only: Consumes pre-parsed CSM dictionaries; does not parse raw CLI syntax.
    - UNKNOWN preservation: Unconfigured or indeterminate controls return ComplianceStatus.UNKNOWN.
    """

    def __init__(self, controls: Optional[Dict[str, Control]] = None):
        self._controls = dict(controls) if controls is not None else CIS_CISCO_IOSXE_CONTROLS

    @property
    def framework_id(self) -> str:
        return CIS_CISCO_IOSXE_FRAMEWORK_ID

    def evaluate(
        self,
        csm: Dict[str, Any],
        controls: Optional[Sequence[Control]] = None
    ) -> List[EvaluationResult]:
        """Evaluates normalized CSM against CIS Cisco IOS-XE controls.
        
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
            eval_fn = getattr(self, f"_eval_{cid.replace('.', '_')}", None)
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
                        rationale=f"No deterministic evaluator handler implemented for control {cid}.",
                        confidence=1.0,
                    ),
                    reason=f"Control {cid} has no registered deterministic evaluation handler.",
                    evaluator_id="cis_cisco_iosxe_evaluator",
                )
            results.append(res)

        return results

    # --- Per-Control Deterministic Evaluators ---

    def _eval_2_1_1_2(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """CIS §2.1.1.2: Set version 2 for 'ip ssh version'."""
        s = csm.get("services")
        if not isinstance(s, dict):
            return self._unknown_result(ctrl, "csm.services", "services section missing from CSM")

        ssh_ver = s.get("ssh_version")
        ssh_en = bool(s.get("ssh"))
        telnet_en = bool(s.get("telnet"))

        observed = {"ssh_version": ssh_ver, "ssh": ssh_en, "telnet": telnet_en}
        expected = {"ssh_version": 2, "ssh": True, "telnet": False}

        # If SSH is disabled and telnet is not explicitly configured, check if unconfigured
        if ssh_ver == 2 and ssh_en and not telnet_en:
            status = ComplianceStatus.PASS
            rationale = "SSH version 2 is configured, SSH is enabled, and Telnet is disabled."
        elif ssh_ver == 1 or telnet_en:
            status = ComplianceStatus.FAIL
            rationale = f"Non-compliant SSH/Telnet settings: ssh_version={ssh_ver}, telnet={telnet_en}."
        elif not ssh_en and ssh_ver is None:
            status = ComplianceStatus.UNKNOWN
            rationale = "SSH and remote management services are not configured in CSM."
        else:
            status = ComplianceStatus.FAIL
            rationale = f"SSH version {ssh_ver} does not satisfy version 2 requirement."

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
            reason=f"{ctrl.title}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="cis_cisco_iosxe_evaluator",
        )

    def _eval_1_1_1(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """CIS §1.1.1: Enable 'aaa new-model'."""
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
            rationale = f"AAA new-model is enabled with authentication method: '{auth_method}'."
        else:
            status = ComplianceStatus.FAIL
            rationale = (
                f"AAA new-model is incomplete: enabled={enabled}, authentication_method={auth_method}."
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
            reason=f"{ctrl.title}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="cis_cisco_iosxe_evaluator",
        )

    def _eval_2_3_1_1(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """CIS §2.3.1.1: Set 'ntp authenticate'."""
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
            rationale = f"NTP authentication is enabled with {len(servers)} configured server(s)."
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
            reason=f"{ctrl.title}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="cis_cisco_iosxe_evaluator",
        )

    def _eval_2_2_4(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """CIS §2.2.4: Set IP address for 'logging host'."""
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
                f"Remote logging is enabled to {remote_servers} and timestamps are enabled."
            )
        elif logging_enabled:
            status = ComplianceStatus.FAIL
            rationale = (
                f"Logging is configured but incomplete: remote_logging={remote_enabled}, "
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
            reason=f"{ctrl.title}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="cis_cisco_iosxe_evaluator",
        )

    def _eval_1_5_7(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """CIS §1.5.7: Set 'snmp-server host' when using SNMP."""
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
            rationale = f"SNMP is enabled with insecure/weak community string(s): {weak_found}."
        else:
            status = ComplianceStatus.PASS
            rationale = f"SNMP is enabled with no weak community strings detected (comms={comms})."

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
            reason=f"{ctrl.title}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="cis_cisco_iosxe_evaluator",
        )

    def _eval_1_2_5(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """CIS §1.2.5: Set 'access-class' for 'line vty'."""
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
            rationale = "Management access-class is applied to line vty."
        elif ssh_enabled or acls_present:
            status = ComplianceStatus.FAIL
            rationale = "Remote management (SSH) or ACLs exist but access-class is missing from line vty."
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
            reason=f"{ctrl.title}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="cis_cisco_iosxe_evaluator",
        )

    def _eval_3_3_3_1(self, csm: Dict[str, Any], ctrl: Control) -> EvaluationResult:
        """CIS §3.3.3.1: Set 'neighbor password'."""
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
            rationale = f"Routing protocols configured ({protocols}) but neighbor authentication is not enabled."

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
            reason=f"{ctrl.title}: {status.value}",
            observed_value=observed,
            expected_value=expected,
            evaluator_id="cis_cisco_iosxe_evaluator",
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
            reason=f"{ctrl.title}: Unknown",
            observed_value=None,
            expected_value=ctrl.expected_state,
            evaluator_id="cis_cisco_iosxe_evaluator",
        )


# --- 5. Registration Hook ---

def register_cis_cisco_iosxe(registry: Optional[FrameworkRegistry] = None) -> FrameworkRegistry:
    """Registers the CIS Cisco IOS-XE Benchmark v2.2.1 framework and evaluator into the registry.
    
    Args:
        registry: Target FrameworkRegistry. If None, uses default process-level registry.
        
    Returns:
        The updated FrameworkRegistry instance.
    """
    target = registry if registry is not None else get_default_registry()
    evaluator = CisCiscoIosXeEvaluator()
    target.register(
        framework=CIS_CISCO_IOSXE_FRAMEWORK,
        evaluator=evaluator,
        allow_replace=True
    )
    return target
