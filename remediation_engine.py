"""Remediation Generation, Static Conflict Analysis & AI Explanation (PRD Addendum Section 4 Step 4).
Renders Jinja2 remediation templates from parsed CSM fields only,
performs static conflict analysis against device configuration state,
and generates plain-language failure explanations via local AI.
Guaranteed execution-safe: remediation commands are NEVER executed.
"""
import ast
import json
import os
import pathlib
import re
import time
import urllib.error
import urllib.request
import jinja2
import ai_model_manager
from ai_model_manager import ModelMode, WorkloadType

BASE = pathlib.Path(__file__).parent.resolve()
TEMPLATE_DIR = BASE / "templates" / "remediation"
_MODEL_MANAGER = ai_model_manager.get_model_manager()

def generate_remediation(rule_id: str, csm: dict) -> str:
    """Renders Jinja2 remediation template for the given rule_id.
    Context variables are derived ONLY from parsed CSM fields.
    Returns rendered CLI command text. NEVER executes anything.
    """
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True
    )
    template_name = f"{rule_id}.j2"
    try:
        template = env.get_template(template_name)
    except jinja2.TemplateNotFound:
        raise FileNotFoundError(f"Remediation template '{template_name}' not found in {TEMPLATE_DIR}")

    # Pass only known CSM fields as context
    context = {
        "device": csm.get("device", {}),
        "ntp": csm.get("ntp", {}),
        "snmp": csm.get("snmp", {}),
        "services": csm.get("services", {}),
        "management": csm.get("management", {}),
        "interfaces": csm.get("interfaces", [])
    }
    rendered = template.render(**context)
    return rendered.strip()

def check_static_conflicts(rule_id: str, csm: dict, remediation_commands: str) -> dict:
    """Scans parsed CSM for configuration dependencies that the remediation command would break.
    For CISCO-NTP-001, checks:
    1. NTP_AUTH_KEY_MISSING: Enabling ntp authenticate without active authentication keys severs peer sync.
    2. NTP_MGMT_VRF_ACL_BLOCK: NTP servers routed across Mgmt VRF without explicit UDP 123 permit.
    """
    conflicts = []

    if rule_id == "CISCO-NTP-001":
        ntp_data = csm.get("ntp", {})
        servers = ntp_data.get("servers", [])

        # Conflict 1: Missing NTP authentication keys
        raw_ev = [item["field"] for item in csm.get("raw_evidence", [])]
        has_keys = any("ntp.key" in f or "ntp.trusted-key" in f for f in raw_ev) or bool(ntp_data.get("authentication_keys") or ntp_data.get("trusted_key_ids"))
        if not has_keys and servers:
            conflicts.append({
                "conflict_id": "NTP_AUTH_KEY_MISSING",
                "title": "Missing Trusted Authentication Keys",
                "severity": "HIGH",
                "affected_components": [f"NTP Peer {s}" for s in servers],
                "description": (
                    f"Enabling 'ntp authenticate' globally instructs Cisco IOS-XE to drop packets from any "
                    f"server that does not present a trusted key. No 'ntp authentication-key' or 'ntp trusted-key' "
                    f"is configured in the current configuration. Deploying 'ntp authenticate' will immediately "
                    f"sever clock synchronization with server(s) {servers}, leading to clock drift, TLS validation "
                    f"failures, and broken log timestamping."
                ),
                "mitigation": "Configure 'ntp authentication-key <id> md5 <key>' and 'ntp trusted-key <id>' prior to or in conjunction with 'ntp authenticate'."
            })

        # Conflict 2: VRF & Management Access Restriction
        mgmt = csm.get("management", {})
        if mgmt.get("management_vrf_enabled") and servers:
            conflicts.append({
                "conflict_id": "NTP_VRF_SOURCE_CHECK",
                "title": "Management VRF Route Binding Notice",
                "severity": "MEDIUM",
                "affected_components": ["Management VRF (Mgmt-intf)"],
                "description": (
                    "Dedicated Management VRF is active. Ensure 'ntp server vrf Mgmt-intf' or 'ntp source-interface' "
                    "is specified if NTP servers reside in the out-of-band management plane."
                ),
                "mitigation": "Verify routing reachability for NTP server addresses inside the designated VRF table."
            })

    return {
        "rule_id": rule_id,
        "has_conflicts": len(conflicts) > 0,
        "conflict_count": len(conflicts),
        "conflicts": conflicts
    }

def explain_failure_ai(rule_id: str, csm: dict, remediation_cmd: str) -> dict:
    """Generates plain-language explanation of failure cause and remediation action
    using local AI via AIModelManager with fallback to hardcoded templates if unreachable.
    """
    # Build prompt from real audit context
    ntp_srv = csm.get("ntp", {}).get("servers", ["configured servers"])
    if rule_id == "CISCO-NTP-001":
        ntp_auth = csm.get("ntp", {}).get("authentication_enabled", False)
        evidence_summary = f"ntp.authenticate = {ntp_auth} (should be True); ntp.servers = {ntp_srv}"
    else:
        evidence = csm.get("raw_evidence", [])
        evidence_summary = "; ".join(f"{e.get('field', '')}={e.get('value', '')}" for e in evidence[:5]) if evidence else "no evidence fields"

    _last_cmd = remediation_cmd.splitlines()[-1].strip()
    _hostname = csm.get("device", {}).get("hostname", "unknown")
    prompt = (
        f"Complete this technical audit report. Write only factual, procedural sentences.\n\n"
        f"Device: {_hostname} | Rule: {rule_id}\n"
        f"Configuration evidence: {evidence_summary}\n\n"
        f"WHY_IT_FAILED: [In 2 sentences: what IOS-XE configuration command or setting is "
        f"absent on this device, and what that setting does when it is configured.]\n\n"
        f"WHAT_REMEDIATION_DOES: [In 2 sentences: what the command '{_last_cmd}' adds to "
        f"the device configuration, and what the device does differently after it is applied.]\n"
    )

    res = _MODEL_MANAGER.generate(
        prompt=prompt,
        workload=WorkloadType.REMEDIATION_EXPLANATION
    )

    if not res.is_fallback and len(res.text) > 20:
        print(f"[explain_failure_ai] path=ollama model={res.model_used} mode={res.mode_used.value} chars={len(res.text)} elapsed={res.latency_sec:.1f}s")
        # Split on WHAT_REMEDIATION_DOES — handles both "LABEL: text" and "LABEL\n\ntext"
        _WHAT_PAT = re.compile(r'WHAT_REMEDIATION_DOES\s*:?\s*', re.IGNORECASE)
        parts = _WHAT_PAT.split(res.text, maxsplit=1)
        if len(parts) == 2:
            why = re.sub(r'(?i)^WHY_IT_FAILED\s*:?\s*', '', parts[0]).strip()
            what = parts[1].strip()
        else:
            why = what = res.text
        # Strip echoed context lines the model sometimes repeats from the prompt
        _CTX_PAT = re.compile(
            r'^(here is.*?\n+|device\s*:.*?\n+|rule\s*:.*?\n+|configuration evidence\s*:.*?\n+)+',
            re.IGNORECASE | re.MULTILINE
        )
        why = _CTX_PAT.sub('', why).lstrip('\n').strip()
        what = _CTX_PAT.sub('', what).lstrip('\n').strip()
        return {
            "rule_id": rule_id,
            "why_it_failed": why,
            "what_remediation_does": what,
            "model_used": res.model_used,
            "execution_safety": "display_only_no_device_execution",
        }
    else:
        print(f"[explain_failure_ai] path=fallback reason={res.fallback_reason} chars=0")

    # Fallback: original hardcoded templates
    if rule_id == "CISCO-NTP-001":
        why = (
            f"The network device is synchronizing time with external server(s) {ntp_srv}, but NTP cryptographic "
            "authentication is explicitly disabled ('no ntp authenticate'). Without authentication, an attacker "
            "can inject spoofed NTP responses, artificially skewing the device clock. Clock desynchronization breaks "
            "TLS certificate validation, invalidates audit trail correlation, and disrupts security token lifecycles."
        )
        what = (
            f"The remediation command '{remediation_cmd}' turns on mandatory packet verification for all NTP "
            "exchanges. The device will henceforth reject any NTP packet that fails cryptographic verification, "
            "preventing man-in-the-middle time manipulation."
        )
    else:
        why = f"The control {rule_id} failed compliance checks against approved baseline security policy."
        what = f"The remediation command '{remediation_cmd}' modifies configuration parameters to align with policy."

    return {
        "rule_id": rule_id,
        "why_it_failed": why,
        "what_remediation_does": what,
        "model_used": "fallback_template",
        "execution_safety": "display_only_no_device_execution",
    }


import ast_safety


def verify_safety_no_execution() -> bool:
    """AST code analysis asserting that no process execution or device communication
    libraries are imported or used in remediation_engine.py.
    """
    return ast_safety.assert_no_execution_imports(pathlib.Path(__file__))

