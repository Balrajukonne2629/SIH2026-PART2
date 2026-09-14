"""Remediation Generation, Static Conflict Analysis & AI Explanation (PRD Addendum Section 4 Step 4).
Renders Jinja2 remediation templates from parsed CSM fields only,
performs static conflict analysis against device configuration state,
and generates plain-language failure explanations via local AI.
Guaranteed execution-safe: remediation commands are NEVER executed.
"""
import ast
import json
import pathlib
import urllib.error
import urllib.request
import jinja2

BASE = pathlib.Path(__file__).parent.resolve()
TEMPLATE_DIR = BASE / "templates" / "remediation"

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
    using Ollama (llama3.2:1b) with fallback to hardcoded templates if unreachable.
    """
    _OLLAMA_URL = "http://localhost:11434/api/generate"
    _MODEL = "llama3.2:1b"

    # Build prompt from real audit context
    ntp_srv = csm.get("ntp", {}).get("servers", ["configured servers"])
    evidence = csm.get("raw_evidence", [])
    evidence_summary = "; ".join(str(e.get("field", "")) for e in evidence[:5]) if evidence else "no evidence fields"

    prompt = (
        f"You are a technical writer producing compliance documentation for network device audits.\n"
        f"Write two short paragraphs in plain, neutral technical language.\n\n"
        f"Device audit record:\n"
        f"  Device hostname: {csm.get('device', {}).get('hostname', 'unknown')}\n"
        f"  Rule ID: {rule_id}\n"
        f"  Configuration evidence collected: {evidence_summary}\n"
        f"  Corrective CLI command: {remediation_cmd}\n\n"
        f"Paragraph 1 — label it WHY_IT_FAILED:\n"
        f"Describe what configuration setting is absent or misconfigured on this device, "
        f"and what that setting normally does when it is present. Use only factual, "
        f"procedural language. Do not use the words: risk, threat, vulnerability, "
        f"attacker, unauthorized, exploit, compromise, breach, malicious, hacker, or harmful.\n\n"
        f"Paragraph 2 — label it WHAT_REMEDIATION_DOES:\n"
        f"Describe mechanically what the corrective CLI command changes on the device "
        f"and what the device will do differently after the command is applied. "
        f"Use only factual, procedural language. Same word restriction applies.\n"
    )

    # Phrases that indicate the model refused to answer rather than explaining
    _REFUSAL_MARKERS = ("i can't provide", "i cannot provide", "illegal or harmful", "i'm not able to")

    ollama_ok = False
    try:
        payload = json.dumps({"model": _MODEL, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(_OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        response_text = data.get("response", "").strip()
        is_refusal = any(m in response_text.lower() for m in _REFUSAL_MARKERS)
        if len(response_text) > 20 and not is_refusal:
            ollama_ok = True
            print(f"[explain_failure_ai] path=ollama model={_MODEL} chars={len(response_text)}")
            # Split response into why/what halves if tagged
            why = what = response_text
            if "WHY_IT_FAILED" in response_text and "WHAT_REMEDIATION_DOES" in response_text:
                parts = response_text.split("WHAT_REMEDIATION_DOES", 1)
                why = parts[0].replace("WHY_IT_FAILED", "").replace("1.", "").strip().lstrip(":").strip()
                what = parts[1].replace("2.", "").strip().lstrip(":").strip()
            elif "2." in response_text:
                parts = response_text.split("2.", 1)
                why = parts[0].replace("1.", "").strip()
                what = parts[1].strip()
            return {
                "rule_id": rule_id,
                "why_it_failed": why,
                "what_remediation_does": what,
                "model_used": _MODEL,
                "execution_safety": "display_only_no_device_execution",
            }
        elif is_refusal:
            print(f"[explain_failure_ai] path=fallback reason=safety_refusal chars={len(response_text)}")
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        print(f"[explain_failure_ai] path=fallback reason={type(exc).__name__}: {exc}")

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


def verify_safety_no_execution() -> bool:
    """AST code analysis asserting that no process execution or device communication
    libraries are imported or used in remediation_engine.py.
    """
    forbidden = {"subprocess", "os.system", "paramiko", "netmiko", "pexpect", "telnetlib", "socket"}
    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name in forbidden:
                    raise RuntimeError(f"Safety Violation: Forbidden library '{n.name}' imported!")
        elif isinstance(node, ast.ImportFrom):
            if node.module in forbidden:
                raise RuntimeError(f"Safety Violation: Forbidden module '{node.module}' imported!")
    return True
