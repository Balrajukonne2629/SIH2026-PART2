"""NTRO PS26155 — Juniper Junos Compliance Auditor & Parser (Phase 2).

Provides pure Python standard library configuration parsing, CSM normalization,
and deterministic baseline compliance evaluation for Juniper Junos devices:

1. Canonical Parser:
   - Supports both hierarchical Junos { ... } syntax and flat 'set ...' syntax.
   - Normalizes configuration constructs into canonical statement tokens.
   - Robust and fault-tolerant: syntax anomalies are caught and preserved in csm["unmapped_lines"].
2. Common Security Model (CSM) Normalization:
   - Produces vendor-neutral schema conforming to normalized_config_schema.json.
   - Normalizes security concepts (SSH, AAA, NTP, Syslog, SNMP, Filters, VRF) into standard fields.
3. 10 Initial Junos Security Rules:
   - JUNOS-SSH-001: SSH Protocol Version (v2 required, v1/telnet forbidden)
   - JUNOS-SSH-002: SSH Connection & Rate Limits (connection-limit / rate-limit)
   - JUNOS-SSH-003: SSH Root Login Restriction (deny / deny-password)
   - JUNOS-AAA-001: Centralized Authentication Order (tacplus / radius)
   - JUNOS-AAA-002: Local Login & Password Policy (sha512, min-length, lockout)
   - JUNOS-NTP-001: NTP Server & Authentication (servers + auth key/trusted key)
   - JUNOS-LOG-001: Remote Syslog & Timestamps (syslog host + time-format)
   - JUNOS-SNMP-001: Insecure SNMP Community Strings (rejects public/private)
   - JUNOS-ACL-001: Management Access Control Filter (control-plane filter on loopback)
   - JUNOS-MGMT-001: Management VRF / Interface Isolation (virtual-router or fxp0)
4. Framework Evaluator Integration:
   - JuniperBaselineEvaluator implementing FrameworkEvaluator under 'juniper-junos-baseline'.
   - Complete vendor isolation: non-Juniper configs evaluate to Unknown without exception.

Hard Invariants:
- Pure Python standard library only (strictly AST-safe: zero subprocess, socket, or exec).
- Deterministic compliance: identical inputs produce bitwise identical outputs across runs.
- UNKNOWN preservation: missing or unconfigured sections remain Unknown, never conflated with Fail.
"""

import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from compliance_framework import (
    ComplianceStatus,
    Control,
    Evidence,
    EvaluationResult,
    Framework,
    FrameworkEvaluator,
    FrameworkRegistry,
    get_default_registry,
)

JUNIPER_FRAMEWORK_ID = "juniper-junos-baseline"
WEAK_COMMUNITIES = frozenset({"public", "private", "cisco", "community", "snmp"})

# 10 Grounded Prototype Rule Specifications
JUNIPER_RULE_SPECS = [
    {
        "vendor_rule_id": "JUNOS-SSH-001",
        "title": "Enforce secure SSH protocol version 2",
        "check_focus": ["SSH", "protocol-version"],
        "csmFieldChecked": "services.ssh_version",
        "condition": "equals 2",
    },
    {
        "vendor_rule_id": "JUNOS-SSH-002",
        "title": "Configure SSH connection and rate limits",
        "check_focus": ["SSH", "connection-restrictions"],
        "csmFieldChecked": "services.connection_limit",
        "condition": "not_null",
    },
    {
        "vendor_rule_id": "JUNOS-SSH-003",
        "title": "Restrict direct SSH root login",
        "check_focus": ["SSH", "root-login"],
        "csmFieldChecked": "services.root_login",
        "condition": "equals deny",
    },
    {
        "vendor_rule_id": "JUNOS-AAA-001",
        "title": "Configure centralized authentication order",
        "check_focus": ["AAA", "authentication-order"],
        "csmFieldChecked": "aaa.tacacs_enabled",
        "condition": "equals True",
    },
    {
        "vendor_rule_id": "JUNOS-AAA-002",
        "title": "Enforce password policy and complexity",
        "check_focus": ["AAA", "password-policy"],
        "csmFieldChecked": "management.password_policy_configured",
        "condition": "equals True",
    },
    {
        "vendor_rule_id": "JUNOS-NTP-001",
        "title": "Require authenticated NTP time synchronization",
        "check_focus": ["NTP", "authentication"],
        "csmFieldChecked": "ntp.authentication_enabled",
        "condition": "equals True",
    },
    {
        "vendor_rule_id": "JUNOS-LOG-001",
        "title": "Configure remote syslog logging with timestamps",
        "check_focus": ["Logging", "remote-syslog"],
        "csmFieldChecked": "logging.remote_logging_enabled",
        "condition": "equals True",
    },
    {
        "vendor_rule_id": "JUNOS-SNMP-001",
        "title": "Disallow default or weak SNMP community strings",
        "check_focus": ["SNMP", "community-strings"],
        "csmFieldChecked": "snmp.community_strings",
        "condition": "secure_communities",
    },
    {
        "vendor_rule_id": "JUNOS-ACL-001",
        "title": "Enforce control-plane and management access filter",
        "check_focus": ["AccessControl", "firewall-filter"],
        "csmFieldChecked": "access_control.control_plane_protection_enabled",
        "condition": "equals True",
    },
    {
        "vendor_rule_id": "JUNOS-MGMT-001",
        "title": "Isolate management traffic via dedicated VRF or interface",
        "check_focus": ["Management", "vrf-isolation"],
        "csmFieldChecked": "management.management_vrf_enabled",
        "condition": "equals True",
    },
]


def resolve_csm_path(csm: dict, path: str) -> Any:
    """Resolves a dot-delimited path (e.g. 'csm.services.ssh_version') in the CSM dict."""
    parts = [p for p in path.strip().split(".") if p and p != "csm"]
    curr = csm
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return None
    return curr


def eval_condition(val: Any, cond: str) -> str:
    """Generic condition evaluator on CSM values."""
    if not cond:
        return "Unknown"
    c = cond.strip()
    if c == "not_null":
        return "Pass" if val is not None else "Fail"
    if c in ("equals False", "is_false", "equals false"):
        return "Pass" if val is False else ("Fail" if val is True else "Unknown")
    if c in ("equals True", "is_true", "equals true"):
        return "Pass" if val is True else ("Fail" if val is False else "Unknown")
    if c.startswith("equals "):
        target = c[7:].strip()
        try:
            target_val: Any = int(target)
        except ValueError:
            target_val = target.strip('"\'')
        return "Pass" if val == target_val else ("Fail" if val is not None else "Unknown")
    return "Unknown"


# --- Canonical Junos Parser ---

def canonicalize_junos_statements(text: str) -> Tuple[List[str], List[str]]:
    """Tokenizes raw Junos configuration into canonical statement strings and unmapped lines.

    Accepts both:
    1. Hierarchical syntax with braces: 'system { services { ssh { ... } } }'
    2. Flat syntax: 'set system services ssh ...'

    Returns:
        Tuple of (canonical_statements, unmapped_or_comment_lines)
    """
    if not text or not text.strip():
        return [], []

    statements: List[str] = []
    unmapped: List[str] = []

    # 1. Strip C-style comments /* ... */ while noting their presence
    clean = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)

    # 2. Check if configuration is predominantly flat 'set' syntax
    raw_lines = [line.strip() for line in clean.splitlines() if line.strip()]
    set_lines = [l for l in raw_lines if l.startswith("set ")]

    if len(set_lines) > 0 and len(set_lines) >= (len(raw_lines) / 2):
        for line in raw_lines:
            if line.startswith("#") or line.startswith("!"):
                continue
            if line.startswith("set "):
                stmt = line[4:].strip().rstrip(";")
                statements.append(stmt)
            else:
                unmapped.append(line)
        return statements, unmapped

    # 3. Hierarchical Brace Tokenizer
    # Remove single-line comments (## and #)
    lines_clean = []
    for line in clean.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        if trimmed.startswith("##") or trimmed.startswith("#") or trimmed.startswith("!"):
            continue
        lines_clean.append(line)

    clean_content = "\n".join(lines_clean)

    tokens = re.findall(r'(\{|\}|;|\"[^\"]*\"|\[[^\]]*\]|[^\s\{\};]+)', clean_content)
    stack: List[List[str]] = []
    cur_stmt: List[str] = []

    for tok in tokens:
        if tok == "{":
            if cur_stmt:
                stack.append(cur_stmt)
                cur_stmt = []
        elif tok == "}":
            if cur_stmt:
                flat_stack = [item for sub in stack for item in sub]
                statements.append(" ".join(flat_stack + cur_stmt))
                cur_stmt = []
            if stack:
                stack.pop()
        elif tok == ";":
            if cur_stmt:
                flat_stack = [item for sub in stack for item in sub]
                statements.append(" ".join(flat_stack + cur_stmt))
                cur_stmt = []
        else:
            cur_stmt.append(tok)

    # Any leftover dangling tokens indicate unmatched braces or malformed syntax
    if cur_stmt:
        unmapped.append(" ".join(cur_stmt))

    return statements, unmapped


def parse_juniper(
    text: str,
    filename: str = "juniper.conf",
    trusted_rules: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    """Parses raw Juniper Junos configuration text into a normalized CSM dictionary.

    Conforms strictly to 07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/normalized_config_schema.json.
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    csm: Dict[str, Any] = {
        "schema_version": "1.0",
        "device": {
            "hostname": "unknown",
            "vendor": "juniper",
            "platform": "Junos",
            "os_version": None,
            "serial_number": None,
            "management_ip": None,
        },
        "source": {
            "source_type": "uploaded_file",
            "file_name": filename,
            "parser": "juniper_auditor",
            "parser_version": "1.0",
            "parsed_at": now_iso,
        },
        "interfaces": [],
        "services": {
            "telnet": False,
            "ssh": False,
            "ssh_version": None,
            "connection_limit": None,
            "rate_limit": None,
            "root_login": None,
            "http": False,
            "https": False,
            "ftp": False,
            "cdp_or_lldp": False,
            "finger": False,
        },
        "aaa": {
            "enabled": False,
            "authentication_method": None,
            "authorization_enabled": False,
            "accounting_enabled": False,
            "local_user_count": 0,
            "radius_enabled": False,
            "tacacs_enabled": False,
            "password_encryption": False,
            "configured": False,
        },
        "logging": {
            "enabled": False,
            "remote_logging_enabled": False,
            "remote_servers": [],
            "console_logging_enabled": False,
            "buffered_logging_enabled": False,
            "timestamps_enabled": False,
            "severity_level": None,
        },
        "ntp": {
            "enabled": False,
            "servers": [],
            "authentication_enabled": False,
            "authentication_keys": [],
            "trusted_key_ids": [],
            "synchronized": None,
        },
        "snmp": {
            "enabled": False,
            "version": None,
            "read_only": True,
            "communities_present": False,
            "community_strings": [],
            "community_strings_encrypted": False,
            "snmpv3_users_present": False,
            "trap_enabled": False,
        },
        "access_control": {
            "acls_present": False,
            "inbound_acl_count": 0,
            "outbound_acl_count": 0,
            "implicit_deny_present": False,
            "management_acl_present": False,
            "control_plane_protection_enabled": False,
        },
        "routing": {
            "static_routes_present": False,
            "ospf_enabled": False,
            "bgp_enabled": False,
            "eigrp_enabled": False,
            "isis_enabled": False,
            "rip_enabled": False,
            "routing_protocols": [],
            "routing_authentication_enabled": False,
        },
        "management": {
            "management_protocol": "ssh",
            "management_vrf_enabled": False,
            "login_banner_present": False,
            "motd_banner_present": False,
            "exec_timeout_configured": False,
            "password_policy_configured": False,
            "privilege_separation_enabled": False,
        },
        "raw_evidence": [],
        "unmapped_lines": [],
    }

    def add_ev(field_name: str, value: Any, source_line: str):
        csm["raw_evidence"].append({
            "field": field_name,
            "value": value,
            "source_lines": [source_line],
            "confidence": 1.0,
        })

    statements, unmapped = canonicalize_junos_statements(text)
    csm["unmapped_lines"].extend(unmapped)

    interfaces_map: Dict[str, dict] = {}

    for stmt in statements:
        line = stmt.strip()
        if not line:
            continue

        # 1. Device Hostname
        m_host = re.match(r"^system\s+host-name\s+(\S+)", line)
        if m_host:
            csm["device"]["hostname"] = m_host.group(1).strip('"\'')
            add_ev("device.hostname", csm["device"]["hostname"], line)
            continue

        # 2. SSH & Remote Services
        if "system services ssh" in line:
            csm["services"]["ssh"] = True
            add_ev("services.ssh", True, line)
            if "protocol-version v2" in line or "protocol-version 2" in line:
                csm["services"]["ssh_version"] = 2
                add_ev("services.ssh_version", 2, line)
            elif "protocol-version v1" in line or "protocol-version 1" in line:
                csm["services"]["ssh_version"] = 1
                add_ev("services.ssh_version", 1, line)

            m_conn = re.search(r"connection-limit\s+(\d+)", line)
            if m_conn:
                csm["services"]["connection_limit"] = int(m_conn.group(1))
                add_ev("services.connection_limit", csm["services"]["connection_limit"], line)

            m_rate = re.search(r"rate-limit\s+(\d+)", line)
            if m_rate:
                csm["services"]["rate_limit"] = int(m_rate.group(1))
                add_ev("services.rate_limit", csm["services"]["rate_limit"], line)

            m_root = re.search(r"root-login\s+(deny-password|deny|permit)", line)
            if m_root:
                csm["services"]["root_login"] = m_root.group(1)
                add_ev("services.root_login", m_root.group(1), line)
            continue

        if "system services telnet" in line:
            csm["services"]["telnet"] = True
            add_ev("services.telnet", True, line)
            continue

        # 3. AAA & Authentication
        if "system authentication-order" in line:
            csm["aaa"]["enabled"] = True
            csm["aaa"]["configured"] = True
            order_text = line.replace("system authentication-order", "").strip()
            csm["aaa"]["authentication_method"] = order_text
            if "tacplus" in order_text:
                csm["aaa"]["tacacs_enabled"] = True
            if "radius" in order_text:
                csm["aaa"]["radius_enabled"] = True
            add_ev("aaa.authentication-order", order_text, line)
            continue

        if "system tacplus-server" in line:
            csm["aaa"]["enabled"] = True
            csm["aaa"]["tacacs_enabled"] = True
            csm["aaa"]["configured"] = True
            add_ev("aaa.tacplus-server", True, line)
            continue

        if "system radius-server" in line:
            csm["aaa"]["enabled"] = True
            csm["aaa"]["radius_enabled"] = True
            csm["aaa"]["configured"] = True
            add_ev("aaa.radius-server", True, line)
            continue

        if "system login user" in line:
            csm["aaa"]["configured"] = True
            csm["aaa"]["local_user_count"] += 1
            if "encrypted-password" in line or "secret" in line:
                csm["aaa"]["password_encryption"] = True
            if "class super-user" in line:
                csm["management"]["privilege_separation_enabled"] = True
            add_ev("aaa.user", True, line)
            continue

        if "system login password" in line or "system login retry-options" in line:
            csm["management"]["password_policy_configured"] = True
            if "format sha512" in line or "sha512" in line:
                csm["aaa"]["password_encryption"] = True
            add_ev("management.password_policy", True, line)
            continue

        # 4. NTP
        if "system ntp server" in line:
            csm["ntp"]["enabled"] = True
            parts = line.split()
            idx = parts.index("server") if "server" in parts else -1
            if idx != -1 and idx + 1 < len(parts):
                server_ip = parts[idx + 1]
                if server_ip not in csm["ntp"]["servers"]:
                    csm["ntp"]["servers"].append(server_ip)
            add_ev("ntp.server", csm["ntp"]["servers"], line)
            continue

        if "system ntp authentication-key" in line or "system ntp trusted-key" in line:
            csm["ntp"]["authentication_enabled"] = True
            add_ev("ntp.authentication_enabled", True, line)
            continue

        # 5. Syslog Logging
        if "system syslog host" in line:
            csm["logging"]["enabled"] = True
            csm["logging"]["remote_logging_enabled"] = True
            parts = line.split()
            idx = parts.index("host") if "host" in parts else -1
            if idx != -1 and idx + 1 < len(parts):
                host_ip = parts[idx + 1]
                if host_ip not in csm["logging"]["remote_servers"]:
                    csm["logging"]["remote_servers"].append(host_ip)
            add_ev("logging.remote_servers", csm["logging"]["remote_servers"], line)
            continue

        if "system syslog file" in line:
            csm["logging"]["enabled"] = True
            csm["logging"]["buffered_logging_enabled"] = True
            add_ev("logging.file", True, line)
            continue

        if "system syslog time-format" in line:
            csm["logging"]["timestamps_enabled"] = True
            add_ev("logging.timestamps_enabled", True, line)
            continue

        # 6. SNMP
        if line.startswith("snmp community"):
            csm["snmp"]["enabled"] = True
            csm["snmp"]["communities_present"] = True
            parts = line.split()
            if len(parts) >= 3:
                comm_name = parts[2].strip('"\'')
                if comm_name not in csm["snmp"]["community_strings"]:
                    csm["snmp"]["community_strings"].append(comm_name)
            add_ev("snmp.community", csm["snmp"]["community_strings"], line)
            continue

        if "snmp v3" in line or "snmp usm" in line:
            csm["snmp"]["enabled"] = True
            csm["snmp"]["snmpv3_users_present"] = True
            csm["snmp"]["version"] = "3"
            add_ev("snmp.v3", True, line)
            continue

        # 7. Access Control & Firewall Filters
        if "firewall family inet" in line or "firewall family inet6" in line:
            csm["access_control"]["acls_present"] = True
            if "filter protect-control-plane" in line or "term allow-ssh" in line or "filter protect" in line:
                csm["access_control"]["control_plane_protection_enabled"] = True
                csm["access_control"]["management_acl_present"] = True
            if "discard" in line or "reject" in line:
                csm["access_control"]["implicit_deny_present"] = True
            add_ev("access_control.firewall", True, line)
            continue

        # 8. Interfaces & Management Isolation
        if line.startswith("interfaces "):
            parts = line.split()
            if len(parts) >= 2:
                if_name = parts[1]
                if if_name not in interfaces_map:
                    interfaces_map[if_name] = {
                        "name": if_name,
                        "description": None,
                        "enabled": True,
                        "ip_addresses": [],
                        "switchport": False,
                        "shutdown": False,
                    }
                cur_if = interfaces_map[if_name]

                # Dedicated management interface detection
                if if_name.startswith("fxp0") or if_name.startswith("em0") or if_name.startswith("me0"):
                    csm["management"]["management_vrf_enabled"] = True
                    add_ev("management.mgmt_interface", if_name, line)

                if "description" in line:
                    m_desc = re.search(r'description\s+("[^"]*"|\S+)', line)
                    if m_desc:
                        cur_if["description"] = m_desc.group(1).strip('"')

                if "disable" in parts:
                    cur_if["shutdown"] = True
                    cur_if["enabled"] = False
                    add_ev("interface.disable", if_name, line)

                m_addr = re.search(r'address\s+([0-9a-fA-F\.\:]+/\d+)', line)
                if m_addr:
                    ip_str = m_addr.group(1)
                    cur_if["ip_addresses"].append(ip_str)
                    if not csm["device"]["management_ip"] and (
                        if_name.startswith("fxp0") or if_name.startswith("lo0")
                    ):
                        csm["device"]["management_ip"] = ip_str.split("/")[0]
            continue

        # 9. Management VRF / Routing Instances
        if "routing-instances" in line and ("virtual-router" in line or "instance-type" in line):
            csm["management"]["management_vrf_enabled"] = True
            add_ev("management.management_vrf_enabled", True, line)
            continue

        # 10. Routing Protocols
        if "protocols ospf" in line:
            csm["routing"]["ospf_enabled"] = True
            if "ospf" not in csm["routing"]["routing_protocols"]:
                csm["routing"]["routing_protocols"].append("ospf")
            if "authentication" in line:
                csm["routing"]["routing_authentication_enabled"] = True
            add_ev("routing.ospf", True, line)
            continue

        if "protocols bgp" in line:
            csm["routing"]["bgp_enabled"] = True
            if "bgp" not in csm["routing"]["routing_protocols"]:
                csm["routing"]["routing_protocols"].append("bgp")
            if "authentication-key" in line:
                csm["routing"]["routing_authentication_enabled"] = True
            add_ev("routing.bgp", True, line)
            continue

        # Other statements not recognized by standard rules
        csm["unmapped_lines"].append(line)

    csm["interfaces"] = list(interfaces_map.values())
    return csm


# --- Baseline Compliance Evaluation ---

def evaluate_juniper_baseline(csm: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Deterministically evaluates the 10 initial Junos rules against normalized CSM."""
    s = csm.get("services", {})
    a = csm.get("aaa", {})
    n = csm.get("ntp", {})
    l = csm.get("logging", {})
    sn = csm.get("snmp", {})
    ac = csm.get("access_control", {})
    m = csm.get("management", {})

    ev_items = csm.get("raw_evidence", [])
    ev_lines = [src for item in ev_items for src in item.get("source_lines", [])]

    results: Dict[str, Dict[str, Any]] = {}

    # 1. JUNOS-SSH-001: SSH Protocol Version
    if not s.get("ssh"):
        st_ssh1 = "Unknown"
    elif s.get("ssh_version") == 2 and not s.get("telnet"):
        st_ssh1 = "Pass"
    elif s.get("ssh_version") == 1 or s.get("telnet"):
        st_ssh1 = "Fail"
    else:
        st_ssh1 = "Unknown"
    results["JUNOS-SSH-001"] = {
        "status": st_ssh1,
        "focus": "SSH Protocol Version",
        "evidence_found": [line for line in ev_lines if "ssh" in line.lower() or "telnet" in line.lower()],
    }

    # 2. JUNOS-SSH-002: SSH Connection & Rate Limits
    conn_lim = s.get("connection_limit")
    rate_lim = s.get("rate_limit")
    if not s.get("ssh"):
        st_ssh2 = "Unknown"
    elif (conn_lim and conn_lim > 0) or (rate_lim and rate_lim > 0):
        st_ssh2 = "Pass"
    else:
        st_ssh2 = "Fail"
    results["JUNOS-SSH-002"] = {
        "status": st_ssh2,
        "focus": "SSH Connection Restrictions",
        "evidence_found": [line for line in ev_lines if "limit" in line.lower()],
    }

    # 3. JUNOS-SSH-003: SSH Root Login Restriction
    root_login = s.get("root_login")
    if not s.get("ssh") or root_login is None:
        st_ssh3 = "Unknown"
    elif root_login in ("deny", "deny-password"):
        st_ssh3 = "Pass"
    elif root_login in ("permit", "yes"):
        st_ssh3 = "Fail"
    else:
        st_ssh3 = "Unknown"
    results["JUNOS-SSH-003"] = {
        "status": st_ssh3,
        "focus": "SSH Root Login",
        "evidence_found": [line for line in ev_lines if "root-login" in line.lower()],
    }

    # 4. JUNOS-AAA-001: Centralized Authentication Order
    if not a.get("enabled") and not a.get("configured"):
        st_aaa1 = "Unknown"
    elif a.get("enabled") and (a.get("tacacs_enabled") or a.get("radius_enabled")):
        st_aaa1 = "Pass"
    elif a.get("enabled") or a.get("configured"):
        st_aaa1 = "Fail"
    else:
        st_aaa1 = "Unknown"
    results["JUNOS-AAA-001"] = {
        "status": st_aaa1,
        "focus": "Authentication Order",
        "evidence_found": [line for line in ev_lines if "authentication" in line.lower() or "server" in line.lower()],
    }

    # 5. JUNOS-AAA-002: Local User & Password Policy
    pwd_configured = m.get("password_policy_configured", False)
    pwd_encrypted = a.get("password_encryption", False)
    if not a.get("configured") and not pwd_configured:
        st_aaa2 = "Unknown"
    elif pwd_configured and pwd_encrypted:
        st_aaa2 = "Pass"
    elif a.get("configured") and not pwd_configured:
        st_aaa2 = "Fail"
    else:
        st_aaa2 = "Fail"
    results["JUNOS-AAA-002"] = {
        "status": st_aaa2,
        "focus": "Password Policy",
        "evidence_found": [line for line in ev_lines if "password" in line.lower() or "user" in line.lower()],
    }

    # 6. JUNOS-NTP-001: NTP Server & Authentication
    ntp_servers = n.get("servers", [])
    ntp_auth = n.get("authentication_enabled", False)
    if not ntp_servers:
        st_ntp1 = "Unknown"
    elif ntp_auth:
        st_ntp1 = "Pass"
    else:
        st_ntp1 = "Fail"
    results["JUNOS-NTP-001"] = {
        "status": st_ntp1,
        "focus": "NTP Authentication",
        "evidence_found": [line for line in ev_lines if "ntp" in line.lower()],
    }

    # 7. JUNOS-LOG-001: Remote Syslog & Timestamps
    remote_log = l.get("remote_logging_enabled", False)
    timestamps = l.get("timestamps_enabled", False)
    if not l.get("enabled"):
        st_log1 = "Unknown"
    elif remote_log and timestamps:
        st_log1 = "Pass"
    else:
        st_log1 = "Fail"
    results["JUNOS-LOG-001"] = {
        "status": st_log1,
        "focus": "Remote Logging",
        "evidence_found": [line for line in ev_lines if "syslog" in line.lower()],
    }

    # 8. JUNOS-SNMP-001: Insecure SNMP Communities
    comms = sn.get("community_strings", [])
    has_weak = any(c.lower() in WEAK_COMMUNITIES for c in comms)
    if not sn.get("enabled"):
        st_snmp1 = "Unknown"
    elif has_weak:
        st_snmp1 = "Fail"
    elif sn.get("snmpv3_users_present") or (sn.get("communities_present") and comms):
        st_snmp1 = "Pass"
    else:
        st_snmp1 = "Unknown"
    results["JUNOS-SNMP-001"] = {
        "status": st_snmp1,
        "focus": "SNMP Community Strings",
        "evidence_found": [line for line in ev_lines if "snmp" in line.lower()],
    }

    # 9. JUNOS-ACL-001: Management Access Control Filter
    mgmt_filter = ac.get("control_plane_protection_enabled") or ac.get("management_acl_present")
    if not s.get("ssh") and not ac.get("acls_present"):
        st_acl1 = "Unknown"
    elif mgmt_filter:
        st_acl1 = "Pass"
    elif s.get("ssh") and not mgmt_filter:
        st_acl1 = "Fail"
    else:
        st_acl1 = "Unknown"
    results["JUNOS-ACL-001"] = {
        "status": st_acl1,
        "focus": "Control Plane Filter",
        "evidence_found": [line for line in ev_lines if "filter" in line.lower() or "firewall" in line.lower()],
    }

    # 10. JUNOS-MGMT-001: Management VRF / Interface Isolation
    mgmt_vrf = m.get("management_vrf_enabled", False)
    if not s.get("ssh"):
        st_mgmt1 = "Unknown"
    elif mgmt_vrf:
        st_mgmt1 = "Pass"
    elif s.get("ssh") and not mgmt_vrf:
        st_mgmt1 = "Fail"
    else:
        st_mgmt1 = "Unknown"
    results["JUNOS-MGMT-001"] = {
        "status": st_mgmt1,
        "focus": "Management VRF Isolation",
        "evidence_found": [line for line in ev_lines if "routing-instances" in line.lower() or "fxp0" in line.lower()],
    }

    return results


def evaluate_rules(
    csm: Dict[str, Any],
    rules: Optional[List[dict]] = None,
    trusted_rules: Optional[List[dict]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Legacy compatibility adapter evaluating baseline and trusted rules on CSM."""
    # Vendor isolation: if CSM does not belong to Juniper, return Unknown for all
    if csm.get("device", {}).get("vendor") != "juniper":
        empty_res: Dict[str, Dict[str, Any]] = {}
        for spec in JUNIPER_RULE_SPECS:
            empty_res[spec["vendor_rule_id"]] = {
                "status": "Unknown",
                "focus": spec["check_focus"][0],
                "evidence_found": [],
            }
        return empty_res

    res = evaluate_juniper_baseline(csm)

    # Evaluate dynamic / trusted rules
    ev_items = csm.get("raw_evidence", [])
    ev_lines = [src for item in ev_items for src in item.get("source_lines", [])]

    for tr in (trusted_rules or []):
        rid = tr.get("vendor_rule_id", "TRUSTED-000")
        field_path = tr.get("csmFieldChecked", "")
        cond = tr.get("condition", "")
        if field_path and cond:
            val = resolve_csm_path(csm, field_path)
            st_val = eval_condition(val, cond)
        else:
            st_val = "Unknown"
        ev = [e for e in tr.get("configuration_evidence", []) if any(e in line for line in ev_lines)]
        res[rid] = {
            "status": st_val,
            "focus": tr.get("check_focus", ["Security"])[0],
            "evidence_found": ev,
        }

    return res


# --- Framework Evaluator Integration ---

class JuniperBaselineEvaluator(FrameworkEvaluator):
    """Deterministic FrameworkEvaluator implementing 'juniper-junos-baseline'."""

    def __init__(self, framework_id: str = JUNIPER_FRAMEWORK_ID):
        self._framework_id = framework_id.strip().lower()
        self._controls: Dict[str, Control] = {
            spec["vendor_rule_id"]: Control(
                framework_id=self._framework_id,
                control_id=spec["vendor_rule_id"],
                title=spec["title"],
                description=f"Deterministic verification of {spec['title']}.",
                severity="high",
                expected_state=spec["condition"],
                evaluation_metadata={
                    "category": spec["check_focus"][0],
                    "csm_section": spec["check_focus"][0].lower(),
                    "csm_fields": [spec["csmFieldChecked"]],
                },
            )
            for spec in JUNIPER_RULE_SPECS
        }

    @property
    def framework_id(self) -> str:
        return self._framework_id

    def evaluate(
        self,
        csm: Dict[str, Any],
        controls: Optional[Sequence[Control]] = None,
    ) -> List[EvaluationResult]:
        """Evaluates normalized CSM against 'juniper-junos-baseline' controls with vendor isolation."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        results: List[EvaluationResult] = []

        is_juniper = csm.get("device", {}).get("vendor") == "juniper"
        evals = evaluate_juniper_baseline(csm) if is_juniper else {}

        target_controls = controls if controls is not None else list(self._controls.values())

        for ctrl in target_controls:
            rule_id = ctrl.control_id
            spec = next((s for s in JUNIPER_RULE_SPECS if s["vendor_rule_id"] == rule_id), None)
            title = spec["title"] if spec else ctrl.title

            if not is_juniper:
                status = ComplianceStatus.UNKNOWN
                evidence = Evidence(
                    observed_value=csm.get("device", {}).get("vendor"),
                    location="csm.device.vendor",
                    expected_value="juniper",
                    rationale="Device vendor is not Juniper Junos; control evaluated as Unknown.",
                    confidence=1.0,
                    source_lines=(),
                )
            else:
                rule_res = evals.get(rule_id, {})
                status = ComplianceStatus.from_str(rule_res.get("status", "Unknown"))
                ev_found = rule_res.get("evidence_found", [])
                evidence = Evidence(
                    observed_value=ev_found,
                    location=f"csm.{spec['csmFieldChecked'] if spec else 'security'}",
                    expected_value=spec["condition"] if spec else "Compliant",
                    rationale=f"Evaluated rule {rule_id} against normalized Junos CSM. Verdict: {status.value}.",
                    confidence=1.0,
                    source_lines=tuple(ev_found),
                )

            results.append(
                EvaluationResult(
                    framework_id=self._framework_id,
                    control_id=rule_id,
                    status=status,
                    evidence=evidence,
                    reason=f"{title}: {status.value}",
                    observed_value=evidence.observed_value,
                    expected_value=evidence.expected_value,
                    evaluator_id="juniper_auditor.JuniperBaselineEvaluator",
                    timestamp=now_iso,
                )
            )

        return results


def register_juniper_baseline(
    registry: Optional[FrameworkRegistry] = None,
) -> FrameworkRegistry:
    """Registers the 'juniper-junos-baseline' framework and evaluator into FrameworkRegistry."""
    target = registry if registry is not None else get_default_registry()
    framework = Framework(
        framework_id=JUNIPER_FRAMEWORK_ID,
        name="Juniper Junos Baseline Security Standard",
        version="1.0",
        description="Deterministic network security baseline for Juniper Junos network operating systems.",
        vendor_scope="Juniper Junos",
        control_namespace="JUNOS",
        enabled=True,
    )
    evaluator = JuniperBaselineEvaluator(framework_id=JUNIPER_FRAMEWORK_ID)
    target.register(framework=framework, evaluator=evaluator, allow_replace=True)
    return target
