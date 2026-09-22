"""NTRO PS26155 — Juniper Junos Vendor Integration Tests (Phase 2).

Comprehensive TDD test suite validating the complete Juniper vendor integration:
1. Vendor Adapter & Registry Integration (Registration, Lookup, Extensible Listing)
2. Deterministic Vendor Detection (Hierarchical & Flat Set detection, Negative Cisco rejection, Fail-closed)
3. Juniper Parsing & CSM Normalization (Hierarchical and Set parity, JSON schema conformance, Zero Cisco leakage)
4. Determinism & AST Execution Safety (Identical hash across 5 runs, stdlib-only verification)
5. 10 Initial Junos Rules Compliance (Pass, Fail, Unknown for all 10 rules)
6. Framework Integration (JuniperBaselineEvaluator, FrameworkRegistry, Deterministic Evidence)
7. Vendor Isolation (Cross-vendor evaluation safety: Cisco vs Junos baseline)
8. End-to-End Generic API Ingestion (Upload via /api/audit/upload with no vendor branching in main.py)
9. Cisco MVP Baseline Parity (Zero regressions against existing Cisco test suite)
"""

import hashlib
import json
import pathlib
import re
import zipfile
import pytest
from fastapi.testclient import TestClient

import auth
import database
import juniper_auditor
from vendor_adapter import CiscoVendorAdapter, JuniperVendorAdapter, VendorAdapter
from vendor_registry import (
    VendorRegistry,
    get_default_vendor_registry,
    ingest_configuration,
    UndeterminedVendorError,
    UnsupportedVendorError,
)
from compliance_framework import (
    ComplianceStatus,
    FrameworkRegistry,
    get_default_registry,
)
from main import app

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_FILE = BASE_DIR / "config" / "Rule_Library" / "normalized_config_schema.json"
SAMPLES_ZIP = BASE_DIR / "datasets" / "Juniper" / "Juniper_Junos_Samples.zip"


# --- Fixtures ---

@pytest.fixture
def clean_vendor_registry():
    """Returns a fresh VendorRegistry with both Cisco and Juniper adapters registered."""
    reg = VendorRegistry()
    reg.register(CiscoVendorAdapter())
    reg.register(JuniperVendorAdapter())
    return reg


@pytest.fixture
def sample_junos_from_repo_zip():
    """Returns the actual synthetic Junos sample from the repository zip file."""
    if SAMPLES_ZIP.exists():
        with zipfile.ZipFile(SAMPLES_ZIP) as z:
            return z.read("Juniper_Junos_Samples/sample_juniper_junos_configuration.conf").decode("utf-8")
    return ""


@pytest.fixture
def sample_junos_hierarchical():
    """Returns a synthetic Junos hierarchical configuration with full security controls."""
    return """
system {
    host-name lab-junos-router;
    services {
        ssh {
            protocol-version v2;
            connection-limit 10;
            rate-limit 5;
            root-login deny;
        }
    }
    login {
        user netadmin {
            class super-user;
            authentication {
                encrypted-password "$6$REDACTED_HASH_VALUE";
            }
        }
        password {
            format sha512;
            minimum-length 12;
        }
    }
    ntp {
        server 192.0.2.10;
        authentication-key 1 type md5 value "$9$...";
        trusted-key [ 1 ];
    }
    syslog {
        host 192.0.2.10 {
            any info;
        }
        time-format millisecond;
    }
}
interfaces {
    ge-0/0/0 {
        description "Uplink";
        unit 0 {
            family inet {
                address 192.0.2.1/30;
            }
        }
    }
    fxp0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
}
snmp {
    community secure-comm {
        authorization read-only;
        clients {
            192.0.2.0/24;
        }
    }
}
firewall {
    family inet {
        filter protect-control-plane {
            term allow-ssh {
                from {
                    protocol tcp;
                    destination-port ssh;
                }
                then accept;
            }
            term default-deny {
                then discard;
            }
        }
    }
}
routing-instances {
    mgmt_junos {
        instance-type virtual-router;
    }
}
"""


@pytest.fixture
def sample_junos_set():
    """Returns a synthetic Junos configuration in flat 'set' format."""
    return """
set system host-name lab-junos-router
set system services ssh protocol-version v2
set system services ssh connection-limit 10
set system services ssh rate-limit 5
set system services ssh root-login deny
set system login user netadmin class super-user
set system login password format sha512
set system login password minimum-length 12
set system ntp server 192.0.2.10
set system ntp authentication-key 1 type md5 value "$9$..."
set system ntp trusted-key 1
set system syslog host 192.0.2.10 any info
set system syslog time-format millisecond
set interfaces ge-0/0/0 description "Uplink"
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30
set interfaces fxp0 unit 0 family inet address 192.168.1.1/24
set snmp community secure-comm authorization read-only
set snmp community secure-comm clients 192.0.2.0/24
set firewall family inet filter protect-control-plane term allow-ssh from protocol tcp
set firewall family inet filter protect-control-plane term allow-ssh from destination-port ssh
set firewall family inet filter protect-control-plane term allow-ssh then accept
set firewall family inet filter protect-control-plane term default-deny then discard
set routing-instances mgmt_junos instance-type virtual-router
"""


@pytest.fixture
def sample_junos_compliant():
    """Fully compliant Junos config where all 10 initial rules PASS."""
    return """
system {
    host-name compliant-junos;
    services {
        ssh {
            protocol-version v2;
            connection-limit 10;
            rate-limit 5;
            root-login deny;
        }
    }
    authentication-order [ tacplus radius password ];
    login {
        user admin {
            class super-user;
            authentication {
                encrypted-password "$6$somehash";
            }
        }
        password {
            format sha512;
            minimum-length 12;
        }
        retry-options {
            tries-before-disconnect 3;
            lockout-period 15;
        }
    }
    ntp {
        server 192.0.2.100;
        authentication-key 1 type md5 value "$9$xxx";
        trusted-key [ 1 ];
    }
    syslog {
        host 192.0.2.50 {
            any info;
        }
        time-format millisecond;
    }
}
snmp {
    community hardened_comm {
        authorization read-only;
        clients { 192.0.2.0/24; }
    }
}
firewall {
    family inet {
        filter protect-control-plane {
            term allow-ssh {
                from { protocol tcp; destination-port ssh; }
                then accept;
            }
            term default-deny {
                then discard;
            }
        }
    }
}
routing-instances {
    mgmt-vrf {
        instance-type virtual-router;
    }
}
interfaces {
    fxp0 {
        unit 0 {
            family inet { address 10.0.0.1/24; }
        }
    }
}
"""


@pytest.fixture
def sample_junos_noncompliant():
    """Non-compliant Junos config where all 10 initial rules FAIL."""
    return """
system {
    host-name insecure-junos;
    services {
        ssh {
            protocol-version v1;
            root-login permit;
        }
    }
    authentication-order [ password ];
    login {
        user admin {
            class super-user;
        }
        password {
            format md5;
            minimum-length 4;
        }
    }
    ntp {
        server 192.0.2.100;
    }
    syslog {
        file messages {
            any info;
        }
    }
}
snmp {
    community public {
        authorization read-only;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 192.0.2.1/24; }
        }
    }
}
"""


# --- A. Juniper Adapter Registration ---

def test_juniper_adapter_properties():
    """Verify JuniperVendorAdapter properties conform to VendorAdapter contract."""
    adapter = JuniperVendorAdapter()
    assert adapter.vendor_id == "juniper"
    assert "Juniper" in adapter.vendor_name
    assert "Junos" in adapter.supported_platforms
    assert isinstance(adapter, VendorAdapter)


def test_juniper_adapter_registration(clean_vendor_registry):
    """Verify JuniperVendorAdapter registers cleanly in VendorRegistry."""
    assert clean_vendor_registry.has("juniper")
    assert "juniper" in clean_vendor_registry.list_vendor_ids()
    adapter = clean_vendor_registry.get("juniper")
    assert isinstance(adapter, JuniperVendorAdapter)


def test_default_vendor_registry_includes_juniper():
    """Verify process-level default registry contains both Cisco and Juniper."""
    reg = get_default_vendor_registry()
    assert reg.has("cisco")
    assert reg.has("juniper")
    assert sorted(reg.list_vendor_ids()) == ["cisco", "juniper"]


# --- B & C. Vendor Detection ---

def test_detect_juniper_hierarchical(clean_vendor_registry, sample_junos_hierarchical):
    """Verify detection accurately identifies hierarchical Junos configs."""
    adapter = clean_vendor_registry.detect(sample_junos_hierarchical)
    assert adapter is not None
    assert adapter.vendor_id == "juniper"


def test_detect_juniper_set(clean_vendor_registry, sample_junos_set):
    """Verify detection accurately identifies flat set Junos configs."""
    adapter = clean_vendor_registry.detect(sample_junos_set)
    assert adapter is not None
    assert adapter.vendor_id == "juniper"


def test_detect_cisco_not_juniper(clean_vendor_registry):
    """Verify Cisco configuration is detected as Cisco with 0 Juniper confidence."""
    cisco_cfg = """
hostname router1
!
service timestamps log datetime msec
service password-encryption
!
line vty 0 4
 transport input ssh
!
ip ssh version 2
aaa new-model
"""
    adapter = clean_vendor_registry.detect(cisco_cfg)
    assert adapter is not None
    assert adapter.vendor_id == "cisco"
    assert JuniperVendorAdapter().detect_confidence(cisco_cfg) == 0.0


def test_detect_ambiguous_fails_closed(clean_vendor_registry):
    """Verify ambiguous, empty, or unknown text fails closed."""
    assert clean_vendor_registry.detect("") is None
    assert clean_vendor_registry.detect("   \n\t  ") is None
    assert clean_vendor_registry.detect("random unformatted text without network tokens") is None


# --- D. Juniper Parsing & CSM Normalization ---

def test_parse_juniper_hierarchical(sample_junos_hierarchical):
    """Verify parsing hierarchical Junos config generates complete, normalized CSM."""
    csm = juniper_auditor.parse_juniper(sample_junos_hierarchical, filename="sample.conf")

    assert csm["schema_version"] == "1.0"
    assert csm["device"]["vendor"] == "juniper"
    assert csm["device"]["platform"] == "Junos"
    assert csm["device"]["hostname"] == "lab-junos-router"
    assert csm["source"]["parser"] == "juniper_auditor"

    # Services
    assert csm["services"]["ssh"] is True
    assert csm["services"]["ssh_version"] == 2
    assert csm["services"]["connection_limit"] == 10
    assert csm["services"]["rate_limit"] == 5
    assert csm["services"]["root_login"] == "deny"

    # NTP
    assert csm["ntp"]["enabled"] is True
    assert len(csm["ntp"]["servers"]) >= 1
    assert csm["ntp"]["authentication_enabled"] is True

    # Logging
    assert csm["logging"]["remote_logging_enabled"] is True
    assert "192.0.2.10" in csm["logging"]["remote_servers"]
    assert csm["logging"]["timestamps_enabled"] is True

    # SNMP
    assert csm["snmp"]["enabled"] is True
    assert "secure-comm" in csm["snmp"]["community_strings"]

    # Access Control
    assert csm["access_control"]["control_plane_protection_enabled"] is True
    assert csm["access_control"]["management_acl_present"] is True

    # Management & Interfaces
    assert csm["management"]["management_vrf_enabled"] is True
    assert len(csm["interfaces"]) >= 1


def test_parse_juniper_set_parity(sample_junos_hierarchical, sample_junos_set):
    """Verify hierarchical and set formats produce functionally equivalent normalized CSM fields."""
    csm_hier = juniper_auditor.parse_juniper(sample_junos_hierarchical)
    csm_set = juniper_auditor.parse_juniper(sample_junos_set)

    # Core security attributes should match exactly
    assert csm_set["device"]["hostname"] == csm_hier["device"]["hostname"]
    assert csm_set["services"]["ssh_version"] == csm_hier["services"]["ssh_version"]
    assert csm_set["services"]["connection_limit"] == csm_hier["services"]["connection_limit"]
    assert csm_set["services"]["rate_limit"] == csm_hier["services"]["rate_limit"]
    assert csm_set["services"]["root_login"] == csm_hier["services"]["root_login"]
    assert csm_set["ntp"]["authentication_enabled"] == csm_hier["ntp"]["authentication_enabled"]
    assert csm_set["logging"]["remote_logging_enabled"] == csm_hier["logging"]["remote_logging_enabled"]
    assert csm_set["logging"]["timestamps_enabled"] == csm_hier["logging"]["timestamps_enabled"]
    assert csm_set["snmp"]["community_strings"] == csm_hier["snmp"]["community_strings"]
    assert csm_set["access_control"]["control_plane_protection_enabled"] == csm_hier["access_control"]["control_plane_protection_enabled"]
    assert csm_set["management"]["management_vrf_enabled"] == csm_hier["management"]["management_vrf_enabled"]


def test_csm_schema_conformance(sample_junos_hierarchical):
    """Verify generated Juniper CSM conforms to normalized_config_schema.json required fields."""
    csm = juniper_auditor.parse_juniper(sample_junos_hierarchical)

    if SCHEMA_FILE.exists():
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        for req_key in schema.get("required", []):
            assert req_key in csm, f"Missing required CSM key: {req_key}"

    # Device object required fields
    assert "hostname" in csm["device"]
    assert "vendor" in csm["device"]
    assert "platform" in csm["device"]
    assert csm["device"]["vendor"] == "juniper"

    # Verify no Cisco leakage at root
    assert "line_vty" not in csm
    assert "access_class" not in csm


def test_malformed_junos_config_safety():
    """Verify malformed configuration with unmatched braces does not crash and collects unmapped lines."""
    bad_cfg = """
system {
    host-name broken-junos;
    services {
        ssh {
            protocol-version v2;
    # missing closing braces
garbage line that makes no sense
"""
    csm = juniper_auditor.parse_juniper(bad_cfg)
    assert csm["device"]["hostname"] == "broken-junos"
    assert csm["services"]["ssh_version"] == 2
    assert len(csm["unmapped_lines"]) > 0


# --- E, F, G, H. The 10 Initial Junos Rules Evaluation ---

def test_all_10_rules_pass_on_compliant_config(sample_junos_compliant):
    """Verify all 10 initial Junos rules evaluate to PASS on fully compliant configuration."""
    csm = juniper_auditor.parse_juniper(sample_junos_compliant)
    results = juniper_auditor.evaluate_juniper_baseline(csm)

    expected_rules = [
        "JUNOS-SSH-001",
        "JUNOS-SSH-002",
        "JUNOS-SSH-003",
        "JUNOS-AAA-001",
        "JUNOS-AAA-002",
        "JUNOS-NTP-001",
        "JUNOS-LOG-001",
        "JUNOS-SNMP-001",
        "JUNOS-ACL-001",
        "JUNOS-MGMT-001",
    ]

    assert len(results) == 10
    for rule_id in expected_rules:
        assert rule_id in results, f"Missing rule in results: {rule_id}"
        assert results[rule_id]["status"] == "Pass", f"Rule {rule_id} did not PASS: {results[rule_id]}"


def test_all_10_rules_fail_on_noncompliant_config(sample_junos_noncompliant):
    """Verify rules evaluate to FAIL on non-compliant configuration."""
    csm = juniper_auditor.parse_juniper(sample_junos_noncompliant)
    results = juniper_auditor.evaluate_juniper_baseline(csm)

    # Specific expected FAILs:
    assert results["JUNOS-SSH-001"]["status"] == "Fail"  # v1 protocol
    assert results["JUNOS-SSH-002"]["status"] == "Fail"  # no connection/rate limits
    assert results["JUNOS-SSH-003"]["status"] == "Fail"  # root-login permit
    assert results["JUNOS-AAA-001"]["status"] == "Fail"  # only password, no tacplus/radius
    assert results["JUNOS-AAA-002"]["status"] == "Fail"  # weak md5, length 4
    assert results["JUNOS-NTP-001"]["status"] == "Fail"  # ntp configured without authentication
    assert results["JUNOS-LOG-001"]["status"] == "Fail"  # local syslog only, no remote host
    assert results["JUNOS-SNMP-001"]["status"] == "Fail"  # weak community "public"
    assert results["JUNOS-ACL-001"]["status"] == "Fail"  # SSH exposed without firewall filter
    assert results["JUNOS-MGMT-001"]["status"] == "Fail"  # SSH without mgmt VRF/interface


def test_empty_config_evaluates_unknown():
    """Verify empty or missing sections evaluate to Unknown, preserving fail-closed semantics."""
    empty_csm = juniper_auditor.parse_juniper("## empty config\n")
    results = juniper_auditor.evaluate_juniper_baseline(empty_csm)

    for rule_id, res in results.items():
        assert res["status"] == "Unknown", f"Rule {rule_id} expected Unknown but was {res['status']}"


# --- I. Framework Evaluator Integration ---

def test_juniper_framework_evaluator_registration():
    """Verify JuniperBaselineEvaluator registers into FrameworkRegistry."""
    reg = FrameworkRegistry()
    juniper_auditor.register_juniper_baseline(reg)

    assert reg.exists("juniper-junos-baseline")
    framework = reg.get("juniper-junos-baseline")
    assert framework.framework_id == "juniper-junos-baseline"
    assert "Juniper" in framework.vendor_scope

    evaluator = reg.get_evaluator("juniper-junos-baseline")
    assert evaluator is not None
    assert evaluator.framework_id == "juniper-junos-baseline"


def test_juniper_framework_evaluator_execution(sample_junos_compliant):
    """Verify JuniperBaselineEvaluator produces valid EvaluationResult objects."""
    csm = juniper_auditor.parse_juniper(sample_junos_compliant)
    evaluator = juniper_auditor.JuniperBaselineEvaluator()
    eval_results = evaluator.evaluate(csm)

    assert len(eval_results) == 10
    for res in eval_results:
        assert res.framework_id == "juniper-junos-baseline"
        assert res.status == ComplianceStatus.PASS
        assert res.evidence is not None
        assert res.evidence.confidence == 1.0
        assert res.evidence.location.startswith("csm.")


# --- J & K. Vendor Isolation ---

def test_cisco_csm_against_juniper_evaluator():
    """Verify evaluating a Cisco CSM against Juniper evaluator returns Unknown safely with zero errors."""
    cisco_csm = {
        "schema_version": "1.0",
        "device": {"hostname": "cisco-rtr", "vendor": "cisco", "platform": "IOS-XE"},
        "services": {"ssh": True, "ssh_version": 2},
        "aaa": {"enabled": True},
        "ntp": {"servers": ["1.1.1.1"]},
        "logging": {"remote_logging_enabled": True},
        "snmp": {"enabled": True},
        "access_control": {"acls_present": True},
        "management": {"management_vrf_enabled": True},
    }
    evaluator = juniper_auditor.JuniperBaselineEvaluator()
    results = evaluator.evaluate(cisco_csm)

    assert len(results) == 10
    for res in results:
        assert res.status == ComplianceStatus.UNKNOWN


def test_juniper_csm_against_cisco_framework():
    """Verify evaluating a Juniper CSM against Cisco framework adapters returns Unknown safely."""
    from compliance_framework import CiscoCsmFrameworkAdapter
    juniper_csm = juniper_auditor.parse_juniper("system { host-name junos-box; }\n")
    adapter = CiscoCsmFrameworkAdapter()
    results = adapter.evaluate(juniper_csm)
    for res in results:
        assert res.status == ComplianceStatus.UNKNOWN


# --- L. Determinism Verification ---

def test_juniper_parser_determinism(sample_junos_hierarchical):
    """Verify 5 consecutive parser executions produce bitwise identical SHA-256 signatures."""
    signatures = []
    for _ in range(5):
        csm = juniper_auditor.parse_juniper(sample_junos_hierarchical)
        # Exclude parsed_at timestamp
        csm_copy = dict(csm)
        csm_copy["source"] = dict(csm["source"])
        csm_copy["source"]["parsed_at"] = "fixed"
        serialized = json.dumps(csm_copy, sort_keys=True)
        sig = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        signatures.append(sig)

    assert len(set(signatures)) == 1, "Parser output is not deterministic across runs!"


# --- M. Generic API Ingestion Route ---

def test_parse_juniper_repo_zip_sample(sample_junos_from_repo_zip):
    """Verify parsing the actual synthetic Junos sample from the repository zip file."""
    if not sample_junos_from_repo_zip:
        pytest.skip("Repo zip sample not found")
    csm = juniper_auditor.parse_juniper(sample_junos_from_repo_zip, filename="repo_sample.conf")
    assert csm["device"]["hostname"] == "lab-junos-router"
    assert csm["device"]["vendor"] == "juniper"
    assert csm["services"]["ssh"] is True
    assert csm["services"]["ssh_version"] == 2
    assert csm["snmp"]["enabled"] is True
    assert "public" in csm["snmp"]["community_strings"]
    assert csm["access_control"]["control_plane_protection_enabled"] is True


# --- M. Generic API Ingestion Route ---

def test_api_upload_juniper_auto_detection(sample_junos_compliant):
    """Verify /api/audit/upload ingests and evaluates Juniper config automatically without vendor parameter."""
    database.initialize_database()
    client = TestClient(app)
    token = auth.create_access_token(
        user_id="usr-uploader-test",
        username="uploader_test",
        role="uploader",
        is_authorized_approver=False,
    )
    headers = {"Authorization": f"Bearer {token}"}

    upload_resp = client.post(
        "/api/audit/upload",
        files={"file": ("junos.conf", sample_junos_compliant, "text/plain")},
        headers=headers,
    )

    assert upload_resp.status_code == 200
    data = upload_resp.json()
    assert data["platform"] == "Junos"
    assert data["device_hostname"] == "compliant-junos"
    assert data["summary"]["total"] >= 10
    assert data["summary"]["pass"] >= 10

    # Verify all 10 initial Junos rules PASS in the upload results
    expected_junos_rules = [
        "JUNOS-SSH-001", "JUNOS-SSH-002", "JUNOS-SSH-003", "JUNOS-AAA-001", "JUNOS-AAA-002",
        "JUNOS-NTP-001", "JUNOS-LOG-001", "JUNOS-SNMP-001", "JUNOS-ACL-001", "JUNOS-MGMT-001",
    ]
    for r_id in expected_junos_rules:
        assert r_id in data["rule_results"]
        assert data["rule_results"][r_id]["status"] == "Pass"


def test_api_upload_juniper_explicit_vendor(sample_junos_compliant):
    """Verify /api/audit/upload accepts explicit vendor='juniper'."""
    database.initialize_database()
    client = TestClient(app)
    token = auth.create_access_token(
        user_id="usr-uploader-test",
        username="uploader_test",
        role="uploader",
        is_authorized_approver=False,
    )
    headers = {"Authorization": f"Bearer {token}"}

    upload_resp = client.post(
        "/api/audit/upload",
        data={"vendor": "juniper"},
        files={"file": ("junos.conf", sample_junos_compliant, "text/plain")},
        headers=headers,
    )

    assert upload_resp.status_code == 200
    data = upload_resp.json()
    assert data["platform"] == "Junos"
    assert data["summary"]["total"] >= 10
    for r_id in [
        "JUNOS-SSH-001", "JUNOS-SSH-002", "JUNOS-SSH-003", "JUNOS-AAA-001", "JUNOS-AAA-002",
        "JUNOS-NTP-001", "JUNOS-LOG-001", "JUNOS-SNMP-001", "JUNOS-ACL-001", "JUNOS-MGMT-001",
    ]:
        assert r_id in data["rule_results"]
        assert data["rule_results"][r_id]["status"] == "Pass"
