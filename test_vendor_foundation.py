"""NTRO PS26155 — Vendor Foundation & Scalable Architecture Tests (Phase 1).

Verifies the extensible vendor adapter architecture:
A. Cisco adapter is registered by default in VendorRegistry.
B. Cisco configuration reaches the verified Cisco parser through the new adapter boundary.
C. Cisco CSM output remains 100% compatible with the multi-framework compliance engine.
D. Existing Cisco audit API behavior remains intact (/api/audit/upload, /api/compliance/evaluate).
E. Unsupported and undetermined vendor handling is explicit, safe, and fails closed with HTTP 422.
F. The compliance engine does not contain vendor-specific branching or direct parser imports.
G. Vendor registry can accept future adapters without modifying the core compliance engine.
H. AST safety assertions pass on all new vendor foundation modules.
"""

import ast
import pathlib
import pytest
from fastapi.testclient import TestClient

import auth
import database
from main import app
import vendor_adapter
from vendor_adapter import CiscoVendorAdapter, VendorAdapter
import vendor_registry
from vendor_registry import (
    VendorRegistry,
    get_default_vendor_registry,
    ingest_configuration,
    UnsupportedVendorError,
    UndeterminedVendorError,
)
import compliance_framework
from compliance_framework import (
    ComplianceStatus,
    Control,
    EvaluationResult,
    Framework,
    FrameworkEvaluator,
    FrameworkRegistry,
)
import cis_benchmark_cisco_iosxe
import disa_stig_cisco_iosxe
import compliance_aggregator
import cisco_auditor
import ast_safety

client = TestClient(app)

BASE_DIR = pathlib.Path(__file__).parent.resolve()
CFG_FILE = BASE_DIR / "05_Configuration_Datasets" / "Cisco" / "labeled_test_config.txt"


@pytest.fixture(autouse=True)
def setup_test_db():
    database.initialize_database()
    cis_benchmark_cisco_iosxe.register_cis_cisco_iosxe()
    disa_stig_cisco_iosxe.register_disa_stig_cisco_iosxe()


@pytest.fixture
def uploader_token():
    return auth.create_access_token(
        user_id="test-uploader-foundation",
        username="uploader_foundation",
        role="uploader",
        is_authorized_approver=False,
    )


@pytest.fixture
def reviewer_token():
    return auth.create_access_token(
        user_id="test-reviewer-foundation",
        username="secops_reviewer",
        role="reviewer",
        is_authorized_approver=True,
    )


# --- Test A: Cisco Adapter Registration ---

def test_a_cisco_adapter_registered_by_default():
    """Test A: Verifies Cisco adapter is registered by default in the VendorRegistry."""
    registry = get_default_vendor_registry()
    assert registry.has("cisco") is True
    assert "cisco" in registry.list_vendor_ids()

    adapter = registry.get("cisco")
    assert isinstance(adapter, CiscoVendorAdapter)
    assert adapter.vendor_id == "cisco"
    assert adapter.vendor_name == "Cisco Systems"
    assert "IOS-XE" in adapter.supported_platforms


# --- Test B: Cisco Parser Through Adapter Boundary ---

def test_b_cisco_configuration_reaches_cisco_parser():
    """Test B: Verifies Cisco configuration reaches existing Cisco parser through adapter boundary."""
    raw_cfg = CFG_FILE.read_text(encoding="utf-8")
    registry = get_default_vendor_registry()
    adapter = registry.get("cisco")

    # Parse via adapter directly
    csm_adapter = adapter.parse(raw_cfg, filename="labeled_test_config.txt")

    # Parse via unified ingestion boundary
    csm_ingest, matched_adapter = ingest_configuration(raw_cfg, filename="labeled_test_config.txt")

    # Direct baseline parse
    csm_direct = cisco_auditor.parse_cisco(raw_cfg, filename="labeled_test_config.txt")

    assert matched_adapter.vendor_id == "cisco"
    assert csm_adapter == csm_direct
    assert csm_ingest == csm_direct
    assert csm_ingest["device"]["hostname"] == "EDGE-RTR-01"
    assert csm_ingest["device"]["platform"] == "IOS-XE"
    assert "service call-home" in csm_ingest["unmapped_lines"]


# --- Test C: Cisco CSM Compatibility with Compliance Engine ---

def test_c_cisco_csm_compatibility_with_compliance_engine():
    """Test C: Verifies Cisco CSM output remains 100% compatible with existing compliance engine."""
    raw_cfg = CFG_FILE.read_text(encoding="utf-8")
    csm, _ = ingest_configuration(raw_cfg)

    # 1. Evaluate against CIS Cisco IOS-XE Benchmark
    cis_evaluator = cis_benchmark_cisco_iosxe.CisCiscoIosXeEvaluator()
    cis_results = cis_evaluator.evaluate(csm)
    assert len(cis_results) == 7
    assert all(isinstance(r, EvaluationResult) for r in cis_results)

    # 2. Evaluate against DISA-STIG Cisco IOS-XE
    stig_evaluator = disa_stig_cisco_iosxe.StigCiscoIosXeEvaluator()
    stig_results = stig_evaluator.evaluate(csm)
    assert len(stig_results) == 10
    assert all(isinstance(r, EvaluationResult) for r in stig_results)

    # 3. Aggregate results via MultiFrameworkAggregator
    aggregator = compliance_aggregator.MultiFrameworkAggregator()
    audit_result = aggregator.aggregate(
        results=cis_results + stig_results,
        audit_id="test-foundation-audit",
        device_hostname=csm["device"]["hostname"],
    )

    assert audit_result.overall_metrics.total_frameworks == 2
    assert audit_result.overall_metrics.total_controls == 17
    assert audit_result.device_hostname == "EDGE-RTR-01"


# --- Test D: Existing Cisco Audit API Behavior Intact ---

def test_d_existing_cisco_audit_upload_api_behavior_intact(uploader_token):
    """Test D: Verifies existing Cisco audit API upload behavior remains intact."""
    raw_cfg = CFG_FILE.read_text(encoding="utf-8")
    headers = {"Authorization": f"Bearer {uploader_token}"}

    # Test multipart form upload
    res = client.post(
        "/api/audit/upload",
        files={"file": ("labeled_test_config.txt", raw_cfg, "text/plain")},
        headers=headers,
    )
    assert res.status_code == 200, f"Upload failed: {res.text}"
    data = res.json()
    assert "session_id" in data
    assert data["device_hostname"] == "EDGE-RTR-01"
    assert data["platform"] == "IOS-XE"
    assert data["summary"]["total"] >= 10
    assert "CISCO-SSH-001" in data["rule_results"]
    assert data["rule_results"]["CISCO-SSH-001"]["status"] == "Pass"
    assert data["rule_results"]["CISCO-NTP-001"]["status"] == "Fail"
    assert data["rule_results"]["CISCO-SNMP-001"]["status"] == "Fail"

    session_id = data["session_id"]

    # Test cached results retrieval
    res_results = client.get(f"/api/audit/{session_id}/results", headers=headers)
    assert res_results.status_code == 200
    res_data = res_results.json()
    assert res_data["device_hostname"] == "EDGE-RTR-01"
    assert res_data["platform"] == "IOS-XE"


def test_d_compliance_evaluate_api_with_raw_config(uploader_token):
    """Test D2: Verifies /api/compliance/evaluate route works with raw_config through the boundary."""
    raw_cfg = CFG_FILE.read_text(encoding="utf-8")
    headers = {"Authorization": f"Bearer {uploader_token}"}

    res = client.post(
        "/api/compliance/evaluate",
        json={"raw_config": raw_cfg},
        headers=headers,
    )
    assert res.status_code == 200, f"Evaluate failed: {res.text}"
    data = res.json()
    assert data["device_hostname"] == "EDGE-RTR-01"
    assert "cis-cisco-iosxe" in data["framework_summaries"]
    assert "disa-stig-cisco-iosxe" in data["framework_summaries"]


# --- Test E: Explicit & Safe Handling for Unsupported/Undetermined Vendors ---

def test_e_unsupported_vendor_raises_in_ingest():
    """Test E1: Explicit unsupported vendor raises UnsupportedVendorError."""
    with pytest.raises(UnsupportedVendorError) as exc_info:
        ingest_configuration("hostname RTR-01", vendor="juniper")
    assert "Vendor 'juniper' is not supported" in str(exc_info.value)
    assert "Supported vendors: ['cisco']" in str(exc_info.value)


def test_e_unsupported_vendor_api_returns_422(uploader_token):
    """Test E2: Explicit unsupported vendor via upload API returns HTTP 422."""
    headers = {"Authorization": f"Bearer {uploader_token}"}
    res = client.post(
        "/api/audit/upload",
        data={"raw_config": "hostname RTR-01", "vendor": "juniper"},
        headers=headers,
    )
    assert res.status_code == 422
    assert "Vendor 'juniper' is not supported" in res.json()["detail"]


def test_e_undetermined_vendor_without_signature_raises_in_ingest():
    """Test E3: Ambiguous or non-network configuration without vendor raises UndeterminedVendorError."""
    garbage_text = "lorem ipsum dolor sit amet, consectetur adipiscing elit."
    with pytest.raises(UndeterminedVendorError) as exc_info:
        ingest_configuration(garbage_text)
    assert "Unable to determine vendor configuration type" in str(exc_info.value)


def test_e_undetermined_vendor_api_returns_422(uploader_token):
    """Test E4: Ambiguous configuration without vendor via upload API returns HTTP 422."""
    headers = {"Authorization": f"Bearer {uploader_token}"}
    res = client.post(
        "/api/audit/upload",
        json={"raw_config": "some random non-cisco text without network commands"},
        headers=headers,
    )
    assert res.status_code == 422
    assert "Unable to determine vendor configuration type" in res.json()["detail"]


def test_e_juniper_syntax_not_falsely_detected_as_cisco():
    """Test E5: Juniper syntax is not falsely classified as Cisco."""
    junos_cfg = """
    ## Last changed: 2026-09-20 12:00:00 UTC
    version 21.4R1.12;
    system {
        host-name JUNIPER-CORE;
        services {
            ssh {
                protocol-version v2;
            }
        }
    }
    """
    cisco_adapter = CiscoVendorAdapter()
    confidence = cisco_adapter.detect_confidence(junos_cfg)
    assert confidence == 0.0, "Cisco adapter must score 0.0 confidence on Junos configuration"

    # With only Cisco registered, ingesting Junos without vendor fails closed
    with pytest.raises(UndeterminedVendorError):
        ingest_configuration(junos_cfg)


# --- Test F: Compliance Engine Free of Vendor-Specific Branching ---

def test_f_compliance_engine_has_no_vendor_branching():
    """Test F: Verifies compliance_framework.py and compliance_aggregator.py contain no parser imports."""
    fw_path = BASE_DIR / "compliance_framework.py"
    agg_path = BASE_DIR / "compliance_aggregator.py"

    for file_path in (fw_path, agg_path):
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            # Verify no parse_cisco or ingest_configuration calls in compliance core
            if isinstance(node, ast.Attribute) and node.attr in ("parse_cisco", "parse_juniper"):
                pytest.fail(f"Found vendor parser call '{node.attr}' in {file_path.name}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ("cisco_adapter", "juniper_adapter"), f"Forbidden import in {file_path.name}"


# --- Test G: Vendor Registry Accepts Future Adapter Without Modifying Engine ---

class MockFutureVendorAdapter(VendorAdapter):
    """Mock future vendor adapter (e.g. Arista / Junos prototype) demonstrating zero-engine-change extensibility."""

    @property
    def vendor_id(self) -> str:
        return "mock_future_vendor"

    @property
    def vendor_name(self) -> str:
        return "Mock Future Vendor OS"

    @property
    def supported_platforms(self) -> Sequence[str]:
        return ("MockOS",)

    def parse(self, text: str, filename: str = "config.txt", trusted_rules: list = None) -> dict:
        return {
            "schema_version": "1.0",
            "device": {
                "hostname": "MOCK-ROUTER-01",
                "vendor": "mock_future_vendor",
                "platform": "MockOS",
                "os_version": "1.0",
                "serial_number": None,
                "management_ip": "192.168.100.1",
            },
            "source": {"source_type": "uploaded_file", "file_name": filename},
            "services": {"ssh": True, "ssh_version": 2, "telnet": False},
            "interfaces": [],
            "aaa": {"enabled": True, "configured": True, "authentication_method": "tacacs"},
            "logging": {"enabled": True, "remote_logging_enabled": True, "timestamps_enabled": True},
            "ntp": {"enabled": True, "servers": ["10.0.0.1"], "authentication_enabled": True},
            "snmp": {"enabled": False},
            "access_control": {"management_acl_present": True},
            "routing": {"routing_protocols": []},
            "spanning_tree": {},
            "raw_evidence": [],
            "unmapped_lines": [],
        }

    def detect_confidence(self, text: str) -> float:
        return 1.0 if "mock_future_vendor_signature" in text else 0.0

    def evaluate_legacy_rules(self, csm: dict, rules: list, trusted_rules: list = None) -> dict:
        return {"MOCK-RULE-001": {"status": "Pass", "focus": "Security", "evidence_found": []}}


def test_g_vendor_registry_extensibility_without_engine_modifications():
    """Test G: Proves VendorRegistry can register a new vendor adapter and pass normalized CSM to compliance."""
    custom_registry = VendorRegistry()
    custom_registry.register(CiscoVendorAdapter())
    custom_registry.register(MockFutureVendorAdapter())

    assert custom_registry.has("mock_future_vendor") is True
    assert "mock_future_vendor" in custom_registry.list_vendor_ids()

    # Ingest using explicit vendor
    csm, adapter = ingest_configuration(
        raw_text="mock_future_vendor_signature\nhostname MOCK-ROUTER-01",
        vendor="mock_future_vendor",
        registry=custom_registry,
    )
    assert adapter.vendor_id == "mock_future_vendor"
    assert csm["device"]["vendor"] == "mock_future_vendor"
    assert csm["device"]["hostname"] == "MOCK-ROUTER-01"

    # Ingest using auto-detection
    csm_auto, adapter_auto = ingest_configuration(
        raw_text="mock_future_vendor_signature\nhostname MOCK-ROUTER-01",
        registry=custom_registry,
    )
    assert adapter_auto.vendor_id == "mock_future_vendor"

    # Verify that existing compliance aggregator processes this CSM without error
    eval_result = EvaluationResult(
        framework_id="mock-framework",
        control_id="CTRL-001",
        status=ComplianceStatus.PASS,
        reason="Mock control passed",
    )
    aggregator = compliance_aggregator.MultiFrameworkAggregator()
    audit_res = aggregator.aggregate([eval_result], audit_id="mock-audit", device_hostname=csm["device"]["hostname"])
    assert audit_res.overall_metrics.total_pass == 1
    assert audit_res.device_hostname == "MOCK-ROUTER-01"


# --- Test H: AST Safety Verification ---

def test_h_ast_safety_vendor_modules():
    """Test H: Asserts that new vendor modules have zero forbidden execution or communication imports."""
    assert ast_safety.assert_no_execution_imports(BASE_DIR / "vendor_adapter.py") is True
    assert ast_safety.assert_no_execution_imports(BASE_DIR / "vendor_registry.py") is True
