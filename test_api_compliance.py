"""NTRO PS26155 — Multi-Framework Compliance REST API Tests (Phase 3A.5).

Verifies:
1. Discovery Endpoint (GET /api/compliance/frameworks):
   - Returns list of registered compliance frameworks with complete metadata.
   - Accurately reports control counts and severity distributions for CIS and DISA-STIG.
   - Fails closed with 401 on unauthenticated or invalid tokens.
   - Authorizes viewer, uploader, and reviewer roles.

2. Evaluation Endpoint (POST /api/compliance/evaluate):
   - Accepts session_id with strict resource ownership enforcement (check_session_ownership).
   - Enforces anti-enumeration: Uploader A cannot evaluate Uploader B's session (HTTP 404).
   - Grants global evaluation access to reviewer role.
   - Accepts direct pre-parsed normalized CSM payload.
   - Accepts raw configuration string payload with automatic CSM parsing.
   - Validates framework_ids filter and rejects unknown frameworks with HTTP 422.
   - Fails closed with 422 when required payload fields are missing.
   - Preserves UNKNOWN verdicts without conflating them with FAIL.
   - Demonstrates strict determinism (repeated evaluations yield identical outputs).

3. Clean Architecture & Security Invariants:
   - Verifies AST safety assertion (zero subprocess, socket, paramiko, or shell imports).
   - Verifies router remains a thin orchestration layer with zero AI/LLM calls.
"""

import ast
import pathlib
import uuid
import pytest
from fastapi.testclient import TestClient

import auth
import database
import main
from main import app, verify_api_safety_no_execution
import compliance_framework
import cis_benchmark_cisco_iosxe
import disa_stig_cisco_iosxe
import compliance_aggregator

client = TestClient(app)

SAMPLE_RAW_CONFIG = """
hostname EDGE-RTR-01
!
ip ssh version 2
!
aaa new-model
aaa authentication login default group tacacs+ local
!
logging host 192.168.1.50
logging trap informational
!
ntp server 192.168.1.1
!
snmp-server community Secur3Comm RO
!
interface GigabitEthernet0/0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
line vty 0 4
 transport input ssh
 access-class 10 in
!
router bgp 65000
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.2 password SecureBgpPassword123
!
end
"""

import cisco_auditor

SAMPLE_COMPLIANT_CSM = cisco_auditor.parse_cisco(SAMPLE_RAW_CONFIG)



@pytest.fixture(autouse=True)
def setup_environment():
    database.initialize_database()
    # Ensure default frameworks are registered
    cis_benchmark_cisco_iosxe.register_cis_cisco_iosxe()
    disa_stig_cisco_iosxe.register_disa_stig_cisco_iosxe()


@pytest.fixture
def uploader_a_token():
    return auth.create_access_token(
        user_id="usr-uploader-a",
        username="uploader_alice",
        role="uploader",
        is_authorized_approver=False,
    )


@pytest.fixture
def uploader_b_token():
    return auth.create_access_token(
        user_id="usr-uploader-b",
        username="uploader_bob",
        role="uploader",
        is_authorized_approver=False,
    )


@pytest.fixture
def reviewer_token():
    return auth.create_access_token(
        user_id="usr-reviewer-01",
        username="secops_reviewer",
        role="reviewer",
        is_authorized_approver=True,
    )


@pytest.fixture
def viewer_token():
    return auth.create_access_token(
        user_id="usr-viewer-01",
        username="compliance_viewer",
        role="viewer",
        is_authorized_approver=False,
    )


def create_uploaded_session(token: str, raw_config: str = SAMPLE_RAW_CONFIG) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post(
        "/api/audit/upload",
        json={"raw_config": raw_config, "filename": "test_rtr.cfg"},
        headers=headers,
    )
    assert res.status_code == 200, f"Session creation failed: {res.text}"
    return res.json()["session_id"]


# ==============================================================================
# 1. Framework Discovery Endpoint (GET /api/compliance/frameworks)
# ==============================================================================

class TestComplianceFrameworkDiscovery:
    """Verifies framework catalog discovery, metadata extraction, and control metrics."""

    def test_get_frameworks_unauthenticated_fails_401(self):
        res = client.get("/api/compliance/frameworks")
        assert res.status_code == 401
        assert "Missing Authorization header" in res.text

    def test_get_frameworks_invalid_token_fails_401(self):
        res = client.get(
            "/api/compliance/frameworks",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert res.status_code == 401

    def test_get_frameworks_viewer_role_authorized(self, viewer_token):
        res = client.get(
            "/api/compliance/frameworks",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "frameworks" in data
        assert "total_count" in data
        assert data["total_count"] >= 2

    def test_get_frameworks_uploader_role_authorized(self, uploader_a_token):
        res = client.get(
            "/api/compliance/frameworks",
            headers={"Authorization": f"Bearer {uploader_a_token}"},
        )
        assert res.status_code == 200

    def test_get_frameworks_reviewer_role_authorized(self, reviewer_token):
        res = client.get(
            "/api/compliance/frameworks",
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200

    def test_get_frameworks_metadata_and_control_metrics(self, viewer_token):
        res = client.get(
            "/api/compliance/frameworks",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        fids = {f["framework_id"]: f for f in data["frameworks"]}

        # Check CIS Framework
        assert "cis-cisco-iosxe" in fids
        cis = fids["cis-cisco-iosxe"]
        assert cis["name"] == "CIS Cisco IOS XE 17.x Benchmark"
        assert cis["version"] == "v2.2.1"
        assert cis["vendor_scope"] == "Cisco IOS-XE"
        assert cis["control_namespace"] == "CIS"
        assert cis["control_count"] == 7
        assert isinstance(cis["severity_distribution"], dict)
        assert sum(cis["severity_distribution"].values()) == 7
        assert cis["enabled"] is True

        # Check DISA-STIG Framework
        assert "disa-stig-cisco-iosxe" in fids
        stig = fids["disa-stig-cisco-iosxe"]
        assert stig["name"] == "DISA STIG Cisco IOS XE Benchmark"
        assert stig["version"] == "V3R7"
        assert stig["vendor_scope"] == "Cisco IOS-XE"
        assert stig["control_namespace"] == "DISA-STIG"
        assert stig["control_count"] == 10
        assert isinstance(stig["severity_distribution"], dict)
        assert sum(stig["severity_distribution"].values()) == 10
        assert stig["enabled"] is True


# ==============================================================================
# 2. Evaluation Endpoint Payload Variants (POST /api/compliance/evaluate)
# ==============================================================================

class TestComplianceEvaluatePayloads:
    """Verifies evaluation execution with different input payload forms."""

    def test_evaluate_unauthenticated_fails_401(self):
        res = client.post("/api/compliance/evaluate", json={"raw_config": SAMPLE_RAW_CONFIG})
        assert res.status_code == 401

    def test_evaluate_invalid_token_fails_401(self):
        res = client.post(
            "/api/compliance/evaluate",
            json={"raw_config": SAMPLE_RAW_CONFIG},
            headers={"Authorization": "Bearer corrupt.token"},
        )
        assert res.status_code == 401

    def test_evaluate_empty_payload_fails_422(self, viewer_token):
        res = client.post(
            "/api/compliance/evaluate",
            json={},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 422
        assert "One of session_id, csm, or raw_config must be provided" in res.text

    def test_evaluate_with_csm(self, viewer_token):
        res = client.post(
            "/api/compliance/evaluate",
            json={"csm": SAMPLE_COMPLIANT_CSM},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()

        assert data["device_hostname"] == "EDGE-RTR-01"
        assert "framework_summaries" in data
        assert "cis-cisco-iosxe" in data["framework_summaries"]
        assert "disa-stig-cisco-iosxe" in data["framework_summaries"]

        # CIS summary check
        cis_summary = data["framework_summaries"]["cis-cisco-iosxe"]
        assert cis_summary["total_controls"] == 7
        assert cis_summary["pass_count"] >= 5
        assert len(cis_summary["results"]) == 7

        # STIG summary check
        stig_summary = data["framework_summaries"]["disa-stig-cisco-iosxe"]
        assert stig_summary["total_controls"] == 10
        assert stig_summary["pass_count"] >= 5
        assert len(stig_summary["results"]) == 10

        # Overall metrics check
        overall = data["overall_metrics"]
        assert overall["total_frameworks"] == 2
        assert overall["total_controls"] == 17
        assert overall["total_pass"] == cis_summary["pass_count"] + stig_summary["pass_count"]
        assert overall["total_fail"] == cis_summary["fail_count"] + stig_summary["fail_count"]
        assert overall["total_unknown"] == cis_summary["unknown_count"] + stig_summary["unknown_count"]

        # Consolidated evidence check
        assert len(data["consolidated_evidence"]) == 17

    def test_evaluate_with_raw_config(self, viewer_token):
        res = client.post(
            "/api/compliance/evaluate",
            json={"raw_config": SAMPLE_RAW_CONFIG},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["device_hostname"] == "EDGE-RTR-01"
        assert "cis-cisco-iosxe" in data["framework_summaries"]
        assert "disa-stig-cisco-iosxe" in data["framework_summaries"]
        assert data["overall_metrics"]["total_controls"] == 17

    def test_evaluate_with_session_id(self, uploader_a_token):
        session_id = create_uploaded_session(uploader_a_token)
        res = client.post(
            "/api/compliance/evaluate",
            json={"session_id": session_id},
            headers={"Authorization": f"Bearer {uploader_a_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["audit_id"] == session_id
        assert data["device_hostname"] == "EDGE-RTR-01"
        assert data["overall_metrics"]["total_controls"] == 17


# ==============================================================================
# 3. Session Ownership & Anti-Enumeration Isolation
# ==============================================================================

class TestComplianceEvaluateOwnershipIsolation:
    """Verifies strict resource ownership enforcement on session-backed evaluations."""

    def test_uploader_b_cannot_evaluate_uploader_a_session(self, uploader_a_token, uploader_b_token):
        session_id = create_uploaded_session(uploader_a_token)

        # Uploader B attempts cross-tenant evaluation
        res = client.post(
            "/api/compliance/evaluate",
            json={"session_id": session_id},
            headers={"Authorization": f"Bearer {uploader_b_token}"},
        )
        # Anti-enumeration invariant: Returns 404, NOT 403
        assert res.status_code == 404
        assert f"Session '{session_id}' not found" in res.text

    def test_nonexistent_session_returns_identical_404(self, uploader_b_token):
        fake_session_id = str(uuid.uuid4())
        res = client.post(
            "/api/compliance/evaluate",
            json={"session_id": fake_session_id},
            headers={"Authorization": f"Bearer {uploader_b_token}"},
        )
        assert res.status_code == 404
        assert f"Session '{fake_session_id}' not found" in res.text

    def test_reviewer_can_evaluate_any_uploader_session(self, uploader_a_token, reviewer_token):
        session_id = create_uploaded_session(uploader_a_token)

        # Reviewer has global access
        res = client.post(
            "/api/compliance/evaluate",
            json={"session_id": session_id},
            headers={"Authorization": f"Bearer {reviewer_token}"},
        )
        assert res.status_code == 200
        assert res.json()["audit_id"] == session_id


# ==============================================================================
# 4. Framework Filtering & Selection
# ==============================================================================

class TestComplianceEvaluateFrameworkFiltering:
    """Verifies framework_ids parameter correctly filters evaluators."""

    def test_evaluate_only_cis(self, viewer_token):
        res = client.post(
            "/api/compliance/evaluate",
            json={
                "csm": SAMPLE_COMPLIANT_CSM,
                "framework_ids": ["cis-cisco-iosxe"]
            },
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "cis-cisco-iosxe" in data["framework_summaries"]
        assert "disa-stig-cisco-iosxe" not in data["framework_summaries"]
        assert data["overall_metrics"]["total_frameworks"] == 1
        assert data["overall_metrics"]["total_controls"] == 7

    def test_evaluate_only_disa_stig(self, viewer_token):
        res = client.post(
            "/api/compliance/evaluate",
            json={
                "csm": SAMPLE_COMPLIANT_CSM,
                "framework_ids": ["disa-stig-cisco-iosxe"]
            },
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "disa-stig-cisco-iosxe" in data["framework_summaries"]
        assert "cis-cisco-iosxe" not in data["framework_summaries"]
        assert data["overall_metrics"]["total_frameworks"] == 1
        assert data["overall_metrics"]["total_controls"] == 10

    def test_evaluate_unknown_framework_fails_422(self, viewer_token):
        res = client.post(
            "/api/compliance/evaluate",
            json={
                "csm": SAMPLE_COMPLIANT_CSM,
                "framework_ids": ["unknown-standard-2026"]
            },
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 422
        assert "Framework 'unknown-standard-2026' is not registered" in res.text


# ==============================================================================
# 5. Determinism & UNKNOWN Verdict Preservation
# ==============================================================================

class TestComplianceEvaluateDeterminismAndUnknowns:
    """Verifies deterministic output repeatability and preservation of UNKNOWN states."""

    def test_evaluate_deterministic_repeatability(self, viewer_token):
        headers = {"Authorization": f"Bearer {viewer_token}"}
        payload = {"csm": SAMPLE_COMPLIANT_CSM}

        res1 = client.post("/api/compliance/evaluate", json=payload, headers=headers)
        res2 = client.post("/api/compliance/evaluate", json=payload, headers=headers)

        assert res1.status_code == 200
        assert res2.status_code == 200

        data1 = res1.json()
        data2 = res2.json()

        # Overall metrics must be identical
        assert data1["overall_metrics"] == data2["overall_metrics"]
        assert data1["framework_summaries"]["cis-cisco-iosxe"]["pass_count"] == \
               data2["framework_summaries"]["cis-cisco-iosxe"]["pass_count"]
        assert data1["framework_summaries"]["disa-stig-cisco-iosxe"]["pass_count"] == \
               data2["framework_summaries"]["disa-stig-cisco-iosxe"]["pass_count"]

    def test_evaluate_preserves_unknown_verdicts(self, viewer_token):
        # Empty device with no configured services
        bare_csm = {
            "device": {"hostname": "EMPTY-DEVICE", "vendor": "cisco"},
            "management": {},
            "aaa": {},
            "logging": {},
            "ntp": {},
            "snmp": {},
            "access_control": {},
            "routing": {}
        }
        res = client.post(
            "/api/compliance/evaluate",
            json={"csm": bare_csm},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()

        # Unconfigured services return UNKNOWN, not conflated with FAIL
        overall = data["overall_metrics"]
        assert overall["total_unknown"] > 0
        assert overall["total_controls"] == 17

        # Check evidence preservation
        unknown_evidences = [
            e for e in data["consolidated_evidence"] if e["status"].upper() == "UNKNOWN"
        ]
        assert len(unknown_evidences) > 0
        for ev in unknown_evidences:
            assert ev["status"].upper() == "UNKNOWN"
            assert isinstance(ev["rationale"], str) and len(ev["rationale"].strip()) > 0


# ==============================================================================
# 6. AST & Clean Architecture Security Invariants
# ==============================================================================

class TestComplianceSecurityASTInvariants:
    """Verifies that the API layer maintains clean boundaries and zero execution imports."""

    def test_main_py_safety_ast(self):
        """Asserts main.py passes execution-free AST safety checks."""
        assert verify_api_safety_no_execution() is True

    def test_zero_network_or_process_in_compliance_modules(self):
        """Verifies that all Phase 3 compliance modules contain zero process/socket libraries."""
        forbidden = {"subprocess", "socket", "paramiko", "netmiko", "pexpect", "telnetlib", "ollama"}
        modules_to_check = [
            "main.py",
            "compliance_framework.py",
            "cis_benchmark_cisco_iosxe.py",
            "disa_stig_cisco_iosxe.py",
            "compliance_aggregator.py",
        ]
        for mod_name in modules_to_check:
            mod_path = pathlib.Path(__file__).parent / mod_name
            assert mod_path.exists(), f"Module {mod_name} must exist"
            tree = ast.parse(mod_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for n in node.names:
                        assert n.name not in forbidden, f"Forbidden import '{n.name}' in {mod_name}"
                elif isinstance(node, ast.ImportFrom):
                    assert node.module not in forbidden, f"Forbidden from-import '{node.module}' in {mod_name}"


# ==============================================================================
# 7. Phase 3C: Vendor-Aware Framework Auto-Selection & Discovery (Chunk 4)
# ==============================================================================

class TestVendorAwareComplianceAPI:
    """Verifies vendor-scoped framework auto-selection, cross-vendor rejection,
    and vendor-filtered discovery.
    """

    SAMPLE_JUNIPER_CSM = {
        "schema_version": "1.0",
        "device": {
            "hostname": "JUNIPER-CORE-01",
            "vendor": "juniper",
            "platform": "Junos",
            "os_version": "21.4R1",
        },
        "interfaces": [],
        "services": {"ssh": True, "ssh_version": 2, "telnet": False},
        "management": {},
        "aaa": {},
        "logging": {},
        "ntp": {},
        "snmp": {},
        "access_control": {},
        "routing": {},
    }

    def test_auto_selection_cisco_evaluates_only_cisco_frameworks(self, viewer_token):
        """When framework_ids is None, a Cisco CSM auto-evaluates only Cisco frameworks."""
        res = client.post(
            "/api/compliance/evaluate",
            json={"csm": SAMPLE_COMPLIANT_CSM},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "cis-cisco-iosxe" in data["framework_summaries"]
        assert "disa-stig-cisco-iosxe" in data["framework_summaries"]
        assert data["overall_metrics"]["total_frameworks"] == 2
        assert data["overall_metrics"]["total_controls"] == 17

    def test_auto_selection_juniper_does_not_evaluate_cisco_frameworks(self, viewer_token):
        """When framework_ids is None, a Juniper CSM does not evaluate any Cisco frameworks."""
        reg = compliance_framework.get_default_registry()
        had_juniper = reg.exists("juniper-junos-baseline")
        if had_juniper:
            reg.unregister("juniper-junos-baseline")

        try:
            res = client.post(
                "/api/compliance/evaluate",
                json={"csm": self.SAMPLE_JUNIPER_CSM},
                headers={"Authorization": f"Bearer {viewer_token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert "cis-cisco-iosxe" not in data["framework_summaries"]
            assert "disa-stig-cisco-iosxe" not in data["framework_summaries"]
            assert data["overall_metrics"]["total_frameworks"] == 0
            assert data["overall_metrics"]["total_controls"] == 0
        finally:
            if had_juniper:
                import juniper_auditor
                juniper_auditor.register_juniper_baseline(reg)

    def test_auto_selection_juniper_evaluates_juniper_framework_when_registered(self, viewer_token):
        """When Juniper baseline is registered, Juniper CSM auto-selects only Juniper framework."""
        import juniper_auditor
        reg = compliance_framework.get_default_registry()
        juniper_auditor.register_juniper_baseline(reg)

        try:
            res = client.post(
                "/api/compliance/evaluate",
                json={"csm": self.SAMPLE_JUNIPER_CSM},
                headers={"Authorization": f"Bearer {viewer_token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert "juniper-junos-baseline" in data["framework_summaries"]
            assert "cis-cisco-iosxe" not in data["framework_summaries"]
            assert "disa-stig-cisco-iosxe" not in data["framework_summaries"]
            assert data["overall_metrics"]["total_frameworks"] == 1
            assert data["overall_metrics"]["total_controls"] == 10
        finally:
            reg.unregister("juniper-junos-baseline")

    def test_explicit_cisco_framework_on_juniper_rejected_422(self, viewer_token):
        """Client attempting to evaluate cis-cisco-iosxe on Juniper CSM is rejected with HTTP 422."""
        res = client.post(
            "/api/compliance/evaluate",
            json={
                "csm": self.SAMPLE_JUNIPER_CSM,
                "framework_ids": ["cis-cisco-iosxe"],
            },
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 422
        assert "not compatible with vendor 'juniper'" in res.text

    def test_explicit_disa_stig_framework_on_juniper_rejected_422(self, viewer_token):
        """Client attempting to evaluate disa-stig-cisco-iosxe on Juniper CSM is rejected with HTTP 422."""
        res = client.post(
            "/api/compliance/evaluate",
            json={
                "csm": self.SAMPLE_JUNIPER_CSM,
                "framework_ids": ["disa-stig-cisco-iosxe"],
            },
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 422
        assert "not compatible with vendor 'juniper'" in res.text

    def test_explicit_disabled_framework_fails_422(self, viewer_token):
        """Attempting to evaluate a registered but disabled framework fails with HTTP 422."""
        reg = compliance_framework.get_default_registry()
        disabled_fw = compliance_framework.Framework(
            framework_id="disabled-framework-test",
            name="Disabled Framework Test",
            version="1.0",
            vendor_scope="Cisco IOS-XE",
            control_namespace="DISABLED",
            enabled=False,
        )
        reg.register(disabled_fw, allow_replace=True)

        try:
            res = client.post(
                "/api/compliance/evaluate",
                json={
                    "csm": SAMPLE_COMPLIANT_CSM,
                    "framework_ids": ["disabled-framework-test"],
                },
                headers={"Authorization": f"Bearer {viewer_token}"},
            )
            assert res.status_code == 422
            assert "is disabled" in res.text
        finally:
            reg.unregister("disabled-framework-test")

    def test_framework_discovery_without_vendor_returns_all(self, viewer_token):
        """GET /api/compliance/frameworks without vendor returns all registered frameworks."""
        res = client.get(
            "/api/compliance/frameworks",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        fids = [f["framework_id"] for f in data["frameworks"]]
        assert "cis-cisco-iosxe" in fids
        assert "disa-stig-cisco-iosxe" in fids
        assert data["total_count"] >= 2

    def test_framework_discovery_vendor_cisco(self, viewer_token):
        """GET /api/compliance/frameworks?vendor=cisco returns only Cisco-scoped frameworks."""
        res = client.get(
            "/api/compliance/frameworks?vendor=cisco",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total_count"] >= 2
        for fw in data["frameworks"]:
            assert "cisco" in fw["vendor_scope"].lower()

    def test_framework_discovery_vendor_juniper(self, viewer_token):
        """GET /api/compliance/frameworks?vendor=juniper returns only Juniper-scoped frameworks."""
        reg = compliance_framework.get_default_registry()
        import juniper_auditor
        juniper_auditor.register_juniper_baseline(reg)

        try:
            res = client.get(
                "/api/compliance/frameworks?vendor=juniper",
                headers={"Authorization": f"Bearer {viewer_token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["total_count"] >= 1
            for fw in data["frameworks"]:
                assert "juniper" in fw["vendor_scope"].lower()
                assert fw["framework_id"] != "cis-cisco-iosxe"
                assert fw["framework_id"] != "disa-stig-cisco-iosxe"
        finally:
            reg.unregister("juniper-junos-baseline")

    def test_framework_discovery_vendor_unknown_returns_empty(self, viewer_token):
        """GET /api/compliance/frameworks?vendor=nonexistent returns empty list."""
        res = client.get(
            "/api/compliance/frameworks?vendor=nonexistent_vendor_xyz",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total_count"] == 0
        assert data["frameworks"] == []

    def test_auto_selection_deterministic_repeatability(self, viewer_token):
        """Repeated auto-selection evaluations produce identical metrics and evidence."""
        headers = {"Authorization": f"Bearer {viewer_token}"}
        payload = {"csm": SAMPLE_COMPLIANT_CSM}

        res1 = client.post("/api/compliance/evaluate", json=payload, headers=headers)
        res2 = client.post("/api/compliance/evaluate", json=payload, headers=headers)

        assert res1.status_code == 200
        assert res2.status_code == 200

        data1 = res1.json()
        data2 = res2.json()

        assert data1["overall_metrics"] == data2["overall_metrics"]
        assert len(data1["consolidated_evidence"]) == len(data2["consolidated_evidence"])
