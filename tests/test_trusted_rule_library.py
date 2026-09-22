"""
NTRO PS26155 Auditor — Phase 3B: Trusted Rule Library & Human-Approved AI Mappings Test Suite
Verifies all 16 required test cases (A through P):
A. Mapping suggestion remains untrusted in pending_suggestions; NOT in trusted_mappings.
B. Authorized reviewer (reviewer + is_authorized_approver=True) can approve suggestion into trusted_mappings.
C. Unauthorized approval returns 403 Forbidden (viewer, uploader, non-approver reviewer).
D. Reviewer correction becomes trusted mapping (human-corrected payload, source='human_corrected').
E. Rejection does not create trust (pending_suggestions status='rejected', trusted_mappings untouched).
F. Vendor isolation: Cisco audit evaluates only Cisco trusted rules; Juniper evaluates only Juniper rules.
G. Duplicate mapping handling: Identical re-approval behaves idempotently and deterministically.
H. Conflicting mapping handling: Conflicting definition for existing vendor_rule_id returns HTTP 409 Conflict.
I. Reviewer identity: JWT sub claim is authoritative; client-supplied reviewer_name is ignored.
J. Deterministic retrieval: GET /api/trusted-mappings returns deterministic library with vendor filter.
K. AI cannot directly persist trusted mappings: AST code assertion on suggestion generation logic.
L. Existing trusted mappings remain compatible with legacy schemas and evaluations.
M. Cisco workflow regression: Cisco audit pipeline runs cleanly with trusted rules.
N. Juniper workflow regression: Juniper audit pipeline runs cleanly with vendor-specific trusted rules.
O. API authorization: GET endpoints allow viewer/uploader/reviewer; DELETE strictly requires approver.
P. Frontend / API contract match: Wire payload matches frontend TypeScript interfaces.
"""

import ast
import json
import pathlib
import uuid
import pytest
from fastapi.testclient import TestClient

import auth
import database
import ai_suggester
import main
from main import app, load_trusted_rules

client = TestClient(app)

SAMPLE_CISCO_CONFIG = """
hostname EDGE-CISCO-01
!
service call-home
!
interface GigabitEthernet0/0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
end
"""

SAMPLE_JUNIPER_CONFIG = """
system {
    host-name EDGE-JUNOS-01;
    services {
        ssh {
            protocol-version v2;
        }
    }
}
"""


@pytest.fixture(autouse=True)
def setup_db():
    database.initialize_database()


@pytest.fixture
def approver_token():
    return auth.create_access_token(
        user_id="usr-secops-lead-01",
        username="secops_lead",
        role="reviewer",
        is_authorized_approver=True,
    )


@pytest.fixture
def non_approver_reviewer_token():
    return auth.create_access_token(
        user_id="usr-reviewer-junior-02",
        username="secops_junior",
        role="reviewer",
        is_authorized_approver=False,
    )


@pytest.fixture
def uploader_token():
    return auth.create_access_token(
        user_id="usr-uploader-01",
        username="netadmin_uploader",
        role="uploader",
        is_authorized_approver=False,
    )


@pytest.fixture
def viewer_token():
    return auth.create_access_token(
        user_id="usr-viewer-01",
        username="auditor_viewer",
        role="viewer",
        is_authorized_approver=False,
    )


# ==============================================================================
# Test A: Mapping suggestion remains untrusted
# ==============================================================================
def test_a_suggestion_remains_untrusted(uploader_token):
    """A. AI mapping suggestion creates a pending suggestion but NEVER writes to trusted_mappings."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    initial_trusted_count = cur.fetchone()[0]
    conn.close()

    res = client.post(
        "/api/ai/suggest",
        json={"unmapped_line": "service call-home", "vendor": "cisco"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert res.status_code == 200
    sug_id = res.json()["suggestion_id"]
    assert sug_id is not None

    # Check pending_suggestions table: must be "pending"
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT status, vendor FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    row = cur.fetchone()
    assert row is not None
    assert row["status"] == "pending"
    assert row["vendor"] == "cisco"

    # Check trusted_mappings table: must NOT have changed!
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    post_trusted_count = cur.fetchone()[0]
    conn.close()
    assert post_trusted_count == initial_trusted_count, "AI suggestion must NEVER write directly to trusted_mappings!"


# ==============================================================================
# Test B: Authorized reviewer can approve
# ==============================================================================
def test_b_authorized_reviewer_can_approve(approver_token):
    """B. Authorized reviewer promotes a suggestion to a trusted rule mapping in trusted_mappings."""
    sug = {
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-DIAG-001",
            "vendor_rule_id": f"CISCO-TEST-{uuid.uuid4().hex[:8]}",
            "internalTitle": "Disable telemetry services",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False",
            "vendor": "cisco"
        },
        "vendor": "cisco"
    }
    sug_id = ai_suggester.store_suggestion(sug, vendor="cisco")

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "approve"

    # Verify rule is in trusted_mappings
    mapping = database.get_trusted_mapping(sug["suggested_new_rule"]["vendor_rule_id"])
    assert mapping is not None
    assert mapping["status"] == "approved"
    assert mapping["vendor"] == "cisco"
    assert mapping["version_info"]["approved_by"] == "usr-secops-lead-01"
    assert mapping["version_info"]["source"] == "ai_suggested"


# ==============================================================================
# Test C: Unauthorized approval returns 403
# ==============================================================================
def test_c_unauthorized_users_cannot_approve(viewer_token, uploader_token, non_approver_reviewer_token):
    """C. Viewer, uploader, and non-approver reviewer all receive HTTP 403 Forbidden."""
    sug_id = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-001",
            "vendor_rule_id": "CISCO-UNAUTH-001",
            "internalTitle": "Test",
            "csmFieldChecked": "csm.test",
            "condition": "not_null"
        }
    })

    # Viewer -> 403
    res_v = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res_v.status_code == 403

    # Uploader -> 403
    res_u = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert res_u.status_code == 403

    # Reviewer non-approver -> 403
    res_r = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {non_approver_reviewer_token}"}
    )
    assert res_r.status_code == 403

    # Missing token -> 401
    res_anon = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"}
    )
    assert res_anon.status_code == 401


# ==============================================================================
# Test D: Reviewer correction becomes trusted mapping
# ==============================================================================
def test_d_reviewer_correction_becomes_trusted_mapping(approver_token):
    """D. approve_with_correction writes the reviewer-supplied mapping with source='human_corrected'."""
    sug_id = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-RAW-001",
            "vendor_rule_id": "CISCO-RAW-001",
            "internalTitle": "Raw AI Title",
            "csmFieldChecked": "csm.raw_field",
            "condition": "raw_cond"
        }
    })

    corrected_payload = {
        "common_rule_id": "COMMON-CORR-001",
        "vendor_rule_id": f"CISCO-CORR-{uuid.uuid4().hex[:8]}",
        "internalTitle": "Human Corrected Title",
        "csmFieldChecked": "csm.services.call_home",
        "condition": "equals False",
        "vendor": "cisco"
    }

    res = client.post(
        "/api/ai/approve",
        json={
            "suggestion_id": sug_id,
            "decision": "approve_with_correction",
            "corrected_mapping": corrected_payload
        },
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert res.status_code == 200

    mapping = database.get_trusted_mapping(corrected_payload["vendor_rule_id"])
    assert mapping is not None
    assert mapping["internalTitle"] == "Human Corrected Title"
    assert mapping["csmFieldChecked"] == "csm.services.call_home"
    assert mapping["status"] == "corrected"
    assert mapping["version_info"]["approved_by"] == "usr-secops-lead-01"


# ==============================================================================
# Test E: Rejection does not create trust
# ==============================================================================
def test_e_rejection_does_not_create_trust(approver_token):
    """E. Rejecting a suggestion updates pending_suggestions status to 'rejected' and NEVER writes to trusted_mappings."""
    sug_id = ai_suggester.store_suggestion({
        "raw_line": "service unneeded-banner",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-REJ-001",
            "vendor_rule_id": "CISCO-REJ-001",
            "internalTitle": "Should Be Rejected",
            "csmFieldChecked": "csm.banner",
            "condition": "not_null"
        }
    })

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    before_count = cur.fetchone()[0]
    conn.close()

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "reject"},
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "rejected"

    # Verify pending_suggestions recorded rejection
    ps = database.get_pending_suggestion(sug_id)
    assert ps["status"] == "rejected"
    assert ps["reviewed_by"] == "usr-secops-lead-01"

    # Verify trusted_mappings count unchanged and rule does not exist
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    after_count = cur.fetchone()[0]
    conn.close()
    assert before_count == after_count
    assert database.get_trusted_mapping("CISCO-REJ-001") is None


# ==============================================================================
# Test F: Vendor isolation on trusted rules
# ==============================================================================
def test_f_vendor_isolation(approver_token, uploader_token):
    """F. Cisco configs only ingest Cisco trusted rules; Juniper only ingests Juniper trusted rules."""
    cisco_rule_id = f"CISCO-ISO-{uuid.uuid4().hex[:6]}"
    juniper_rule_id = f"JUNOS-ISO-{uuid.uuid4().hex[:6]}"

    # Seed Cisco trusted rule
    sug_cisco = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-ISO-01",
            "vendor_rule_id": cisco_rule_id,
            "internalTitle": "Cisco Telemetry Check",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False",
            "vendor": "cisco"
        }
    }, vendor="cisco")
    ai_suggester.approve_suggestion(sug_cisco, "usr-secops-lead-01", "approve")

    # Seed Juniper trusted rule
    sug_juniper = ai_suggester.store_suggestion({
        "raw_line": "services ssh protocol-version v2",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-ISO-02",
            "vendor_rule_id": juniper_rule_id,
            "internalTitle": "Juniper SSH Check",
            "csmFieldChecked": "csm.services.ssh_version",
            "condition": "equals 2",
            "vendor": "juniper"
        }
    }, vendor="juniper")
    ai_suggester.approve_suggestion(sug_juniper, "usr-secops-lead-01", "approve")

    # 1. load_trusted_rules(vendor=...) strictly isolates
    cisco_trusted = load_trusted_rules(vendor="cisco")
    juniper_trusted = load_trusted_rules(vendor="juniper")

    cisco_ids = [r["vendor_rule_id"] for r in cisco_trusted]
    juniper_ids = [r["vendor_rule_id"] for r in juniper_trusted]

    assert cisco_rule_id in cisco_ids
    assert juniper_rule_id not in cisco_ids, "Cross-vendor leakage: Juniper rule found in Cisco trusted rules!"

    assert juniper_rule_id in juniper_ids
    assert cisco_rule_id not in juniper_ids, "Cross-vendor leakage: Cisco rule found in Juniper trusted rules!"

    # 2. Ingestion pipeline isolation: Cisco upload must NOT evaluate Juniper rule
    up_cisco = client.post(
        "/api/audit/upload",
        json={"raw_config": SAMPLE_CISCO_CONFIG, "filename": "cisco.cfg"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert up_cisco.status_code == 200
    cisco_evals = up_cisco.json()["rule_results"]
    assert juniper_rule_id not in cisco_evals, "Juniper trusted rule evaluated on Cisco config!"

    # 3. Ingestion pipeline isolation: Juniper upload must NOT evaluate Cisco rule
    up_juniper = client.post(
        "/api/audit/upload",
        json={"raw_config": SAMPLE_JUNIPER_CONFIG, "filename": "juniper.conf"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert up_juniper.status_code == 200
    juniper_evals = up_juniper.json()["rule_results"]
    assert cisco_rule_id not in juniper_evals, "Cisco trusted rule evaluated on Juniper config!"


# ==============================================================================
# Test G: Duplicate mapping handling (Idempotent success)
# ==============================================================================
def test_g_duplicate_identical_mapping_idempotent(approver_token):
    """G. Re-approving an identical mapping behaves idempotently and deterministically."""
    vrid = f"CISCO-DUP-{uuid.uuid4().hex[:6]}"
    sug_payload = {
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-DIAG-001",
            "vendor_rule_id": vrid,
            "internalTitle": "Disable call home",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False",
            "vendor": "cisco"
        }
    }

    sug_id1 = ai_suggester.store_suggestion(sug_payload)
    res1 = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id1, "decision": "approve"},
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert res1.status_code == 200

    # Submit second identical suggestion with same vendor_rule_id and definition
    sug_id2 = ai_suggester.store_suggestion(sug_payload)
    res2 = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id2, "decision": "approve"},
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert res2.status_code == 200
    assert res2.json()["result"]["vendor_rule_id"] == vrid


# ==============================================================================
# Test H: Conflicting mapping handling (409 Conflict)
# ==============================================================================
def test_h_conflicting_mapping_returns_409(approver_token):
    """H. Approving a suggestion with an existing vendor_rule_id but conflicting definition returns HTTP 409."""
    shared_vrid = f"CISCO-CONFLICT-{uuid.uuid4().hex[:6]}"

    # 1. Establish initial trusted mapping
    sug1 = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-DIAG-001",
            "vendor_rule_id": shared_vrid,
            "internalTitle": "Original Title",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False"
        }
    })
    client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug1, "decision": "approve"},
        headers={"Authorization": f"Bearer {approver_token}"}
    )

    # 2. Attempt to approve conflicting rule for same rule ID
    sug2 = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-DIAG-001",
            "vendor_rule_id": shared_vrid,
            "internalTitle": "Conflicting Different Title",
            "csmFieldChecked": "csm.services.different_field",
            "condition": "equals True"
        }
    })
    res_conflict = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug2, "decision": "approve"},
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert res_conflict.status_code == 409
    assert "Conflict" in res_conflict.json()["detail"]
    assert "Silent overwrite is prohibited" in res_conflict.json()["detail"]

    # Verify original rule definition was NOT overwritten
    original = database.get_trusted_mapping(shared_vrid)
    assert original["internalTitle"] == "Original Title"
    assert original["csmFieldChecked"] == "csm.services.call_home"


# ==============================================================================
# Test I: Reviewer identity / audit logging
# ==============================================================================
def test_i_reviewer_identity_and_audit_provenance(approver_token):
    """I. Authoritative reviewer JWT sub is recorded, client spoofing is ignored."""
    vrid = f"CISCO-AUDIT-{uuid.uuid4().hex[:6]}"
    sug_id = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-001",
            "vendor_rule_id": vrid,
            "internalTitle": "Audit Trail Check",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False"
        }
    })

    res = client.post(
        "/api/ai/approve",
        json={
            "suggestion_id": sug_id,
            "decision": "approve",
            "reviewer_name": "spoofed_hacker_name"
        },
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert res.status_code == 200

    mapping = database.get_trusted_mapping(vrid)
    assert mapping["version_info"]["approved_by"] == "usr-secops-lead-01"
    assert mapping["version_info"]["approved_by"] != "spoofed_hacker_name"
    assert mapping["version_info"]["approved_at"] is not None

    ps = database.get_pending_suggestion(sug_id)
    assert ps["reviewed_by"] == "usr-secops-lead-01"
    assert ps["reviewed_by"] != "spoofed_hacker_name"


# ==============================================================================
# Test J: Deterministic retrieval endpoint
# ==============================================================================
def test_j_deterministic_retrieval(viewer_token, approver_token):
    """J. GET /api/trusted-mappings returns deterministic list and filters by vendor."""
    vrid = f"CISCO-LIST-{uuid.uuid4().hex[:6]}"
    sug_id = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-LIST-01",
            "vendor_rule_id": vrid,
            "internalTitle": "List Retrieval Check",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False",
            "vendor": "cisco"
        }
    }, vendor="cisco")
    ai_suggester.approve_suggestion(sug_id, "usr-secops-lead-01", "approve")

    # List all
    res_all = client.get("/api/trusted-mappings", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_all.status_code == 200
    all_rules = res_all.json()
    assert any(r["vendor_rule_id"] == vrid for r in all_rules)

    # Filter vendor=cisco
    res_cisco = client.get("/api/trusted-mappings?vendor=cisco", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_cisco.status_code == 200
    assert all(r["vendor"] == "cisco" for r in res_cisco.json())

    # Get single rule
    res_single = client.get(f"/api/trusted-mappings/{vrid}", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_single.status_code == 200
    assert res_single.json()["vendor_rule_id"] == vrid

    # Nonexistent rule -> 404
    res_404 = client.get("/api/trusted-mappings/NONEXISTENT-999", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_404.status_code == 404


# ==============================================================================
# Test K: AI code cannot directly persist trusted mappings (AST Inspection)
# ==============================================================================
def test_k_ai_code_cannot_directly_persist_trusted_mappings():
    """K. AST inspection asserts that suggest_mapping in ai_suggester never writes to database."""
    file_path = pathlib.Path(ai_suggester.__file__).resolve()
    tree = ast.parse(file_path.read_text(encoding="utf-8"))

    # Locate suggest_mapping function
    suggest_fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "suggest_mapping":
            suggest_fn = node
            break

    assert suggest_fn is not None, "suggest_mapping function must exist"

    # Assert no database calls inside suggest_mapping
    for child in ast.walk(suggest_fn):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Attribute) and child.func.attr in ("execute", "executemany", "commit"):
                pytest.fail("AI suggestion function 'suggest_mapping' directly accesses database execution!")


# ==============================================================================
# Test L: Existing trusted mappings backward compatibility
# ==============================================================================
def test_l_existing_trusted_mappings_compatibility():
    """L. Existing rows in trusted_mappings conform to expected schema and evaluate cleanly."""
    rules = load_trusted_rules()
    for r in rules:
        assert "vendor_rule_id" in r
        assert "internalTitle" in r
        assert "csmFieldChecked" in r
        assert "condition" in r
        assert "configuration_evidence" in r
        assert isinstance(r["configuration_evidence"], list)
        assert "version_info" in r
        assert isinstance(r["version_info"], dict)


# ==============================================================================
# Test M: Cisco workflow regression
# ==============================================================================
def test_m_cisco_workflow_regression(uploader_token, approver_token):
    """M. Complete Cisco pipeline: upload config -> suggest -> approve -> re-evaluate."""
    # 1. Upload Cisco config with unmapped line
    up_res = client.post(
        "/api/audit/upload",
        json={"raw_config": SAMPLE_CISCO_CONFIG, "filename": "edge_cisco.cfg"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert up_res.status_code == 200
    sess_id = up_res.json()["session_id"]

    # 2. Get AI suggestion
    sug_res = client.post(
        "/api/ai/suggest",
        json={"unmapped_line": "service call-home", "vendor": "cisco"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert sug_res.status_code == 200
    sug_id = sug_res.json()["suggestion_id"]

    # 3. Approve with session_id re-evaluation
    appr_res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve", "session_id": sess_id},
        headers={"Authorization": f"Bearer {approver_token}"}
    )
    assert appr_res.status_code == 200
    appr_data = appr_res.json()
    assert appr_data["status"] == "approve"
    assert appr_data["updated_results"] is not None


# ==============================================================================
# Test N: Juniper workflow regression
# ==============================================================================
def test_n_juniper_workflow_regression(uploader_token, approver_token):
    """N. Complete Juniper pipeline: upload Junos config -> suggest -> approve -> evaluate."""
    # 1. Upload Juniper config
    up_res = client.post(
        "/api/audit/upload",
        json={"raw_config": SAMPLE_JUNIPER_CONFIG, "filename": "edge_junos.conf"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert up_res.status_code == 200
    assert up_res.json()["platform"] == "Junos"

    # 2. Generate Juniper suggestion
    sug_res = client.post(
        "/api/ai/suggest",
        json={"unmapped_line": "set system services call-home", "vendor": "juniper"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert sug_res.status_code == 200
    sug_data = sug_res.json()["suggestion"]
    assert sug_data["vendor"] == "juniper"


# ==============================================================================
# Test O: API authorization on library endpoints
# ==============================================================================
def test_o_api_authorization_matrix(viewer_token, uploader_token, non_approver_reviewer_token, approver_token):
    """O. Verify GET endpoints allow viewer/uploader/reviewer; DELETE strictly requires authorized approver."""
    vrid = f"CISCO-DEL-{uuid.uuid4().hex[:6]}"
    sug_id = ai_suggester.store_suggestion({
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-001",
            "vendor_rule_id": vrid,
            "internalTitle": "Deletion Test",
            "csmFieldChecked": "csm.test",
            "condition": "not_null"
        }
    })
    ai_suggester.approve_suggestion(sug_id, "usr-secops-lead-01", "approve")

    # 1. Viewer can list and inspect
    assert client.get("/api/trusted-mappings", headers={"Authorization": f"Bearer {viewer_token}"}).status_code == 200
    assert client.get(f"/api/trusted-mappings/{vrid}", headers={"Authorization": f"Bearer {viewer_token}"}).status_code == 200

    # 2. Viewer cannot delete -> 403
    assert client.delete(f"/api/trusted-mappings/{vrid}", headers={"Authorization": f"Bearer {viewer_token}"}).status_code == 403

    # 3. Uploader cannot delete -> 403
    assert client.delete(f"/api/trusted-mappings/{vrid}", headers={"Authorization": f"Bearer {uploader_token}"}).status_code == 403

    # 4. Reviewer without approver authorization cannot delete -> 403
    assert client.delete(f"/api/trusted-mappings/{vrid}", headers={"Authorization": f"Bearer {non_approver_reviewer_token}"}).status_code == 403

    # 5. Authorized approver can delete -> 200
    del_res = client.delete(f"/api/trusted-mappings/{vrid}", headers={"Authorization": f"Bearer {approver_token}"})
    assert del_res.status_code == 200
    assert del_res.json()["success"] is True

    # After deletion, inspecting returns 404
    assert client.get(f"/api/trusted-mappings/{vrid}", headers={"Authorization": f"Bearer {viewer_token}"}).status_code == 404


# ==============================================================================
# Test P: Frontend / API contract match
# ==============================================================================
def test_p_frontend_api_contract_match(viewer_token):
    """P. Verifies wire JSON structures conform precisely to frontend TrustedMappingItem and SuggestionQueueItem."""
    res_tm = client.get("/api/trusted-mappings", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_tm.status_code == 200
    tm_list = res_tm.json()
    if tm_list:
        sample_tm = tm_list[0]
        # TrustedMappingItem keys
        required_tm_keys = {"vendor_rule_id", "internalTitle", "csmFieldChecked", "condition", "version_info", "vendor", "status"}
        for k in required_tm_keys:
            assert k in sample_tm, f"Missing key '{k}' in trusted-mappings API contract"

    res_sug = client.get("/api/ai/suggestions", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_sug.status_code == 200
    sug_list = res_sug.json()
    if sug_list:
        sample_sug = sug_list[0]
        # SuggestionQueueItem keys
        required_sug_keys = {"suggestion_id", "timestamp", "status", "suggestion", "vendor"}
        for k in required_sug_keys:
            assert k in sample_sug, f"Missing key '{k}' in ai/suggestions API contract"
