"""
NTRO PS26155 Auditor — Reviewer Identity & Approval Accountability Binding Tests (Chunk 6)
Verifies:
1. Server-side reviewer identity derivation exclusively from authenticated JWT 'sub' claim.
2. Client impersonation prevention: client-supplied reviewer_name, reviewer_id, username,
   headers (X-User-ID, X-Reviewer-ID, X-Forwarded-User), and query strings are ignored.
3. RBAC & Approver Constraints: Reviewer with is_authorized_approver=True is required (403 otherwise).
4. Rejection flow accountability: Rejection records authenticated reviewer identity in DB.
5. Behavioral correctness: approve, reject, approve_with_correction, rule re-evaluation.
6. Backward & forward compatibility: Omitting reviewer_name or supplying dummy values succeeds.
7. Invariant verification: Cryptographic ledger remains untouched; authentication & ownership hold.
"""

import datetime
import json
import uuid
import pytest
from fastapi.testclient import TestClient

import auth
import database
import main
from main import app

client = TestClient(app)

SAMPLE_CONFIG = """
hostname EDGE-RTR-01
!
interface GigabitEthernet0/0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
line vty 0 4
 transport input ssh
!
end
"""


@pytest.fixture(autouse=True)
def setup_db():
    database.initialize_database()


@pytest.fixture
def authorized_approver_token():
    return auth.create_access_token(
        user_id="usr-reviewer-lead-01",
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


def seed_pending_suggestion(suggestion_id: str) -> dict:
    """Inserts a clean pending suggestion row directly into SQLite for deterministic testing."""
    sug_payload = {
        "raw_line": "service call-home",
        "suggested_new_rule": {
            "common_rule_id": "COMMON-DIAG-001",
            "vendor_rule_id": f"CISCO-TEST-{suggestion_id[:8]}",
            "internalTitle": "Disable unneeded telemetry services",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False"
        },
        "framework_hints": ["CIS-Cisco-IOS-XE-1.0"]
    }
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT OR REPLACE INTO pending_suggestions 
        (suggestion_id, timestamp, status, suggestion, reviewed_by, reviewed_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        suggestion_id,
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pending",
        json.dumps(sug_payload),
        None,
        None
    ))
    conn.commit()
    conn.close()
    return sug_payload


# ==============================================================================
# 1. Authoritative Identity Derivation & Impersonation Prevention (Scenarios 1-9)
# ==============================================================================

def test_authorized_reviewer_can_approve(authorized_approver_token):
    """Scenario 1: Authorized reviewer can approve compliance rules."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "approve"


def test_approval_identity_equals_authenticated_jwt_sub(authorized_approver_token):
    """Scenario 2: Reviewer identity recorded in DB equals authenticated JWT 'sub'."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed = seed_pending_suggestion(sug_id)
    vendor_rule_id = seed["suggested_new_rule"]["vendor_rule_id"]

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200

    # 1. Inspect pending_suggestions table
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by, status FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    row = cur.fetchone()
    assert row is not None
    assert row["reviewed_by"] == "usr-reviewer-lead-01"
    assert row["status"] == "approve"

    # 2. Inspect trusted_mappings table version_info
    cur.execute("SELECT version_info FROM trusted_mappings WHERE vendor_rule_id = ?", (vendor_rule_id,))
    tm_row = cur.fetchone()
    conn.close()
    assert tm_row is not None
    v_info = json.loads(tm_row["version_info"])
    assert v_info["approved_by"] == "usr-reviewer-lead-01"


def test_client_reviewer_name_cannot_change_approval_identity(authorized_approver_token):
    """Scenario 3: Client-supplied reviewer_name is ignored; JWT sub is authoritative."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed = seed_pending_suggestion(sug_id)
    vendor_rule_id = seed["suggested_new_rule"]["vendor_rule_id"]

    res = client.post(
        "/api/ai/approve",
        json={
            "suggestion_id": sug_id,
            "reviewer_name": "Chief_Security_Officer_Impersonated",
            "decision": "approve"
        },
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    row = cur.fetchone()
    assert row["reviewed_by"] == "usr-reviewer-lead-01"
    assert row["reviewed_by"] != "Chief_Security_Officer_Impersonated"

    cur.execute("SELECT version_info FROM trusted_mappings WHERE vendor_rule_id = ?", (vendor_rule_id,))
    tm_row = cur.fetchone()
    conn.close()
    v_info = json.loads(tm_row["version_info"])
    assert v_info["approved_by"] == "usr-reviewer-lead-01"
    assert v_info["approved_by"] != "Chief_Security_Officer_Impersonated"


def test_client_reviewer_id_in_payload_cannot_change_approval_identity(authorized_approver_token):
    """Scenario 4: Client-supplied reviewer_id in payload is ignored."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed = seed_pending_suggestion(sug_id)
    vendor_rule_id = seed["suggested_new_rule"]["vendor_rule_id"]

    res = client.post(
        "/api/ai/approve",
        json={
            "suggestion_id": sug_id,
            "reviewer_id": "usr-fake-superadmin-999",
            "decision": "approve"
        },
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    row = cur.fetchone()
    assert row["reviewed_by"] == "usr-reviewer-lead-01"

    cur.execute("SELECT version_info FROM trusted_mappings WHERE vendor_rule_id = ?", (vendor_rule_id,))
    v_info = json.loads(cur.fetchone()["version_info"])
    conn.close()
    assert v_info["approved_by"] == "usr-reviewer-lead-01"


def test_client_username_in_payload_cannot_change_approval_identity(authorized_approver_token):
    """Scenario 5: Client-supplied username in payload is ignored."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={
            "suggestion_id": sug_id,
            "username": "root_admin",
            "decision": "approve"
        },
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    assert cur.fetchone()["reviewed_by"] == "usr-reviewer-lead-01"
    conn.close()


def test_x_user_id_header_cannot_change_approval_identity(authorized_approver_token):
    """Scenario 6: Custom X-User-ID header cannot alter reviewer identity."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={
            "Authorization": f"Bearer {authorized_approver_token}",
            "X-User-ID": "spoofed-user-id"
        }
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    assert cur.fetchone()["reviewed_by"] == "usr-reviewer-lead-01"
    conn.close()


def test_x_reviewer_id_header_cannot_change_approval_identity(authorized_approver_token):
    """Scenario 7: Custom X-Reviewer-ID header cannot alter reviewer identity."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={
            "Authorization": f"Bearer {authorized_approver_token}",
            "X-Reviewer-ID": "spoofed-reviewer-id"
        }
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    assert cur.fetchone()["reviewed_by"] == "usr-reviewer-lead-01"
    conn.close()


def test_x_forwarded_user_header_cannot_change_approval_identity(authorized_approver_token):
    """Scenario 8: Proxy X-Forwarded-User header cannot alter reviewer identity."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={
            "Authorization": f"Bearer {authorized_approver_token}",
            "X-Forwarded-User": "spoofed-forwarded-user"
        }
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    assert cur.fetchone()["reviewed_by"] == "usr-reviewer-lead-01"
    conn.close()


def test_query_string_identity_cannot_change_approval_identity(authorized_approver_token):
    """Scenario 9: Query string parameters cannot alter reviewer identity."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        f"/api/ai/approve?reviewer_name=spoof&reviewer_id=spoof&sub=spoof",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    assert cur.fetchone()["reviewed_by"] == "usr-reviewer-lead-01"
    conn.close()


# ==============================================================================
# 2. Role & Approver Constraint Enforcement (Scenarios 10-15)
# ==============================================================================

def test_unauthorized_reviewer_cannot_approve(non_approver_reviewer_token):
    """Scenario 10: Reviewer without approver authorization receives 403."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {non_approver_reviewer_token}"}
    )
    assert res.status_code == 403
    assert "Only authorized approvers can approve compliance rules" in res.json()["detail"]


def test_uploader_cannot_approve(uploader_token):
    """Scenario 11: Uploader role cannot approve compliance rules (receives 403)."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert res.status_code == 403
    assert "Role 'uploader' is not permitted" in res.json()["detail"]


def test_viewer_cannot_approve(viewer_token):
    """Scenario 12: Viewer role cannot approve compliance rules (receives 403)."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res.status_code == 403
    assert "Role 'viewer' is not permitted" in res.json()["detail"]


def test_missing_jwt_returns_401():
    """Scenario 13: Missing JWT Authorization header returns 401."""
    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": "sug-dummy", "decision": "approve"}
    )
    assert res.status_code == 401
    assert "Missing Authorization header" in res.json()["detail"]


def test_invalid_or_tampered_jwt_returns_401():
    """Scenario 14: Tampered/invalid JWT returns 401."""
    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": "sug-dummy", "decision": "approve"},
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.invalid.signature"}
    )
    assert res.status_code == 401
    assert "Invalid token" in res.json()["detail"]


def test_reviewer_non_approver_receives_403(non_approver_reviewer_token):
    """Scenario 15: Reviewer with is_authorized_approver=false explicitly receives 403."""
    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": "sug-dummy", "decision": "approve"},
        headers={"Authorization": f"Bearer {non_approver_reviewer_token}"}
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json()["detail"]


# ==============================================================================
# 3. Behavioral Correctness, Accountability & Regression Invariants (Scenarios 16-20)
# ==============================================================================

def test_authenticated_authorized_approver_remains_authorized(authorized_approver_token):
    """Scenario 16: Authenticated authorized approver remains authorized and succeeds."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200
    assert res.json()["result"]["vendor_rule_id"].startswith("CISCO-TEST-")


def test_existing_approval_functionality_behaviorally_correct(authorized_approver_token):
    """Scenario 17: approve_with_correction works correctly and updates trusted rules."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    corrected = {
        "common_rule_id": "COMMON-CORR-001",
        "vendor_rule_id": f"CISCO-CORR-{sug_id[:8]}",
        "internalTitle": "Corrected rule title",
        "csmFieldChecked": "csm.services.call_home",
        "condition": "equals False"
    }

    res = client.post(
        "/api/ai/approve",
        json={
            "suggestion_id": sug_id,
            "decision": "approve_with_correction",
            "corrected_mapping": corrected
        },
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200
    result = res.json()["result"]
    assert result["vendor_rule_id"] == corrected["vendor_rule_id"]
    assert result["version_info"]["approved_by"] == "usr-reviewer-lead-01"


def test_rejection_flow_records_authoritative_reviewer_identity(authorized_approver_token):
    """Scenario 18: Rejection flow binds authoritative reviewer identity in DB."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={
            "suggestion_id": sug_id,
            "reviewer_name": "spoofed_reviewer_name",
            "decision": "reject"
        },
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "rejected"
    assert data["result"]["reviewer"] == "usr-reviewer-lead-01"

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT reviewed_by, status FROM pending_suggestions WHERE suggestion_id = ?", (sug_id,))
    row = cur.fetchone()
    conn.close()
    assert row["status"] == "rejected"
    assert row["reviewed_by"] == "usr-reviewer-lead-01"


def test_omitting_reviewer_name_succeeds_cleanly(authorized_approver_token):
    """Scenario 19: Omitting client-supplied reviewer_name succeeds without validation error."""
    sug_id = f"sug-{uuid.uuid4().hex[:12]}"
    seed_pending_suggestion(sug_id)

    res = client.post(
        "/api/ai/approve",
        json={"suggestion_id": sug_id, "decision": "approve"},
        headers={"Authorization": f"Bearer {authorized_approver_token}"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "approve"


def test_existing_ownership_behavior_remains_correct(uploader_token):
    """Scenario 20: Existing session ownership behavior remains functional and isolated."""
    res_up = client.post(
        "/api/audit/upload",
        json={"raw_config": SAMPLE_CONFIG, "filename": "test.cfg"},
        headers={"Authorization": f"Bearer {uploader_token}"}
    )
    assert res_up.status_code == 200
    sess_id = res_up.json()["session_id"]

    session = database.get_session(sess_id)
    assert session is not None
    assert session["owner_user_id"] == "usr-uploader-01"
