"""
NTRO PS26155 Auditor — Resource Ownership & Session Isolation Tests (Chunk 5)
Verifies:
1. Server-side session ownership assignment derived strictly from JWT sub claim.
2. Inability of client to override owner_user_id via payload, query, or headers.
3. Strict session isolation: Uploader A cannot access or manipulate Uploader B's session.
4. Anti-enumeration: 404 Not Found response and message are indistinguishable between
   non-existent session IDs and unauthorized cross-owner session IDs.
5. Reviewer global access to any session (results, remediation, finalization).
6. Viewer access to session results (read-only compliance view).
7. Precedence order: Authentication (401) -> RBAC (403) -> Ownership (404) -> Business Logic.
8. Direct unit verification of check_session_ownership helper.
"""

import uuid
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import auth
import database
import main
from main import app, check_session_ownership, get_authenticated_session

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
        username="auditor_viewer",
        role="viewer",
        is_authorized_approver=False,
    )


def create_session_for_uploader(token: str, extra_body: dict = None, extra_headers: dict = None, query: str = ""):
    headers = {"Authorization": f"Bearer {token}"}
    if extra_headers:
        headers.update(extra_headers)

    payload = {
        "raw_config": SAMPLE_CONFIG,
        "filename": "router_test.cfg"
    }
    if extra_body:
        payload.update(extra_body)

    url = "/api/audit/upload"
    if query:
        url += f"?{query}"

    res = client.post(url, json=payload, headers=headers)
    assert res.status_code == 200, f"Upload failed: {res.text}"
    return res.json()["session_id"]


# ==============================================================================
# 1. Server-side Assignment & Client Override Resistance (Scenarios 1-4)
# ==============================================================================

def test_upload_assigns_owner_user_id_from_jwt_sub(uploader_a_token):
    """Scenario 1: Audit upload assigns owner_user_id strictly from JWT sub claim."""
    session_id = create_session_for_uploader(uploader_a_token)
    session = database.get_session(session_id)
    assert session is not None
    assert session.get("owner_user_id") == "usr-uploader-a"


def test_client_cannot_override_owner_user_id_in_payload(uploader_a_token):
    """Scenario 2: Client cannot override owner_user_id via JSON body payload."""
    session_id = create_session_for_uploader(
        uploader_a_token,
        extra_body={"owner_user_id": "usr-injected-attacker", "owner": "hacker"}
    )
    session = database.get_session(session_id)
    assert session.get("owner_user_id") == "usr-uploader-a"


def test_client_cannot_override_owner_user_id_in_query(uploader_a_token):
    """Scenario 3: Client cannot override owner_user_id via query parameters."""
    session_id = create_session_for_uploader(
        uploader_a_token,
        query="owner_user_id=usr-injected-attacker"
    )
    session = database.get_session(session_id)
    assert session.get("owner_user_id") == "usr-uploader-a"


def test_client_cannot_override_owner_user_id_in_headers(uploader_a_token):
    """Scenario 4: Client cannot override owner_user_id via custom headers."""
    session_id = create_session_for_uploader(
        uploader_a_token,
        extra_headers={"X-User-ID": "usr-injected-attacker", "X-Owner-ID": "usr-injected-attacker"}
    )
    session = database.get_session(session_id)
    assert session.get("owner_user_id") == "usr-uploader-a"


# ==============================================================================
# 2. Session Isolation & Anti-Enumeration for GET Results (Scenarios 5-9)
# ==============================================================================

def test_uploader_can_access_own_session_results(uploader_a_token):
    """Scenario 5: Uploader can access their own session results."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.get(
        f"/api/audit/{session_id}/results",
        headers={"Authorization": f"Bearer {uploader_a_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["session_id"] == session_id
    assert "summary" in data


def test_uploader_cannot_access_other_uploader_session_results(uploader_a_token, uploader_b_token):
    """Scenario 6: Uploader B accessing Uploader A's session results receives 404."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.get(
        f"/api/audit/{session_id}/results",
        headers={"Authorization": f"Bearer {uploader_b_token}"}
    )
    assert res.status_code == 404
    assert res.json()["detail"] == f"Session '{session_id}' not found."


def test_anti_enumeration_identical_404_error_detail(uploader_a_token, uploader_b_token):
    """Scenario 7: Anti-enumeration detail is identical between non-existent and cross-owner access."""
    session_id = create_session_for_uploader(uploader_a_token)
    fake_id = str(uuid.uuid4())

    # Cross-owner access
    res_cross = client.get(
        f"/api/audit/{session_id}/results",
        headers={"Authorization": f"Bearer {uploader_b_token}"}
    )
    # Non-existent session access
    res_fake = client.get(
        f"/api/audit/{fake_id}/results",
        headers={"Authorization": f"Bearer {uploader_b_token}"}
    )

    assert res_cross.status_code == 404
    assert res_fake.status_code == 404
    assert res_cross.json()["detail"] == f"Session '{session_id}' not found."
    assert res_fake.json()["detail"] == f"Session '{fake_id}' not found."


def test_reviewer_can_access_any_uploader_session_results(uploader_a_token, reviewer_token):
    """Scenario 8: Reviewer has global access and can read any uploader's session results."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.get(
        f"/api/audit/{session_id}/results",
        headers={"Authorization": f"Bearer {reviewer_token}"}
    )
    assert res.status_code == 200
    assert res.json()["session_id"] == session_id


def test_viewer_can_access_any_uploader_session_results(uploader_a_token, viewer_token):
    """Scenario 9: Viewer can view session results as a read-only compliance auditor."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.get(
        f"/api/audit/{session_id}/results",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res.status_code == 200
    assert res.json()["session_id"] == session_id


# ==============================================================================
# 3. Remediation Endpoint Isolation (Scenarios 10-13)
# ==============================================================================

def test_uploader_can_remediate_own_session(uploader_a_token):
    """Scenario 10: Uploader can request remediation referencing their own session."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.post(
        "/api/remediation/CISCO-NTP-001",
        json={"session_id": session_id},
        headers={"Authorization": f"Bearer {uploader_a_token}"}
    )
    assert res.status_code == 200
    assert "remediation_cmd" in res.json()


def test_uploader_cannot_remediate_other_uploader_session(uploader_a_token, uploader_b_token):
    """Scenario 11: Uploader B cannot request remediation referencing Uploader A's session (returns 404)."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.post(
        "/api/remediation/CISCO-NTP-001",
        json={"session_id": session_id},
        headers={"Authorization": f"Bearer {uploader_b_token}"}
    )
    assert res.status_code == 404
    assert res.json()["detail"] == f"Session '{session_id}' not found."


def test_reviewer_can_remediate_any_session(uploader_a_token, reviewer_token):
    """Scenario 12: Reviewer can request remediation referencing any uploader's session."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.post(
        "/api/remediation/CISCO-NTP-001",
        json={"session_id": session_id},
        headers={"Authorization": f"Bearer {reviewer_token}"}
    )
    assert res.status_code == 200
    assert "remediation_cmd" in res.json()


def test_remediation_nonexistent_session_returns_404(uploader_a_token):
    """Scenario 13: Remediation with non-existent session_id returns 404."""
    fake_id = str(uuid.uuid4())
    res = client.post(
        "/api/remediation/CISCO-NTP-001",
        json={"session_id": fake_id},
        headers={"Authorization": f"Bearer {uploader_a_token}"}
    )
    assert res.status_code == 404
    assert res.json()["detail"] == f"Session '{fake_id}' not found."


# ==============================================================================
# 4. Finalize Endpoint Isolation (Scenarios 14-17)
# ==============================================================================

def test_uploader_can_finalize_own_session(uploader_a_token):
    """Scenario 14: Uploader can finalize their own session."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.post(
        "/api/audit/finalize",
        json={"session_id": session_id, "remediation_summary": {"status": "accepted"}},
        headers={"Authorization": f"Bearer {uploader_a_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "entryHash" in data
    assert "pdf_download_url" in data


def test_uploader_cannot_finalize_other_uploader_session(uploader_a_token, uploader_b_token):
    """Scenario 15: Uploader B cannot finalize Uploader A's session (returns 404)."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.post(
        "/api/audit/finalize",
        json={"session_id": session_id, "remediation_summary": {}},
        headers={"Authorization": f"Bearer {uploader_b_token}"}
    )
    assert res.status_code == 404
    assert res.json()["detail"] == f"Session '{session_id}' not found."


def test_reviewer_can_finalize_any_session(uploader_a_token, reviewer_token):
    """Scenario 16: Reviewer can finalize any uploader's session."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.post(
        "/api/audit/finalize",
        json={"session_id": session_id, "remediation_summary": {"reviewer_override": True}},
        headers={"Authorization": f"Bearer {reviewer_token}"}
    )
    assert res.status_code == 200
    assert "entryHash" in res.json()


def test_finalize_nonexistent_session_returns_404(uploader_a_token):
    """Scenario 17: Finalize with non-existent session_id returns 404."""
    fake_id = str(uuid.uuid4())
    res = client.post(
        "/api/audit/finalize",
        json={"session_id": fake_id, "remediation_summary": {}},
        headers={"Authorization": f"Bearer {uploader_a_token}"}
    )
    assert res.status_code == 404
    assert res.json()["detail"] == f"Session '{fake_id}' not found."


# ==============================================================================
# 5. Boundary Precedence: Auth (401) -> RBAC (403) -> Ownership (404) (Scenarios 18-19)
# ==============================================================================

def test_unauthenticated_request_rejected_at_auth_boundary_before_ownership(uploader_a_token):
    """Scenario 18: Unauthenticated request fails closed with 401 before session/ownership check."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.get(f"/api/audit/{session_id}/results")
    assert res.status_code == 401
    assert "Missing Authorization header" in res.json()["detail"]


def test_unauthorized_role_rejected_at_rbac_boundary_before_ownership(uploader_a_token, viewer_token):
    """Scenario 19: Unauthorized role (Viewer attempting finalize) fails with 403 before ownership check."""
    session_id = create_session_for_uploader(uploader_a_token)
    res = client.post(
        "/api/audit/finalize",
        json={"session_id": session_id, "remediation_summary": {}},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res.status_code == 403
    assert "Role 'viewer' is not permitted" in res.json()["detail"]


# ==============================================================================
# 6. Direct Unit Verification of check_session_ownership (Scenario 20)
# ==============================================================================

def test_check_session_ownership_direct_unit():
    """Scenario 20: Direct unit testing of check_session_ownership helper semantics."""
    # 1. Non-existent session
    with pytest.raises(HTTPException) as exc1:
        check_session_ownership(None, {"role": "uploader", "sub": "u1"}, "sess-01")
    assert exc1.value.status_code == 404
    assert exc1.value.detail == "Session 'sess-01' not found."

    # 2. Uploader matches owner
    sess_own = {"session_id": "sess-02", "owner_user_id": "u1", "csm": {}}
    res2 = check_session_ownership(sess_own, {"role": "uploader", "sub": "u1"}, "sess-02")
    assert res2 == sess_own

    # 3. Uploader does not match owner -> 404
    with pytest.raises(HTTPException) as exc3:
        check_session_ownership(sess_own, {"role": "uploader", "sub": "u2"}, "sess-02")
    assert exc3.value.status_code == 404
    assert exc3.value.detail == "Session 'sess-02' not found."

    # 4. Reviewer accesses another uploader's session -> succeeds
    res4 = check_session_ownership(sess_own, {"role": "reviewer", "sub": "r1"}, "sess-02")
    assert res4 == sess_own

    # 5. Viewer accesses another uploader's session -> succeeds
    res5 = check_session_ownership(sess_own, {"role": "viewer", "sub": "v1"}, "sess-02")
    assert res5 == sess_own


def test_get_authenticated_session_direct_unit(monkeypatch):
    """Verifies get_authenticated_session wrapper retrieves from db and applies ownership check."""
    fake_session = {"session_id": "test-auth-sess", "owner_user_id": "owner-1", "csm": {}}
    
    def fake_get_session(sess_id):
        if sess_id == "test-auth-sess":
            return fake_session
        return None
    
    monkeypatch.setattr(database, "get_session", fake_get_session)
    
    # 1. Matching owner succeeds
    ret = get_authenticated_session("test-auth-sess", {"role": "uploader", "sub": "owner-1"})
    assert ret == fake_session

    # 2. Non-existent session raises 404
    with pytest.raises(HTTPException) as exc1:
        get_authenticated_session("nonexistent-sess", {"role": "reviewer", "sub": "rev-1"})
    assert exc1.value.status_code == 404

    # 3. Cross-uploader access raises 404
    with pytest.raises(HTTPException) as exc2:
        get_authenticated_session("test-auth-sess", {"role": "uploader", "sub": "attacker-uploader"})
    assert exc2.value.status_code == 404

    # 4. Reviewer access succeeds
    ret_rev = get_authenticated_session("test-auth-sess", {"role": "reviewer", "sub": "rev-1"})
    assert ret_rev == fake_session
