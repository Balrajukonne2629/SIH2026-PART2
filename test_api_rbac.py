"""
NTRO PS26155 Auditor — Role-Based Access Control (RBAC) API Integration Tests
Verifies all Chunk 4 requirements:
1. require_role(*roles, require_approver=False) dependency factory
2. 401 Unauthorized vs 403 Forbidden semantics
3. Role enforcement across all protected endpoints:
   - Viewer (read-only: ledger, results, reports)
   - Uploader (mutations: upload, suggest, remediation, finalize)
   - Reviewer (all above + approve)
4. Authorized approver constraint on POST /api/ai/approve
5. Rejection of unknown roles and authentication bypass attempts
"""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import auth
import database
import main
from main import app, require_role

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
def viewer_token():
    return auth.create_access_token(
        user_id="usr-viewer-01",
        username="auditor_viewer",
        role="viewer",
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
def reviewer_token():
    return auth.create_access_token(
        user_id="usr-reviewer-01",
        username="secops_reviewer",
        role="reviewer",
        is_authorized_approver=True,
    )


@pytest.fixture
def reviewer_non_approver_token():
    return auth.create_access_token(
        user_id="usr-reviewer-non-approver",
        username="secops_junior_reviewer",
        role="reviewer",
        is_authorized_approver=False,
    )


# 1. Missing token -> 401
def test_missing_token_returns_401():
    endpoints = [
        ("POST", "/api/audit/upload", {"json": {"raw_config": SAMPLE_CONFIG}}),
        ("GET", "/api/audit/fake-session/results", {}),
        ("POST", "/api/ai/suggest", {"json": {"unmapped_line": "service call-home"}}),
        ("POST", "/api/ai/approve", {"json": {"suggestion_id": "s1", "reviewer_name": "rev", "decision": "approve"}}),
        ("POST", "/api/remediation/CISCO-NTP-001", {"json": {"session_id": "fake"}}),
        ("POST", "/api/audit/finalize", {"json": {"session_id": "fake"}}),
        ("GET", "/api/ledger", {}),
        ("GET", "/api/ledger/verify", {}),
        ("GET", "/api/report/fake-entry/download", {}),
        ("GET", "/api/report/fake-entry/verify", {}),
    ]
    for method, path, kwargs in endpoints:
        res = client.request(method, path, **kwargs)
        assert res.status_code == 401, f"{method} {path} expected 401 without token, got {res.status_code}"
        assert "WWW-Authenticate" in res.headers


# 2. Invalid token -> 401
def test_invalid_token_returns_401():
    headers = {"Authorization": "Bearer invalid.tampered.token"}
    endpoints = [
        ("POST", "/api/audit/upload", {"json": {"raw_config": SAMPLE_CONFIG}}),
        ("GET", "/api/ledger", {}),
        ("POST", "/api/ai/approve", {"json": {"suggestion_id": "s1", "reviewer_name": "r", "decision": "approve"}}),
    ]
    for method, path, kwargs in endpoints:
        res = client.request(method, path, headers=headers, **kwargs)
        assert res.status_code == 401, f"{method} {path} expected 401 with invalid token, got {res.status_code}"


# 3. Viewer accessing uploader/reviewer endpoint -> 403
def test_viewer_accessing_mutation_endpoints_returns_403(viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    mutation_endpoints = [
        ("POST", "/api/audit/upload", {"json": {"raw_config": SAMPLE_CONFIG}}),
        ("POST", "/api/ai/suggest", {"json": {"unmapped_line": "service call-home"}}),
        ("POST", "/api/remediation/CISCO-NTP-001", {"json": {"session_id": "fake"}}),
        ("POST", "/api/ai/approve", {"json": {"suggestion_id": "s1", "reviewer_name": "r", "decision": "approve"}}),
        ("POST", "/api/audit/finalize", {"json": {"session_id": "fake"}}),
    ]
    for method, path, kwargs in mutation_endpoints:
        res = client.request(method, path, headers=headers, **kwargs)
        assert res.status_code == 403, f"{method} {path} expected 403 for viewer, got {res.status_code}"
        assert "Forbidden" in res.json()["detail"]


# 4. Uploader accessing reviewer-only approval endpoint -> 403
def test_uploader_accessing_reviewer_approval_returns_403(uploader_token):
    headers = {"Authorization": f"Bearer {uploader_token}"}
    res = client.post(
        "/api/ai/approve",
        headers=headers,
        json={"suggestion_id": "s1", "reviewer_name": "netadmin", "decision": "approve"},
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json()["detail"]


# 5. Reviewer accessing uploader/reviewer endpoints -> allowed
def test_reviewer_accessing_uploader_reviewer_endpoints_allowed(reviewer_token):
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    # Upload allowed (200)
    upload_res = client.post(
        "/api/audit/upload",
        headers=headers,
        json={"raw_config": SAMPLE_CONFIG, "filename": "test.cfg"},
    )
    assert upload_res.status_code == 200
    session_id = upload_res.json()["session_id"]

    # Remediation allowed
    rem_res = client.post(
        "/api/remediation/CISCO-NTP-001",
        headers=headers,
        json={"session_id": session_id},
    )
    assert rem_res.status_code == 200


# 6. Uploader accessing uploader/reviewer endpoints -> allowed
def test_uploader_accessing_uploader_reviewer_endpoints_allowed(uploader_token):
    headers = {"Authorization": f"Bearer {uploader_token}"}

    # Upload allowed (200)
    upload_res = client.post(
        "/api/audit/upload",
        headers=headers,
        json={"raw_config": SAMPLE_CONFIG, "filename": "test.cfg"},
    )
    assert upload_res.status_code == 200
    session_id = upload_res.json()["session_id"]

    # Remediation allowed
    rem_res = client.post(
        "/api/remediation/CISCO-NTP-001",
        headers=headers,
        json={"session_id": session_id},
    )
    assert rem_res.status_code == 200


# 7. Viewer accessing read-only endpoints -> allowed
def test_viewer_accessing_readonly_endpoints_allowed(viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}

    res_ledger = client.get("/api/ledger", headers=headers)
    assert res_ledger.status_code == 200

    res_verify = client.get("/api/ledger/verify", headers=headers)
    assert res_verify.status_code in (200, 409)  # 200 if valid, 409 if empty/tampered, but NEVER 401/403


# 8. Reviewer accessing read-only endpoints -> allowed
def test_reviewer_accessing_readonly_endpoints_allowed(reviewer_token):
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    res_ledger = client.get("/api/ledger", headers=headers)
    assert res_ledger.status_code == 200


# 9. Uploader accessing read-only endpoints -> allowed
def test_uploader_accessing_readonly_endpoints_allowed(uploader_token):
    headers = {"Authorization": f"Bearer {uploader_token}"}

    res_ledger = client.get("/api/ledger", headers=headers)
    assert res_ledger.status_code == 200


# 10. Reviewer with is_authorized_approver=false attempting approval -> 403
def test_reviewer_non_approver_attempting_approval_returns_403(reviewer_non_approver_token):
    headers = {"Authorization": f"Bearer {reviewer_non_approver_token}"}
    res = client.post(
        "/api/ai/approve",
        headers=headers,
        json={"suggestion_id": "dummy-sug-id", "reviewer_name": "junior", "decision": "approve"},
    )
    assert res.status_code == 403
    assert "Only authorized approvers" in res.json()["detail"]


# 11. Reviewer with is_authorized_approver=true attempting approval -> authorization passes
def test_reviewer_authorized_approver_passes_authorization(reviewer_token):
    headers = {"Authorization": f"Bearer {reviewer_token}"}
    # Approval on nonexistent suggestion will fail with 404/400 at business logic,
    # proving authorization boundary passed (did NOT return 401 or 403)!
    res = client.post(
        "/api/ai/approve",
        headers=headers,
        json={"suggestion_id": "nonexistent-id", "reviewer_name": "lead", "decision": "approve"},
    )
    assert res.status_code not in (401, 403)


# 12. Valid role must not accidentally bypass authentication
def test_valid_role_must_not_bypass_authentication():
    # Sending role in header/query without a signed JWT
    res1 = client.post(
        "/api/audit/upload",
        headers={"X-Role": "reviewer", "Role": "reviewer"},
        json={"raw_config": SAMPLE_CONFIG},
    )
    assert res1.status_code == 401

    res2 = client.get("/api/ledger?role=reviewer")
    assert res2.status_code == 401


# 13. Role checks must not accept arbitrary/unknown roles
@pytest.mark.anyio
async def test_require_role_rejects_unknown_roles():
    checker = require_role("uploader", "reviewer")

    # Unknown role
    fake_user = {"sub": "u1", "username": "attacker", "role": "admin", "is_authorized_approver": False}
    with pytest.raises(HTTPException) as exc_info:
        await checker(current_user=fake_user)
    assert exc_info.value.status_code == 403

    # Approver check with wrong flag
    approver_checker = require_role("reviewer", require_approver=True)
    non_approver_user = {"sub": "u2", "username": "reviewer1", "role": "reviewer", "is_authorized_approver": False}
    with pytest.raises(HTTPException) as exc_info2:
        await approver_checker(current_user=non_approver_user)
    assert exc_info2.value.status_code == 403
    assert "Only authorized approvers" in exc_info2.value.detail

    # Approver check with valid flag
    approver_user = {"sub": "u3", "username": "reviewer2", "role": "reviewer", "is_authorized_approver": True}
    res_user = await approver_checker(current_user=approver_user)
    assert res_user == approver_user
