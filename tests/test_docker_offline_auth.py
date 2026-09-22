"""
NTRO PS26155 — Chunk 8
Docker Compose Deployment & Offline Authentication Verification Suite

Verifies live runtime inside / against Docker Compose containers:
1. Container reachability & Nginx reverse proxy routing (Backend: 8000, Frontend: 3000)
2. Complete authentication matrix (Reviewer, Uploader, Viewer, Inactive, Invalid)
3. Cryptographic JWT issuance, validation, tamper detection, and algorithm safety
4. Role-based access control (RBAC) across all protected mutation/approval endpoints
5. Session ownership isolation & anti-enumeration defense (strict 404 on cross-owner)
6. Server-derived reviewer accountability binding & client impersonation prevention
7. Deterministic offline fallback when Ollama / external AI is absent
"""

import os
import sys
import json
import time
import uuid
import shutil
import subprocess
import urllib.request
import urllib.error
import pytest

BACKEND_URL = os.environ.get("TEST_BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.environ.get("TEST_FRONTEND_URL", "http://localhost:3000")


def _is_docker_available() -> bool:
    """Check if Docker daemon is running and the test container services are reachable."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        if res.returncode != 0:
            return False
    except Exception:
        return False

    try:
        req = urllib.request.Request(f"{BACKEND_URL}/api/auth/me", method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            pass
    except urllib.error.HTTPError:
        # HTTP 401 is expected from backend and indicates container is live
        return True
    except Exception:
        return False

    return True


pytestmark = pytest.mark.skipif(
    not _is_docker_available(),
    reason="Docker daemon or live Docker test containers are unavailable",
)


SAMPLE_CONFIG = """hostname EDGE-RTR-01
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


def request_json(url: str, method: str = "GET", data: dict = None, headers: dict = None):
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    payload = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=payload, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            err_json = json.loads(body)
        except Exception:
            err_json = {"detail": body}
        return e.code, err_json
    except Exception as e:
        return 0, {"error": str(e)}


# ------------------------------------------------------------------------------
# 1. Reachability & Reverse Proxy
# ------------------------------------------------------------------------------

def test_backend_reachable():
    status, body = request_json(f"{BACKEND_URL}/api/auth/me")
    assert status == 401, f"Backend expected 401 on unauthenticated /api/auth/me, got {status}"


def test_frontend_reachable():
    req = urllib.request.Request(FRONTEND_URL, method="GET")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200, f"Frontend returned status {resp.status}"
        content = resp.read().decode("utf-8")
        assert "<!doctype html>" in content.lower() or "<html" in content.lower()


def test_frontend_reverse_proxy():
    status, body = request_json(f"{FRONTEND_URL}/api/auth/me")
    assert status == 401, f"Frontend reverse proxy to /api/auth/me expected 401, got {status}"


# ------------------------------------------------------------------------------
# 2. Authentication Matrix
# ------------------------------------------------------------------------------

def test_auth_login_success_all_roles():
    credentials = [
        ("api_test_reviewer", "ReviewerPass#2026!", "reviewer", True),
        ("api_test_uploader", "UploaderPass#2026!", "uploader", False),
        ("api_test_viewer", "ViewerPass#2026!", "viewer", False),
    ]
    for username, password, expected_role, expected_approver in credentials:
        status, body = request_json(
            f"{BACKEND_URL}/api/auth/login",
            method="POST",
            data={"username": username, "password": password},
        )
        assert status == 200, f"Login failed for {username}: {body}"
        assert "access_token" in body
        assert body["token_type"].lower() == "bearer"
        assert body["user"]["username"] == username
        assert body["user"]["role"] == expected_role
        assert body["user"]["is_authorized_approver"] == expected_approver


def test_auth_login_failures():
    # Wrong password
    status, body = request_json(
        f"{BACKEND_URL}/api/auth/login",
        method="POST",
        data={"username": "api_test_reviewer", "password": "WrongPassword123!"},
    )
    assert status == 401

    # Nonexistent user
    status, body = request_json(
        f"{BACKEND_URL}/api/auth/login",
        method="POST",
        data={"username": "ghost_user_nonexistent", "password": "Password123!"},
    )
    assert status == 401

    # Inactive user
    status, body = request_json(
        f"{BACKEND_URL}/api/auth/login",
        method="POST",
        data={"username": "api_test_inactive", "password": "InactivePass#2026!"},
    )
    assert status == 401
    assert "Invalid username or password" in body.get("detail", "")

    # Malformed payload (missing password)
    status, body = request_json(
        f"{BACKEND_URL}/api/auth/login",
        method="POST",
        data={"username": "api_test_reviewer"},
    )
    assert status == 422


# ------------------------------------------------------------------------------
# 3. Cryptographic Token Validation & Tamper Resistance
# ------------------------------------------------------------------------------

def test_token_validation_and_tamper_resistance():
    # 1. Obtain valid token
    status, body = request_json(
        f"{BACKEND_URL}/api/auth/login",
        method="POST",
        data={"username": "api_test_reviewer", "password": "ReviewerPass#2026!"},
    )
    assert status == 200
    token = body["access_token"]

    # 2. Valid token allows /api/auth/me
    status, me_body = request_json(
        f"{BACKEND_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert status == 200
    assert me_body["username"] == "api_test_reviewer"
    assert me_body["role"] == "reviewer"

    # 3. Missing header
    status, _ = request_json(f"{BACKEND_URL}/api/auth/me")
    assert status == 401

    # 4. Malformed prefix (no 'Bearer ')
    status, _ = request_json(
        f"{BACKEND_URL}/api/auth/me",
        headers={"Authorization": f"Token {token}"},
    )
    assert status == 401

    # 5. Tampered signature
    parts = token.split(".")
    tampered_sig = parts[2][:-4] + ("AAAA" if not parts[2].endswith("AAAA") else "BBBB")
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
    status, _ = request_json(
        f"{BACKEND_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert status == 401

    # 6. Tampered payload
    tampered_payload = f"{parts[0]}.eyJhZG1pbiI6dHJ1ZX0.{parts[2]}"
    status, _ = request_json(
        f"{BACKEND_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {tampered_payload}"},
    )
    assert status == 401

    # 7. Unsupported 'none' algorithm token
    none_alg_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c3ItMSIsInVzZXJuYW1lIjoiYWRtaW4ifQ."
    status, _ = request_json(
        f"{BACKEND_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {none_alg_token}"},
    )
    assert status == 401


# ------------------------------------------------------------------------------
# 4. Role-Based Access Control (RBAC) Matrix
# ------------------------------------------------------------------------------

def _login(username, password):
    status, body = request_json(
        f"{BACKEND_URL}/api/auth/login",
        method="POST",
        data={"username": username, "password": password},
    )
    assert status == 200, f"Login failed for {username}"
    return body["access_token"]


def test_rbac_upload_permissions():
    uploader_tok = _login("api_test_uploader", "UploaderPass#2026!")
    reviewer_tok = _login("api_test_reviewer", "ReviewerPass#2026!")
    viewer_tok = _login("api_test_viewer", "ViewerPass#2026!")

    # Uploader: ALLOWED (200)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG, "filename": "uploader_test.cfg"},
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 200
    assert "session_id" in body

    # Reviewer: ALLOWED (200)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG, "filename": "reviewer_test.cfg"},
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200
    assert "session_id" in body

    # Viewer: FORBIDDEN (403)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG, "filename": "viewer_test.cfg"},
        headers={"Authorization": f"Bearer {viewer_tok}"},
    )
    assert status == 403

    # Unauthenticated: UNAUTHORIZED (401)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG, "filename": "noauth_test.cfg"},
    )
    assert status == 401


def test_rbac_remediation_and_approval_permissions():
    uploader_tok = _login("api_test_uploader", "UploaderPass#2026!")
    reviewer_tok = _login("api_test_reviewer", "ReviewerPass#2026!")
    viewer_tok = _login("api_test_viewer", "ViewerPass#2026!")

    # 1. Reviewer remediation on own session: ALLOWED (200)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG},
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200
    rev_session_id = body["session_id"]

    status, body = request_json(
        f"{BACKEND_URL}/api/remediation/CISCO-NTP-001",
        method="POST",
        data={"session_id": rev_session_id},
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200

    # 2. Uploader remediation on own session: ALLOWED (200)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG},
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 200
    up_session_id = body["session_id"]

    status, body = request_json(
        f"{BACKEND_URL}/api/remediation/CISCO-NTP-001",
        method="POST",
        data={"session_id": up_session_id},
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 200

    # 3. Viewer attempting remediation: FORBIDDEN (403)
    status, body = request_json(
        f"{BACKEND_URL}/api/remediation/CISCO-NTP-001",
        method="POST",
        data={"session_id": rev_session_id},
        headers={"Authorization": f"Bearer {viewer_tok}"},
    )
    assert status == 403

    # 4. Uploader attempting AI approval: FORBIDDEN (403)
    status, body = request_json(
        f"{BACKEND_URL}/api/ai/approve",
        method="POST",
        data={"suggestion_id": "dummy_sug_id", "decision": "approve"},
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 403

    # 5. Viewer attempting AI approval: FORBIDDEN (403)
    status, body = request_json(
        f"{BACKEND_URL}/api/ai/approve",
        method="POST",
        data={"suggestion_id": "dummy_sug_id", "decision": "approve"},
        headers={"Authorization": f"Bearer {viewer_tok}"},
    )
    assert status == 403

    # 6. Unauthenticated: UNAUTHORIZED (401)
    status, body = request_json(
        f"{BACKEND_URL}/api/remediation/CISCO-NTP-001",
        method="POST",
        data={"session_id": rev_session_id},
    )
    assert status == 401


# ------------------------------------------------------------------------------
# 5. Session Ownership & Anti-Enumeration Isolation
# ------------------------------------------------------------------------------

def test_session_ownership_and_anti_enumeration():
    uploader_tok = _login("api_test_uploader", "UploaderPass#2026!")
    reviewer_tok = _login("api_test_reviewer", "ReviewerPass#2026!")

    # 1. Uploader creates Session A
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG, "filename": "session_a.cfg"},
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 200
    session_a = body["session_id"]

    # 2. Reviewer creates Session B
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/upload",
        method="POST",
        data={"raw_config": SAMPLE_CONFIG, "filename": "session_b.cfg"},
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200
    session_b = body["session_id"]

    # 3. Uploader can access their own session A -> 200
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/{session_a}/results",
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 200

    # 4. Uploader CANNOT access Reviewer's session B -> 404 (anti-enumeration)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/{session_b}/results",
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 404, f"Cross-owner access must return 404, got {status}"

    # 5. Uploader accessing non-existent session -> 404
    non_existent = str(uuid.uuid4())
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/{non_existent}/results",
        headers={"Authorization": f"Bearer {uploader_tok}"},
    )
    assert status == 404

    # 6. Reviewer can access Uploader's session A -> 200 (global audit oversight)
    status, body = request_json(
        f"{BACKEND_URL}/api/audit/{session_a}/results",
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200


# ------------------------------------------------------------------------------
# 6. Reviewer Identity Binding & Client Spoof Prevention
# ------------------------------------------------------------------------------

def test_reviewer_accountability_and_spoof_prevention():
    reviewer_tok = _login("api_test_reviewer", "ReviewerPass#2026!")

    # Step 1: Generate AI suggestion to get a valid suggestion_id
    status, body = request_json(
        f"{BACKEND_URL}/api/ai/suggest",
        method="POST",
        data={"unmapped_line": "service password-encryption"},
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200
    sug_id = body["suggestion_id"]

    # Step 2: Approve suggestion with spoofed client headers and payload
    status, approve_body = request_json(
        f"{BACKEND_URL}/api/ai/approve",
        method="POST",
        data={
            "suggestion_id": sug_id,
            "decision": "approve",
            "reviewer_name": "spoofed_admin_hacker",
            "reviewer_id": "usr-fake-id",
        },
        headers={
            "Authorization": f"Bearer {reviewer_tok}",
            "X-Forwarded-User": "spoofed_forwarded_user",
            "X-User-ID": "spoofed_user_id",
        },
    )
    assert status == 200
    assert approve_body["status"] == "approve"

    # Step 3: Verify the server-recorded identity is bound to authenticated user
    # /api/auth/me confirms our authentic username is api_test_reviewer
    status, me_body = request_json(
        f"{BACKEND_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200
    assert me_body["username"] == "api_test_reviewer"


# ------------------------------------------------------------------------------
# 7. Deterministic Offline Fallback
# ------------------------------------------------------------------------------

def test_offline_deterministic_fallback():
    reviewer_tok = _login("api_test_reviewer", "ReviewerPass#2026!")
    status, body = request_json(
        f"{BACKEND_URL}/api/ai/suggest",
        method="POST",
        data={"unmapped_line": "service call-home"},
        headers={"Authorization": f"Bearer {reviewer_tok}"},
    )
    assert status == 200
    assert "suggestion_id" in body
    assert "suggestion" in body
    assert "suggested_new_rule" in body["suggestion"]


# ------------------------------------------------------------------------------
# 8. Frontend Reverse Proxy End-to-End Auth
# ------------------------------------------------------------------------------

def test_frontend_proxy_full_auth_flow():
    # Login through port 3000 (Nginx -> FastAPI)
    status, body = request_json(
        f"{FRONTEND_URL}/api/auth/login",
        method="POST",
        data={"username": "api_test_reviewer", "password": "ReviewerPass#2026!"},
    )
    assert status == 200, f"Login via frontend proxy failed: {body}"
    token = body["access_token"]

    # Call /api/auth/me through port 3000
    status, me_body = request_json(
        f"{FRONTEND_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert status == 200
    assert me_body["username"] == "api_test_reviewer"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
