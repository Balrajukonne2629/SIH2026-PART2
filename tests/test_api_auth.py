"""
NTRO PS26155 Auditor — API Authentication Integration Tests
Tests for Chunk 3:
1. POST /api/auth/login
2. GET /api/auth/me
3. FastAPI get_current_user dependency
4. Bearer token extraction & rejection of invalid channels
5. Timing & enumeration defense
6. In-memory login abuse/rate-limiting
"""

import json
import time
import pytest
from fastapi.testclient import TestClient

import auth
import database
import main
from main import app

client = TestClient(app)

REVIEWER_USER = "api_test_reviewer"
REVIEWER_PASS = "ReviewerPass#2026!"
UPLOADER_USER = "api_test_uploader"
UPLOADER_PASS = "UploaderPass#2026!"
VIEWER_USER = "api_test_viewer"
VIEWER_PASS = "ViewerPass#2026!"
INACTIVE_USER = "api_test_inactive"
INACTIVE_PASS = "InactivePass#2026!"


@pytest.fixture(autouse=True)
def setup_test_users_and_state():
    """Ensures database is initialized, test users are provisioned, and rate-limiting is clean."""
    database.initialize_database()
    main.LOGIN_ATTEMPTS.clear()

    # Seed test users if not present
    for u, p, r, apprv, act in [
        (REVIEWER_USER, REVIEWER_PASS, "reviewer", 1, 1),
        (UPLOADER_USER, UPLOADER_PASS, "uploader", 0, 1),
        (VIEWER_USER, VIEWER_PASS, "viewer", 0, 1),
        (INACTIVE_USER, INACTIVE_PASS, "viewer", 0, 0),
    ]:
        existing = database.get_user_by_username(u)
        if not existing:
            database.create_user(
                username=u,
                password=p,
                role=r,
                is_authorized_approver=apprv,
                is_active=act,
            )
    yield
    main.LOGIN_ATTEMPTS.clear()


# 1. Successful login
def test_successful_login():
    res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == REVIEWER_USER
    assert data["user"]["role"] == "reviewer"
    assert data["user"]["is_authorized_approver"] is True


# 2. Wrong password -> 401
def test_wrong_password():
    res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": "WrongPassword123!"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid username or password"


# 3. Nonexistent username -> 401
def test_nonexistent_username():
    res = client.post(
        "/api/auth/login",
        json={"username": "definitely_nonexistent_user", "password": "AnyPassword123!"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid username or password"


# 4. Inactive user -> 401
def test_inactive_user():
    res = client.post(
        "/api/auth/login",
        json={"username": INACTIVE_USER, "password": INACTIVE_PASS},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid username or password"


# 5. Missing username/password -> validation failure
def test_missing_username_or_password():
    # Empty body -> 422
    assert client.post("/api/auth/login", json={}).status_code == 422
    # Missing password -> 422
    assert client.post("/api/auth/login", json={"username": REVIEWER_USER}).status_code == 422
    # Missing username -> 422
    assert client.post("/api/auth/login", json={"password": REVIEWER_PASS}).status_code == 422
    # Blank username -> 400
    assert client.post("/api/auth/login", json={"username": "   ", "password": REVIEWER_PASS}).status_code == 400


# 6. Successful response contains JWT
def test_successful_response_contains_jwt():
    res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    token = res.json()["access_token"]
    assert isinstance(token, str)
    assert len(token.split(".")) == 3
    claims = auth.decode_and_verify_jwt(token)
    assert claims["username"] == REVIEWER_USER


# 7. Successful response contains sanitized identity
def test_successful_response_contains_sanitized_identity():
    res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    user = res.json()["user"]
    assert set(user.keys()) == {"user_id", "username", "role", "is_authorized_approver"}
    assert user["username"] == REVIEWER_USER


# 8. Response does not contain password_hash
def test_response_does_not_contain_password_hash():
    res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    res_text = res.text
    assert "password_hash" not in res_text
    assert "password_hash" not in res.json()
    assert "password_hash" not in res.json().get("user", {})


# 9. Response does not contain salt
def test_response_does_not_contain_salt():
    res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    assert "salt" not in res.json()
    assert "salt" not in res.json().get("user", {})


# 10. Response does not contain JWT secret
def test_response_does_not_contain_jwt_secret():
    secret = auth.get_jwt_secret()
    res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    assert secret.decode("latin1", errors="ignore") not in res.text


# 11. Valid Bearer token accepted by /api/auth/me
def test_valid_bearer_token_accepted_by_me():
    login_res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    token = login_res.json()["access_token"]
    
    me_res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    data = me_res.json()
    assert data["username"] == REVIEWER_USER
    assert data["role"] == "reviewer"
    assert data["is_authorized_approver"] is True


# 12. Missing Authorization header -> 401
def test_missing_authorization_header():
    res = client.get("/api/auth/me")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers
    assert res.headers["WWW-Authenticate"] == "Bearer"


# 13. Malformed Authorization scheme -> 401
def test_malformed_authorization_scheme():
    # Basic scheme
    res1 = client.get("/api/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert res1.status_code == 401

    # Missing token
    res2 = client.get("/api/auth/me", headers={"Authorization": "Bearer"})
    assert res2.status_code == 401

    # Extra tokens
    res3 = client.get("/api/auth/me", headers={"Authorization": "Bearer token extra"})
    assert res3.status_code == 401

    # Unknown scheme
    res4 = client.get("/api/auth/me", headers={"Authorization": "Token 12345"})
    assert res4.status_code == 401


# 14. Invalid JWT -> 401
def test_invalid_jwt():
    res = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.jwt.token"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid token"


# 15. Tampered JWT -> 401
def test_tampered_jwt():
    login_res = client.post(
        "/api/auth/login",
        json={"username": REVIEWER_USER, "password": REVIEWER_PASS},
    )
    token = login_res.json()["access_token"]
    parts = token.split(".")
    tampered_sig = ("X" if parts[2][0] != "X" else "Y") + parts[2][1:]
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid token"


# 16. Expired JWT -> 401
def test_expired_jwt():
    now = int(time.time())
    expired_token = auth.create_access_token(
        user_id="usr-test",
        username="tester",
        role="viewer",
        is_authorized_approver=False,
        expires_in=10,
        custom_iat=now - 3600,  # issued 1 hr ago, expired 59 min ago
    )
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


# 17. Unsupported JWT algorithm -> 401
def test_unsupported_jwt_algorithm():
    h_b64 = auth.base64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    p_b64 = auth.base64url_encode(json.dumps({
        "sub": "u1", "username": "u", "role": "viewer", "is_authorized_approver": False,
        "iat": int(time.time()), "exp": int(time.time()) + 3600
    }).encode("utf-8"))
    none_token = f"{h_b64}.{p_b64}."

    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {none_token}"})
    assert res.status_code == 401


# 18. /api/auth/me returns correct role
def test_me_returns_correct_role():
    for user, pw, expected_role in [
        (UPLOADER_USER, UPLOADER_PASS, "uploader"),
        (REVIEWER_USER, REVIEWER_PASS, "reviewer"),
        (VIEWER_USER, VIEWER_PASS, "viewer"),
    ]:
        login_res = client.post("/api/auth/login", json={"username": user, "password": pw})
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        assert me_res.json()["role"] == expected_role


# 19. /api/auth/me returns correct is_authorized_approver
def test_me_returns_correct_is_authorized_approver():
    # Reviewer has approver=True
    r_res = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": REVIEWER_PASS})
    r_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {r_res.json()['access_token']}"})
    assert r_me.json()["is_authorized_approver"] is True

    # Uploader has approver=False
    u_res = client.post("/api/auth/login", json={"username": UPLOADER_USER, "password": UPLOADER_PASS})
    u_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {u_res.json()['access_token']}"})
    assert u_me.json()["is_authorized_approver"] is False


# 20. Token is not accepted through query parameter
def test_token_not_accepted_through_query_param():
    login_res = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": REVIEWER_PASS})
    token = login_res.json()["access_token"]
    
    # Send token only in query parameter, no Authorization header
    res = client.get(f"/api/auth/me?token={token}")
    assert res.status_code == 401


# 21. Token is not accepted through request body
def test_token_not_accepted_through_request_body():
    login_res = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": REVIEWER_PASS})
    token = login_res.json()["access_token"]

    # Send token only in json body
    res = client.request("GET", "/api/auth/me", json={"token": token, "access_token": token})
    assert res.status_code == 401


# 22. Repeated failed login attempts trigger the configured abuse defense
def test_repeated_failed_login_attempts_trigger_abuse_defense():
    # 5 failed attempts
    for i in range(5):
        res = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": "WrongPassword"})
        assert res.status_code == 401

    # 6th attempt triggers 429 Too Many Requests
    res_locked = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": "WrongPassword"})
    assert res_locked.status_code == 429
    assert "Too many failed login attempts" in res_locked.json()["detail"]


# 23. Successful login resets relevant failure state
def test_successful_login_resets_failure_state():
    # 3 failed attempts
    for i in range(3):
        client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": "WrongPassword"})

    # Successful login resets the counter
    ok_res = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": REVIEWER_PASS})
    assert ok_res.status_code == 200

    # 3 more failed attempts should not trigger lockout immediately
    for i in range(3):
        res = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": "WrongPassword"})
        assert res.status_code == 401  # Not 429


# 24. Auth failure responses do not reveal whether username exists
def test_auth_failure_responses_do_not_reveal_username_existence():
    # Wrong password on existing user
    res_existing = client.post("/api/auth/login", json={"username": REVIEWER_USER, "password": "BadPassword"})
    
    # Nonexistent user
    res_nonexistent = client.post("/api/auth/login", json={"username": "totally_fictional_user_999", "password": "BadPassword"})

    assert res_existing.status_code == 401
    assert res_nonexistent.status_code == 401
    assert res_existing.json() == res_nonexistent.json()
    assert res_existing.json()["detail"] == "Invalid username or password"
