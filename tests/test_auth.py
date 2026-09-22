"""
NTRO PS26155 Auditor — Authentication Subsystem Unit Tests
Verifies all 20 required security properties of auth.py:
HS256 JWT, PBKDF2 password verification, secret management, AST safety, and dependency boundaries.
"""

import ast
import json
import os
import pathlib
import time
import pytest

import auth
from auth import (
    get_jwt_secret,
    verify_password,
    create_access_token,
    decode_and_verify_jwt,
    base64url_encode,
    base64url_decode,
    AuthError,
    InvalidTokenError,
    TokenExpiredError,
)
from database import hash_password
from main import verify_api_safety_no_execution

TEST_SECRET = b"unit-test-secret-key-at-least-32-bytes-long!!"


# 1. Valid password verification
def test_valid_password_verification():
    pw = "AuditSecOpsPass#2026!"
    pw_hash, salt = hash_password(pw)
    assert verify_password(pw, pw_hash, salt) is True


# 2. Incorrect password rejection
def test_incorrect_password_rejection():
    pw = "AuditSecOpsPass#2026!"
    pw_hash, salt = hash_password(pw)
    assert verify_password("WrongPassword123!", pw_hash, salt) is False
    assert verify_password(pw + "x", pw_hash, salt) is False
    assert verify_password("", pw_hash, salt) is False


# 3. Malformed stored password hash rejection
def test_malformed_stored_password_hash_rejection():
    pw = "AuditSecOpsPass#2026!"
    pw_hash, salt = hash_password(pw)

    # Invalid hex string
    assert verify_password(pw, "non_hex_digest_xyz", salt) is False
    assert verify_password(pw, pw_hash, "non_hex_salt_xyz") is False
    assert verify_password(pw, "", salt) is False
    assert verify_password(pw, pw_hash, "") is False

    # Type mismatches
    assert verify_password(None, pw_hash, salt) is False  # type: ignore
    assert verify_password(pw, None, salt) is False       # type: ignore
    assert verify_password(pw, pw_hash, None) is False    # type: ignore
    assert verify_password(123, pw_hash, salt) is False   # type: ignore
    assert verify_password(pw, 12345, salt) is False      # type: ignore
    assert verify_password(pw, pw_hash, []) is False      # type: ignore


# 4. Valid JWT generation
def test_valid_jwt_generation():
    token = create_access_token(
        user_id="usr-12345",
        username="secops_auditor",
        role="reviewer",
        is_authorized_approver=True,
        secret=TEST_SECRET,
    )
    assert isinstance(token, str)
    parts = token.split(".")
    assert len(parts) == 3
    for p in parts:
        assert len(p) > 0
        assert "=" not in p  # Base64URL must be unpadded


# 5. Valid JWT verification
def test_valid_jwt_verification():
    token = create_access_token(
        user_id="usr-12345",
        username="secops_auditor",
        role="reviewer",
        is_authorized_approver=True,
        secret=TEST_SECRET,
    )
    claims = decode_and_verify_jwt(token, secret=TEST_SECRET)
    assert claims["sub"] == "usr-12345"
    assert claims["username"] == "secops_auditor"
    assert claims["role"] == "reviewer"
    assert claims["is_authorized_approver"] is True
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["exp"] > claims["iat"]


# 6. Tampered payload rejection
def test_tampered_payload_rejection():
    token = create_access_token(
        user_id="usr-12345",
        username="secops_auditor",
        role="uploader",
        is_authorized_approver=False,
        secret=TEST_SECRET,
    )
    parts = token.split(".")
    
    # Tamper payload claims to elevate privileges
    payload = json.loads(base64url_decode(parts[1]).decode("utf-8"))
    payload["role"] = "reviewer"
    payload["is_authorized_approver"] = True
    tampered_payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"
    with pytest.raises(InvalidTokenError, match="Invalid token signature"):
        decode_and_verify_jwt(tampered_token, secret=TEST_SECRET)


# 7. Tampered signature rejection
def test_tampered_signature_rejection():
    token = create_access_token(
        user_id="usr-12345",
        username="secops_auditor",
        role="viewer",
        is_authorized_approver=False,
        secret=TEST_SECRET,
    )
    parts = token.split(".")
    # Mutate signature character
    mutated_sig = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    tampered_token = f"{parts[0]}.{parts[1]}.{mutated_sig}"

    with pytest.raises(InvalidTokenError, match="Invalid token signature"):
        decode_and_verify_jwt(tampered_token, secret=TEST_SECRET)


# 8. Wrong secret rejection
def test_wrong_secret_rejection():
    token = create_access_token(
        user_id="usr-12345",
        username="secops_auditor",
        role="viewer",
        is_authorized_approver=False,
        secret=b"correct-secret-key-32-bytes-long!",
    )
    wrong_secret = b"wrong---secret-key-32-bytes-long!"
    with pytest.raises(InvalidTokenError, match="Invalid token signature"):
        decode_and_verify_jwt(token, secret=wrong_secret)


# 9. alg=none rejection
def test_alg_none_rejection():
    for none_alg in ["none", "None", "NONE"]:
        header = {"alg": none_alg, "typ": "JWT"}
        payload = {
            "sub": "usr-12345",
            "username": "attacker",
            "role": "reviewer",
            "is_authorized_approver": True,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        h_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
        
        # Token with empty signature
        token_empty_sig = f"{h_b64}.{p_b64}."
        with pytest.raises(InvalidTokenError, match="Algorithm 'none' is strictly forbidden"):
            decode_and_verify_jwt(token_empty_sig, secret=TEST_SECRET)

        # Token with fake signature
        fake_sig = base64url_encode(b"dummy-signature")
        token_fake_sig = f"{h_b64}.{p_b64}.{fake_sig}"
        with pytest.raises(InvalidTokenError, match="Algorithm 'none' is strictly forbidden"):
            decode_and_verify_jwt(token_fake_sig, secret=TEST_SECRET)


# 10. Unsupported algorithm rejection
def test_unsupported_algorithm_rejection():
    for bad_alg in ["RS256", "HS512", "ES256", "none", "unknown"]:
        header = {"alg": bad_alg, "typ": "JWT"}
        payload = {
            "sub": "usr-12345",
            "username": "user",
            "role": "viewer",
            "is_authorized_approver": False,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        h_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
        token = f"{h_b64}.{p_b64}.c2lnbmF0dXJl"

        with pytest.raises(InvalidTokenError):
            decode_and_verify_jwt(token, secret=TEST_SECRET)


# 11. Malformed token / wrong segment count rejection
def test_malformed_token_and_segment_count_rejection():
    # Wrong segment counts
    with pytest.raises(InvalidTokenError, match="exactly 3 segments"):
        decode_and_verify_jwt("only-one-segment", secret=TEST_SECRET)
    with pytest.raises(InvalidTokenError, match="exactly 3 segments"):
        decode_and_verify_jwt("two.segments", secret=TEST_SECRET)
    with pytest.raises(InvalidTokenError, match="exactly 3 segments"):
        decode_and_verify_jwt("four.segments.here.now", secret=TEST_SECRET)

    # Non-string input
    with pytest.raises(InvalidTokenError, match="Token must be a string"):
        decode_and_verify_jwt(None, secret=TEST_SECRET)  # type: ignore
    with pytest.raises(InvalidTokenError, match="Token must be a string"):
        decode_and_verify_jwt(12345, secret=TEST_SECRET)  # type: ignore

    # Malformed base64url characters
    with pytest.raises(InvalidTokenError):
        decode_and_verify_jwt("invalid+header.payload.sig", secret=TEST_SECRET)
    with pytest.raises(InvalidTokenError):
        decode_and_verify_jwt("header.invalid/payload.sig", secret=TEST_SECRET)
    with pytest.raises(InvalidTokenError):
        decode_and_verify_jwt("header.payload.invalid=sig", secret=TEST_SECRET)


# 12. Missing required claims rejection
def test_missing_required_claims_rejection():
    required_keys = ["sub", "username", "role", "is_authorized_approver", "exp", "iat"]
    now = int(time.time())
    base_claims = {
        "sub": "u1",
        "username": "tester",
        "role": "viewer",
        "is_authorized_approver": False,
        "iat": now,
        "exp": now + 3600,
    }

    for missing in required_keys:
        bad_claims = dict(base_claims)
        del bad_claims[missing]
        
        h_b64 = base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
        p_b64 = base64url_encode(json.dumps(bad_claims).encode("utf-8"))
        import hmac, hashlib
        sig = hmac.new(TEST_SECRET, f"{h_b64}.{p_b64}".encode("ascii"), hashlib.sha256).digest()
        s_b64 = base64url_encode(sig)
        bad_token = f"{h_b64}.{p_b64}.{s_b64}"

        with pytest.raises(InvalidTokenError, match=f"Missing required claim: '{missing}'"):
            decode_and_verify_jwt(bad_token, secret=TEST_SECRET)


# 13. Wrong claim types rejection
def test_wrong_claim_types_rejection():
    now = int(time.time())
    invalid_type_scenarios = [
        ({"sub": 12345}, "Claim 'sub' must be a non-empty string"),
        ({"sub": ""}, "Claim 'sub' must be a non-empty string"),
        ({"username": ""}, "Claim 'username' must be a non-empty string"),
        ({"username": None}, "Claim 'username' must be a non-empty string"),
        ({"role": 999}, "Invalid role: '999'"),
        ({"is_authorized_approver": "true"}, "Claim 'is_authorized_approver' must be a boolean"),
        ({"is_authorized_approver": 1}, "Claim 'is_authorized_approver' must be a boolean"),
        ({"exp": "tomorrow"}, "Claim 'exp' must be a numeric timestamp"),
        ({"iat": True}, "Claim 'iat' must be a numeric timestamp"),
    ]

    for override, expected_match in invalid_type_scenarios:
        claims = {
            "sub": "u1",
            "username": "tester",
            "role": "viewer",
            "is_authorized_approver": False,
            "iat": now,
            "exp": now + 3600,
        }
        claims.update(override)

        h_b64 = base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
        p_b64 = base64url_encode(json.dumps(claims).encode("utf-8"))
        import hmac, hashlib
        sig = hmac.new(TEST_SECRET, f"{h_b64}.{p_b64}".encode("ascii"), hashlib.sha256).digest()
        s_b64 = base64url_encode(sig)
        bad_token = f"{h_b64}.{p_b64}.{s_b64}"

        with pytest.raises(InvalidTokenError, match=expected_match):
            decode_and_verify_jwt(bad_token, secret=TEST_SECRET)


# 14. Expired token rejection
def test_expired_token_rejection():
    now = 1700000000
    # Token expired 60 seconds ago (beyond 30s leeway)
    token = create_access_token(
        user_id="u1",
        username="tester",
        role="viewer",
        is_authorized_approver=False,
        expires_in=100,
        custom_iat=now - 160,
        secret=TEST_SECRET,
    )
    with pytest.raises(TokenExpiredError, match="Token expired"):
        decode_and_verify_jwt(token, secret=TEST_SECRET, current_time=now)


# 15. 30-second expiration boundary behavior
def test_expiration_30s_boundary_behavior():
    eval_time = 1700000000
    exp_time = eval_time - 25  # Expired 25 seconds ago (within 30s leeway)
    
    token_leeway_ok = create_access_token(
        user_id="u1",
        username="tester",
        role="viewer",
        is_authorized_approver=False,
        expires_in=100,
        custom_iat=exp_time - 100,
        secret=TEST_SECRET,
    )
    # Inside leeway: must succeed
    verified = decode_and_verify_jwt(token_leeway_ok, secret=TEST_SECRET, leeway=30, current_time=eval_time)
    assert verified["sub"] == "u1"

    # Exactly on boundary: eval_time == exp + 30
    exact_boundary_iat = eval_time - 30 - 100
    token_exact_boundary = create_access_token(
        user_id="u1",
        username="tester",
        role="viewer",
        is_authorized_approver=False,
        expires_in=100,
        custom_iat=exact_boundary_iat,
        secret=TEST_SECRET,
    )
    verified_boundary = decode_and_verify_jwt(token_exact_boundary, secret=TEST_SECRET, leeway=30, current_time=eval_time)
    assert verified_boundary["sub"] == "u1"

    # 1 second past boundary: eval_time > exp + 30
    past_boundary_iat = eval_time - 31 - 100
    token_past_boundary = create_access_token(
        user_id="u1",
        username="tester",
        role="viewer",
        is_authorized_approver=False,
        expires_in=100,
        custom_iat=past_boundary_iat,
        secret=TEST_SECRET,
    )
    with pytest.raises(TokenExpiredError, match="Token expired"):
        decode_and_verify_jwt(token_past_boundary, secret=TEST_SECRET, leeway=30, current_time=eval_time)


# 16. Role validation
def test_role_validation():
    # Allowed roles
    for valid_role in ["uploader", "reviewer", "viewer"]:
        token = create_access_token(
            user_id="u1",
            username="tester",
            role=valid_role,
            is_authorized_approver=False,
            secret=TEST_SECRET,
        )
        claims = decode_and_verify_jwt(token, secret=TEST_SECRET)
        assert claims["role"] == valid_role

    # Disallowed roles rejected at token creation
    for bad_role in ["admin", "root", "operator", ""]:
        with pytest.raises(ValueError, match="role must be one of"):
            create_access_token(
                user_id="u1",
                username="tester",
                role=bad_role,
                is_authorized_approver=False,
                secret=TEST_SECRET,
            )


# 17. Boolean validation for is_authorized_approver
def test_boolean_validation_for_is_authorized_approver():
    # Valid booleans
    token_true = create_access_token("u1", "reviewer", "reviewer", True, secret=TEST_SECRET)
    assert decode_and_verify_jwt(token_true, secret=TEST_SECRET)["is_authorized_approver"] is True

    token_false = create_access_token("u2", "viewer", "viewer", False, secret=TEST_SECRET)
    assert decode_and_verify_jwt(token_false, secret=TEST_SECRET)["is_authorized_approver"] is False

    # Non-booleans rejected at token creation
    for invalid in [1, 0, "true", "False", None, []]:
        with pytest.raises(ValueError, match="is_authorized_approver must be a boolean"):
            create_access_token("u1", "user", "reviewer", invalid, secret=TEST_SECRET)  # type: ignore


# 18. Secret generation/persistence behavior
def test_secret_generation_and_persistence(tmp_path, monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    secret_file = tmp_path / "subdir" / ".jwt_secret"

    assert not secret_file.exists()
    secret_bytes_1 = get_jwt_secret(secret_file_path=secret_file)
    assert secret_file.exists()
    assert len(secret_bytes_1) == 32
    assert isinstance(secret_bytes_1, bytes)

    # Calling again on existing file must yield identical persisted secret
    secret_bytes_2 = get_jwt_secret(secret_file_path=secret_file)
    assert secret_bytes_1 == secret_bytes_2


# 19. Environment secret override behavior
def test_environment_secret_override_behavior(tmp_path, monkeypatch):
    test_env_secret = "env-secret-override-at-least-32-chars-long"
    monkeypatch.setenv("JWT_SECRET_KEY", test_env_secret)
    unused_file = tmp_path / ".jwt_secret_unused"

    resolved_secret = get_jwt_secret(secret_file_path=unused_file)
    assert resolved_secret == test_env_secret.encode("utf-8")
    assert not unused_file.exists()  # Env var completely bypasses fallback file creation


# 20. No external JWT/password dependency and AST safety
def test_no_external_jwt_dependency_and_ast_safety():
    # 1. Assert auth.py satisfies the project AST execution-safety invariant
    auth_file = pathlib.Path(auth.__file__).resolve()
    assert verify_api_safety_no_execution(auth_file) is True

    # 2. Assert auth.py imports only standard library and internal database module
    tree = ast.parse(auth_file.read_text(encoding="utf-8"))
    forbidden_third_party = {
        "jwt", "jose", "passlib", "bcrypt", "authlib", "cryptography",
        "pydantic", "fastapi", "starlette", "requests", "urllib3"
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_pkg = alias.name.split(".")[0]
                assert root_pkg not in forbidden_third_party, f"Forbidden third-party import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root_pkg = node.module.split(".")[0]
                assert root_pkg not in forbidden_third_party, f"Forbidden third-party import: {node.module}"
