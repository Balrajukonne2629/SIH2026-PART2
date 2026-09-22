"""
NTRO PS26155 Auditor — Zero-Dependency Authentication Subsystem
Pure Python HS256 JWT encoding/decoding and PBKDF2-HMAC-SHA256 password verification.
Offline-first, on-premises compliant. No third-party auth dependencies.
"""

import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import time
from typing import Optional, Dict, Any, Union

from src.database import hash_password, BASE_DIR, DATA_DIR

DEFAULT_SECRET_FILE = DATA_DIR / ".jwt_secret"
JWT_EXPIRATION_SECONDS = 8 * 3600  # 8 hours
JWT_LEEWAY_SECONDS = 30           # 30 seconds clock-skew leeway
ALLOWED_ROLES = {"uploader", "reviewer", "viewer"}
REQUIRED_CLAIMS = ("sub", "username", "role", "is_authorized_approver", "exp", "iat")


class AuthError(Exception):
    """Base exception for authentication and token validation errors."""
    pass


class InvalidTokenError(AuthError):
    """Raised when token format, algorithm, claims, or cryptographic signature are invalid."""
    pass


class TokenExpiredError(AuthError):
    """Raised when a token has expired beyond allowable clock-skew leeway."""
    pass


def get_jwt_secret(secret_file_path: Optional[Union[str, pathlib.Path]] = None) -> bytes:
    """Retrieves or provisions the 256-bit secret key used for HS256 JWT signing.
    
    Resolution hierarchy:
    1. JWT_SECRET_KEY environment variable (if non-empty).
    2. Persistent secret file at secret_file_path (defaults to data/.jwt_secret).
       If absent:
         - Generates exactly 32 cryptographically secure random bytes.
         - Persists them to disk with 0600 permissions where supported.
    
    Fails closed (raises RuntimeError) if neither the environment secret nor
    the fallback file can be securely read or created. Never falls back to a hard-coded key.
    Never logs or exposes the secret.
    """
    env_secret = os.environ.get("JWT_SECRET_KEY")
    if env_secret:
        secret_bytes = env_secret.encode("utf-8")
        if not secret_bytes:
            raise RuntimeError("Environment variable JWT_SECRET_KEY is empty.")
        return secret_bytes

    file_path = pathlib.Path(secret_file_path) if secret_file_path is not None else DEFAULT_SECRET_FILE
    
    if file_path.exists():
        try:
            secret = file_path.read_bytes()
            if not secret:
                raise RuntimeError(f"JWT secret file at {file_path} is empty.")
            return secret
        except Exception as e:
            raise RuntimeError(f"Failed to read JWT secret file at {file_path}: {e}")

    # File does not exist: generate exactly 32 cryptographically secure random bytes
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        new_secret = secrets.token_bytes(32)
        
        # Atomically create and write with 0600 permissions where supported
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(file_path), flags, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(new_secret)
            
        try:
            os.chmod(str(file_path), 0o600)
        except Exception:
            pass  # Windows or restricted file system
            
        return new_secret
    except Exception as e:
        raise RuntimeError(f"Failed to safely generate and persist JWT secret at {file_path}: {e}")


def verify_password(plain_password: str, password_hash: str, salt: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash and salt.
    
    Reuses database.hash_password (600,000 iterations PBKDF2-HMAC-SHA256).
    Uses hmac.compare_digest for constant-time comparison to prevent timing side-channels.
    Safely returns False on malformed inputs, type mismatches, or non-hex salts.
    Never logs plaintext passwords or raises exceptions on invalid data.
    """
    if not isinstance(plain_password, str) or not isinstance(password_hash, str) or not isinstance(salt, str):
        return False
    if not password_hash or not salt:
        return False
    try:
        candidate_hash, _ = hash_password(plain_password, salt_hex=salt)
        return hmac.compare_digest(candidate_hash, password_hash)
    except Exception:
        return False


def base64url_encode(data: bytes) -> str:
    """Encodes bytes to unpadded Base64URL string (RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(data: str) -> bytes:
    """Decodes unpadded Base64URL string to bytes strictly (RFC 7515).
    Rejects malformed characters, invalid lengths, or padding characters.
    """
    if not isinstance(data, str):
        raise ValueError("Base64URL input must be a string.")
    
    # Strict validation: RFC 7515 Section 2 forbids '=' and non-base64url characters
    valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for ch in data:
        if ch not in valid_chars:
            raise ValueError(f"Invalid Base64URL character: {ch!r}")
            
    rem = len(data) % 4
    if rem == 1:
        raise ValueError("Invalid Base64URL string length.")
    padding = "=" * ((4 - rem) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    is_authorized_approver: bool,
    expires_in: int = JWT_EXPIRATION_SECONDS,
    secret: Optional[bytes] = None,
    custom_iat: Optional[int] = None
) -> str:
    """Creates a signed HS256 JWT access token with required identity claims.
    
    Claims:
        sub: user_id (string)
        username: username (string)
        role: role ('uploader', 'reviewer', 'viewer')
        is_authorized_approver: boolean
        iat: issued-at timestamp (seconds)
        exp: expiration timestamp (seconds)
    """
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id must be a non-empty string.")
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string.")
    if role not in ALLOWED_ROLES:
        raise ValueError(f"role must be one of {sorted(ALLOWED_ROLES)}, got {role!r}")
    if type(is_authorized_approver) is not bool:
        raise ValueError("is_authorized_approver must be a boolean.")

    signing_secret = secret if secret is not None else get_jwt_secret()

    now = int(time.time()) if custom_iat is None else int(custom_iat)
    exp = now + int(expires_in)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "is_authorized_approver": is_authorized_approver,
        "iat": now,
        "exp": exp,
    }

    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    header_b64 = base64url_encode(header_json)
    payload_b64 = base64url_encode(payload_json)

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(signing_secret, signing_input, hashlib.sha256).digest()
    sig_b64 = base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_and_verify_jwt(
    token: str,
    secret: Optional[bytes] = None,
    leeway: int = JWT_LEEWAY_SECONDS,
    current_time: Optional[float] = None
) -> Dict[str, Any]:
    """Decodes and cryptographically verifies an HS256 JWT.
    
    Security verification sequence:
    1. Validates string format and asserts exactly 3 segments (header.payload.signature).
    2. Strictly parses header to verify alg == 'HS256'.
       Explicitly rejects alg == 'none', None, or any unsupported algorithm.
    3. Computes expected HMAC-SHA256 signature and verifies against token signature
       using constant-time hmac.compare_digest() BEFORE trusting or decoding payload.
    4. Decodes and parses payload JSON.
    5. Validates presence and types of all required claims:
       (sub, username, role, is_authorized_approver, exp, iat).
    6. Validates expiration: current_time <= exp + leeway.
    
    Returns:
        The validated payload claims dictionary.
    Raises:
        InvalidTokenError: on malformed token, unsupported alg, signature mismatch, or claim violations.
        TokenExpiredError: when token has expired beyond allowable leeway.
    """
    if not isinstance(token, str):
        raise InvalidTokenError("Token must be a string.")
    
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError(f"Token must have exactly 3 segments, found {len(parts)}.")

    header_b64, payload_b64, sig_b64 = parts

    # 1. Parse and validate header strictly
    try:
        header_bytes = base64url_decode(header_b64)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        raise InvalidTokenError(f"Malformed token header: {e}")

    if not isinstance(header, dict):
        raise InvalidTokenError("Token header must be a JSON object.")

    alg = header.get("alg")
    if alg is None or str(alg).lower() == "none":
        raise InvalidTokenError("Algorithm 'none' is strictly forbidden.")
    if alg != "HS256":
        raise InvalidTokenError(f"Unsupported algorithm '{alg}'. Only 'HS256' is accepted.")

    # 2. Verify signature BEFORE trusting payload claims
    signing_secret = secret if secret is not None else get_jwt_secret()
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(signing_secret, signing_input, hashlib.sha256).digest()

    try:
        received_sig = base64url_decode(sig_b64)
    except Exception as e:
        raise InvalidTokenError(f"Malformed signature encoding: {e}")

    if not hmac.compare_digest(received_sig, expected_sig):
        raise InvalidTokenError("Invalid token signature.")

    # 3. Cryptographic signature verified — now decode and parse payload
    try:
        payload_bytes = base64url_decode(payload_b64)
        claims = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise InvalidTokenError(f"Malformed token payload: {e}")

    if not isinstance(claims, dict):
        raise InvalidTokenError("Token payload must be a JSON object.")

    # 4. Validate required claims presence and types
    for required in REQUIRED_CLAIMS:
        if required not in claims:
            raise InvalidTokenError(f"Missing required claim: '{required}'.")

    sub = claims["sub"]
    if not isinstance(sub, str) or not sub.strip():
        raise InvalidTokenError("Claim 'sub' must be a non-empty string.")

    username = claims["username"]
    if not isinstance(username, str) or not username.strip():
        raise InvalidTokenError("Claim 'username' must be a non-empty string.")

    role = claims["role"]
    if role not in ALLOWED_ROLES:
        raise InvalidTokenError(f"Invalid role: '{role}'. Must be one of {sorted(ALLOWED_ROLES)}.")

    is_approver = claims["is_authorized_approver"]
    if type(is_approver) is not bool:
        raise InvalidTokenError("Claim 'is_authorized_approver' must be a boolean.")

    for num_claim in ("exp", "iat"):
        val = claims[num_claim]
        if type(val) is bool or not isinstance(val, (int, float)):
            raise InvalidTokenError(f"Claim '{num_claim}' must be a numeric timestamp.")

    # 5. Check expiration with leeway: current_time <= exp + leeway
    now = time.time() if current_time is None else float(current_time)
    exp = claims["exp"]
    if now > exp + leeway:
        raise TokenExpiredError(f"Token expired at timestamp {exp} (current: {now}, leeway: {leeway}s).")

    return claims
