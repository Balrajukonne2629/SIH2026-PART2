"""FastAPI application for the NTRO PS26155 Network Security Compliance Auditor.

Integrates deterministic compliance evaluation engines, security authentication/RBAC,
AI model management, remediation generation, and cryptographic audit ledger.

Exposes REST endpoints for:
Authentication:
1.  POST /api/auth/login                     - Authenticates user and returns HS256 JWT access token
2.  GET  /api/auth/me                        - Returns authenticated user identity, role, and approver status

Configuration Audit & Ingestion:
3.  POST /api/audit/upload                   - Ingests config file/text, normalizes to CSM, runs baseline evaluation
4.  GET  /api/audit/{session_id}/results     - Retrieves cached audit results with session ownership checks

Multi-Framework Compliance Engine:
5.  GET  /api/compliance/frameworks          - Discovers registered compliance frameworks (CIS, DISA-STIG)
6.  POST /api/compliance/evaluate            - Evaluates configuration against specified compliance frameworks

AI Unmapped Line Suggestion & Reviewer Approval:
7.  POST /api/ai/suggest                     - Local DistilBERT semantic analysis on unmapped lines
8.  POST /api/ai/approve                     - Reviewer-gated approval/rejection writing to trusted_mappings

Remediation & Conflict Detection:
9.  POST /api/remediation/{rule_id}          - Renders Jinja2 CLI fix, checks static conflicts, provides AI rationale

Audit Ledger & Cryptographic Verification:
10. POST /api/audit/finalize                 - Records tamper-evident audit entry in SQLite ledger & generates PDF
11. GET  /api/ledger                         - Lists historical audit ledger records
12. GET  /api/ledger/verify                  - Cryptographically verifies SHA-256 hash-chain integrity
13. GET  /api/report/{entry_id}/download     - Downloads certified tamper-evident PDF compliance report
14. GET  /api/report/{entry_id}/verify       - Cryptographically validates embedded PDF hash against SQLite ledger

AI Model Manager Telemetry & Control:
15. GET  /api/model/status                   - Returns active AI model mode, hardware probe, and Ollama status
16. POST /api/model/mode                     - Updates AI runtime mode (fast, quality, auto, override)

Architectural Invariants & Security Boundaries:
- Persistence: SQLite database (data/auditor.db) stores users, sessions, mappings, and the audit ledger.
- Authentication & RBAC: Pure-Python HS256 JWT validation and PBKDF2 password hashing in auth.py.
  Strict role enforcement (reviewer, uploader, viewer) with server-derived reviewer identity binding.
- Session Isolation: Session ownership enforced by username (anti-enumeration returns strict 404).
- Deterministic Authority: Compliance scoring and evaluation are strictly deterministic (CIS 7 controls,
  DISA-STIG 10 controls). AI inference (DistilBERT unmapped suggestion, Ollama explainer) is purely advisory.
- AST Execution Safety: Remediation commands are strictly DISPLAY ONLY; zero subprocess/exec capabilities exist.
- Audit Ledger: Monotonically chained cryptographic hash ledger in SQLite table audit_ledger.
  Legacy LOG_FILE (audit_log.jsonl) parameter is retained as a backward-compatible adapter interface.
"""
import ast
import datetime
import hashlib
import json
import pathlib
import sqlite3
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Direct imports of the backend modules
import ai_model_manager
import ai_suggester
import audit_log
import remediation_engine
import report_generator
import vendor_registry
from vendor_registry import (
    get_default_vendor_registry,
    ingest_configuration,
    UnsupportedVendorError,
    UndeterminedVendorError,
)

BASE_DIR = pathlib.Path(__file__).parent.resolve()
RULES_FILE = BASE_DIR / "07_Compliance_Scanners" / "Rule_Library" / "extracted" / "Rule_Library" / "vendor_rule_mapping.json"
TRUSTED_FILE = BASE_DIR / "trusted_mappings.json"
PENDING_FILE = BASE_DIR / "pending_suggestions.json"
LOG_FILE = BASE_DIR / "audit_log.jsonl"
PDF_FILE = BASE_DIR / "cisco_compliance_report.pdf"

import auth
import database
import compliance_framework
import cis_benchmark_cisco_iosxe
import disa_stig_cisco_iosxe
import compliance_aggregator

# Register default deterministic compliance frameworks
cis_benchmark_cisco_iosxe.register_cis_cisco_iosxe()
disa_stig_cisco_iosxe.register_disa_stig_cisco_iosxe()


app = FastAPI(
    title="NTRO Network Security Compliance Auditor API",
    description="Thin REST wrapper for Cisco IOS-XE CSM compliance parsing, local AI suggestions, remediation, and hash-chained audit ledger.",
    version="1.0.0"
)

# Enable CORS for local development (React dev server on port 3000, 5173, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    database.initialize_database()


# --- Helper Loaders (Adapter Layer) ---
def load_baseline_rules() -> List[dict]:
    """Loads baseline rules from Rule Library JSON without altering cisco_auditor signature."""
    if RULES_FILE.exists():
        data = json.loads(RULES_FILE.read_text(encoding="utf-8-sig"))
        return data["vendors"]["Cisco IOS-XE"]["rules"]
    return []


def load_trusted_rules() -> List[dict]:
    """Loads approved trusted custom rules from SQLite trusted_mappings table."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM trusted_mappings')
    rows = cur.fetchall()
    conn.close()
    
    rules = []
    for row in rows:
        rules.append({
            "vendor_rule_id": row["vendor_rule_id"],
            "common_rule_id": row["common_rule_id"],
            "internalTitle": row["internalTitle"],
            "csmFieldChecked": row["csmFieldChecked"],
            "condition": row["condition"],
            "configuration_evidence": json.loads(row["configuration_evidence"]),
            "check_focus": json.loads(row["check_focus"]),
            "frameworkMappings": json.loads(row["frameworkMappings"]),
            "version_info": json.loads(row["version_info"])
        })
    return rules


# --- Pydantic Request Models ---
class LoginRequest(BaseModel):
    username: str
    password: str


class UserIdentityResponse(BaseModel):
    user_id: str
    username: str
    role: str
    is_authorized_approver: bool


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserIdentityResponse


class SuggestRequest(BaseModel):
    unmapped_line: str


class ApproveRequest(BaseModel):
    suggestion_id: str
    reviewer_name: Optional[str] = None  # Accepted for backward compatibility; ignored for authoritative identity
    decision: str  # 'approve', 'reject', or 'approve_with_correction'
    corrected_mapping: Optional[dict] = None
    session_id: Optional[str] = None


class RemediationRequest(BaseModel):
    session_id: Optional[str] = None
    csm: Optional[dict] = None


class FinalizeRequest(BaseModel):
    session_id: str
    remediation_summary: Optional[dict] = None


class ModelModeRequest(BaseModel):
    mode: str
    override_model: Optional[str] = None


class FrameworkMetadataResponse(BaseModel):
    framework_id: str
    name: str
    version: str
    description: str
    vendor_scope: Optional[str] = None
    control_namespace: str
    control_count: int
    severity_distribution: Dict[str, int] = {}
    enabled: bool = True


class FrameworksListResponse(BaseModel):
    frameworks: List[FrameworkMetadataResponse]
    total_count: int


class ComplianceEvaluateRequest(BaseModel):
    session_id: Optional[str] = None
    csm: Optional[Dict[str, Any]] = None
    raw_config: Optional[str] = None
    vendor: Optional[str] = None
    framework_ids: Optional[List[str]] = None



# --- In-Memory Login Rate-Limiting / Abuse Defense ---
LOGIN_ATTEMPTS: Dict[str, Dict[str, Any]] = {}
LOGIN_MAX_FAILED_ATTEMPTS = 5
LOGIN_LOCKOUT_DURATION = 60.0  # seconds
LOGIN_ATTEMPTS_MAX_ENTRIES = 1000

def _clean_expired_login_attempts(now: float):
    expired = [
        k for k, v in LOGIN_ATTEMPTS.items()
        if now > v.get("lockout_until", 0) and (now - v.get("last_attempt", 0)) > LOGIN_LOCKOUT_DURATION
    ]
    for k in expired:
        LOGIN_ATTEMPTS.pop(k, None)
    if len(LOGIN_ATTEMPTS) > LOGIN_ATTEMPTS_MAX_ENTRIES:
        sorted_keys = sorted(LOGIN_ATTEMPTS.keys(), key=lambda k: LOGIN_ATTEMPTS[k].get("last_attempt", 0))
        for k in sorted_keys[: len(LOGIN_ATTEMPTS) - LOGIN_ATTEMPTS_MAX_ENTRIES]:
            LOGIN_ATTEMPTS.pop(k, None)

def check_login_rate_limit(username: str) -> bool:
    """Returns True if login attempt is permitted, False if locked out."""
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    _clean_expired_login_attempts(now)
    key = username.lower().strip()
    entry = LOGIN_ATTEMPTS.get(key)
    if entry:
        if now < entry.get("lockout_until", 0):
            return False
        if now - entry.get("last_attempt", 0) > LOGIN_LOCKOUT_DURATION:
            LOGIN_ATTEMPTS.pop(key, None)
    return True

def record_failed_login(username: str):
    """Records a failed login attempt and applies temporary lockout if threshold reached."""
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    _clean_expired_login_attempts(now)
    key = username.lower().strip()
    entry = LOGIN_ATTEMPTS.setdefault(key, {"count": 0, "last_attempt": now, "lockout_until": 0})
    entry["count"] += 1
    entry["last_attempt"] = now
    if entry["count"] >= LOGIN_MAX_FAILED_ATTEMPTS:
        entry["lockout_until"] = now + LOGIN_LOCKOUT_DURATION

def reset_failed_login(username: str):
    """Clears failed login attempt state on successful authentication."""
    key = username.lower().strip()
    LOGIN_ATTEMPTS.pop(key, None)


# --- FastAPI Authentication Dependency ---
async def get_current_user(request: Request) -> Dict[str, Any]:
    """FastAPI authentication dependency.
    Extracts Bearer token from Authorization header and cryptographically validates HS256 JWT.
    Fails closed with HTTP 401 on missing, malformed, or invalid tokens.
    Does not perform database lookups; claims are verified statelessly.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"}
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication scheme. Expected Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = parts[1]
    try:
        claims = auth.decode_and_verify_jwt(token)
        return claims
    except auth.TokenExpiredError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token", error_description="The token has expired"'}
        )
    except auth.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
        )
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"}
        )


# --- FastAPI Authorization Dependency (RBAC) ---
def require_role(*allowed_roles: str, require_approver: bool = False):
    """FastAPI dependency factory enforcing Role-Based Access Control (RBAC).
    
    Consumes the authenticated identity from get_current_user().
    Asserts current_user['role'] is in allowed_roles.
    If require_approver is True, additionally asserts current_user['is_authorized_approver'] is True.
    
    Returns:
        The authenticated user claims dictionary.
    Raises:
        HTTPException(403, detail="Forbidden: ...") on role/approver mismatch.
    """
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user.get("role")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Role '{user_role}' is not permitted to access this resource"
            )
        if require_approver and not current_user.get("is_authorized_approver"):
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Only authorized approvers can approve compliance rules"
            )
        return current_user
    return role_checker


# --- Resource Ownership & Session Isolation ---
def check_session_ownership(session: Optional[Dict[str, Any]], current_user: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """Enforces audit session resource isolation and anti-enumeration.
    
    Reviewers may access any session.
    Uploaders may only access sessions where session['owner_user_id'] == current_user['sub'].
    Cross-owner access attempts by uploaders raise HTTP 404 (not 403) to prevent resource enumeration.
    """
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found."
        )
    if current_user.get("role") == "uploader" and session.get("owner_user_id") != current_user.get("sub"):
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found."
        )
    return session


def get_authenticated_session(session_id: str, current_user: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieves an audit session from SQLite and enforces resource ownership isolation.
    
    Raises HTTP 404 if session does not exist or if caller is an uploader attempting
    cross-owner session access (anti-enumeration defense).
    """
    raw_session = database.get_session(session_id)
    return check_session_ownership(raw_session, current_user, session_id)


# --- Authentication Endpoints ---
@app.post("/api/auth/login", response_model=LoginResponse)

async def login(req: LoginRequest):
    """Authenticates credentials against database and returns an 8-hour HS256 access token.
    Fails closed without revealing whether the username exists.
    Protected against brute-force abuse via in-memory rate limiting.
    """
    username = req.username.strip()
    if not username or not req.password:
        raise HTTPException(
            status_code=400,
            detail="Username and password must not be empty"
        )

    if not check_login_rate_limit(username):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later."
        )

    user = database.get_user_by_username(username)
    
    # Timing attack mitigation: verify dummy hash if user does not exist
    dummy_salt = "00" * 16
    dummy_hash = "00" * 32
    if not user:
        record_failed_login(username)
        auth.verify_password(req.password, dummy_hash, dummy_salt)
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not user.get("is_active"):
        record_failed_login(username)
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not auth.verify_password(req.password, user["password_hash"], user["salt"]):
        record_failed_login(username)
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Success: reset rate limit tracking
    reset_failed_login(username)

    token = auth.create_access_token(
        user_id=user["user_id"],
        username=user["username"],
        role=user["role"],
        is_authorized_approver=bool(user["is_authorized_approver"])
    )

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user=UserIdentityResponse(
            user_id=user["user_id"],
            username=user["username"],
            role=user["role"],
            is_authorized_approver=bool(user["is_authorized_approver"])
        )
    )


@app.get("/api/auth/me", response_model=UserIdentityResponse)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns the sanitized identity of the authenticated user.
    Extracts identity strictly from the verified JWT claims.
    """
    return UserIdentityResponse(
        user_id=current_user["sub"],
        username=current_user["username"],
        role=current_user["role"],
        is_authorized_approver=bool(current_user["is_authorized_approver"])
    )


# --- 1. POST /api/audit/upload ---

@app.post("/api/audit/upload")
async def audit_upload(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_config: Optional[str] = Form(None),
    vendor: Optional[str] = Form(None),
    current_user: Dict[str, Any] = Depends(require_role("uploader", "reviewer"))
):
    """Accepts uploaded config file (multipart) or raw text.
    Runs unified ingestion boundary (detection/selection -> vendor adapter -> CSM).
    Evaluates baseline rules and caches results in-memory keyed by session_id.
    Does NOT write to audit_log yet.
    """
    text = ""
    filename = "labeled_test_config.txt"

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            text = body.get("raw_config", "")
            filename = body.get("filename", filename)
            vendor = body.get("vendor", vendor)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Malformed JSON request: {e}")
    elif file is not None:
        file_bytes = await file.read()
        text = file_bytes.decode("utf-8", errors="replace")
        filename = file.filename or filename
    elif raw_config:
        text = raw_config
    else:
        raise HTTPException(
            status_code=400,
            detail="No configuration payload provided. Upload a file (.txt/.cfg) or supply raw_config."
        )

    if not text.strip():
        raise HTTPException(status_code=400, detail="Configuration content is empty.")

    try:
        baseline_rules = load_baseline_rules()
        trusted_rules = load_trusted_rules()

        # Step 1 & 2: Ingest configuration through vendor boundary and evaluate baseline rules
        csm, adapter = ingest_configuration(
            raw_text=text,
            filename=filename,
            vendor=vendor,
            trusted_rules=trusted_rules,
        )
        evals = adapter.evaluate_legacy_rules(csm, baseline_rules, trusted_rules=trusted_rules)
        config_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        session_id = str(uuid.uuid4())
        session_data = {
            "session_id": session_id,
            "csm": csm,
            "evals": evals,
            "raw_config_text": text,
            "filename": filename,
            "config_file_hash": config_hash,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "owner_user_id": current_user["sub"]
        }
        database.save_session(session_data)

        pass_count = sum(1 for v in evals.values() if v.get("status") == "Pass")
        fail_count = sum(1 for v in evals.values() if v.get("status") == "Fail")
        unknown_count = sum(1 for v in evals.values() if v.get("status") == "Unknown")

        return {
            "session_id": session_id,
            "device_hostname": csm.get("device", {}).get("hostname", "unknown"),
            "platform": csm.get("device", {}).get("platform") or "unknown",
            "config_file_hash": config_hash,
            "summary": {
                "total": len(evals),
                "pass": pass_count,
                "fail": fail_count,
                "unknown": unknown_count
            },
            "csm_summary": {
                "hostname": csm.get("device", {}).get("hostname"),
                "platform": csm.get("device", {}).get("platform"),
                "interfaces_count": len(csm.get("interfaces", [])),
                "management_ip": csm.get("device", {}).get("management_ip")
            },
            "rule_results": evals,
            "unmapped_lines": csm.get("unmapped_lines", [])
        }
    except (UnsupportedVendorError, UndeterminedVendorError) as ve:
        raise HTTPException(status_code=422, detail=str(ve))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit parsing failed: {e}")


# --- 2. GET /api/audit/{session_id}/results ---
@app.get("/api/audit/{session_id}/results")
async def get_audit_results(
    session_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Returns cached audit results for the given session_id."""
    session = get_authenticated_session(session_id, current_user)

    evals = session["evals"]
    pass_count = sum(1 for v in evals.values() if v.get("status") == "Pass")
    fail_count = sum(1 for v in evals.values() if v.get("status") == "Fail")
    unknown_count = sum(1 for v in evals.values() if v.get("status") == "Unknown")

    return {
        "session_id": session_id,
        "device_hostname": session["csm"].get("device", {}).get("hostname", "unknown"),
        "platform": session["csm"].get("device", {}).get("platform") or "unknown",
        "config_file_hash": session["config_file_hash"],
        "summary": {
            "total": len(evals),
            "pass": pass_count,
            "fail": fail_count,
            "unknown": unknown_count
        },
        "rule_results": evals,
        "unmapped_lines": session["csm"].get("unmapped_lines", []),
        "csm": session["csm"]
    }


# --- 3. POST /api/ai/suggest ---
@app.post("/api/ai/suggest")
async def ai_suggest(
    req: SuggestRequest,
    current_user: Dict[str, Any] = Depends(require_role("uploader", "reviewer"))
):
    """Calls suggest_mapping() and store_suggestion() via DistilBERT 66M."""
    line = req.unmapped_line.strip()
    if not line:
        raise HTTPException(status_code=400, detail="unmapped_line cannot be empty.")

    try:
        rules_context = load_baseline_rules()
        suggestion = ai_suggester.suggest_mapping(line, rules_context=rules_context)
        suggestion_id = ai_suggester.store_suggestion(suggestion, filepath=PENDING_FILE)
        return {
            "suggestion_id": suggestion_id,
            "suggestion": suggestion
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI suggestion generation failed: {e}")


# --- 4. POST /api/ai/approve ---
@app.post("/api/ai/approve")
async def ai_approve(
    req: ApproveRequest,
    current_user: Dict[str, Any] = Depends(require_role("reviewer", require_approver=True))
):
    """Calls approve_suggestion(), updates trusted_mappings.json or rejects suggestion,
    and re-evaluates rules against active session if session_id provided.
    Authoritative reviewer identity is strictly derived from verified JWT claim current_user['sub'].
    Any client-supplied reviewer_name, reviewer_id, or headers are ignored for identity/accountability.
    """
    authoritative_reviewer_id = current_user["sub"]
    try:
        res = ai_suggester.approve_suggestion(
            suggestion_id=req.suggestion_id,
            reviewer_name=authoritative_reviewer_id,
            decision=req.decision,
            corrected_mapping=req.corrected_mapping,
            pending_file=PENDING_FILE,
            trusted_file=TRUSTED_FILE
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval workflow error: {e}")

    # If session_id is provided, re-evaluate rules with the updated trusted mappings
    updated_evals = None
    updated_unmapped = None
    if req.session_id:
        session = database.get_session(req.session_id)
        if session:
            baseline_rules = load_baseline_rules()
            trusted_rules = load_trusted_rules()
    
            # Re-parse and re-evaluate via registered vendor adapter
            session_vendor = session["csm"].get("device", {}).get("vendor", "cisco")
            reg = get_default_vendor_registry()
            adapter = reg.get(session_vendor)
            csm_re = adapter.parse(
                session["raw_config_text"],
                filename=session["filename"],
                trusted_rules=trusted_rules
            )
            evals_re = adapter.evaluate_legacy_rules(csm_re, baseline_rules, trusted_rules=trusted_rules)
    
            session["csm"] = csm_re
            session["evals"] = evals_re
            database.save_session(session)
            
            updated_evals = evals_re
            updated_unmapped = csm_re.get("unmapped_lines", [])

    return {
        "status": res.get("status", req.decision),
        "result": res,
        "updated_results": updated_evals,
        "unmapped_lines": updated_unmapped
    }


# --- 4b. AI Model Management Endpoints ---
@app.get("/api/model/status")
async def get_model_status(
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Returns operational status of the AI Model Manager, hardware capabilities,
    and Ollama loopback connectivity. Available to all authenticated users.
    """
    manager = ai_model_manager.get_model_manager()
    status = manager.get_status()
    return status


@app.post("/api/model/mode")
async def set_model_mode(
    req: ModelModeRequest,
    current_user: Dict[str, Any] = Depends(require_role("reviewer", require_approver=True))
):
    """Updates the operational model mode (fast, quality, auto, override).
    Strictly gated to authorized reviewer approvers.
    Rejects invalid modes or non-allowlisted models with HTTP 400.
    """
    manager = ai_model_manager.get_model_manager()
    success, err_msg = manager.set_mode(req.mode, req.override_model)
    if not success:
        raise HTTPException(status_code=400, detail=err_msg or "Failed to set model mode")

    status = manager.get_status()
    return {
        "success": True,
        "message": f"Model mode successfully updated to '{manager.active_mode.value}'",
        **status,
        "status": status
    }


# --- 5. POST /api/remediation/{rule_id} ---
@app.post("/api/remediation/{rule_id}")
async def get_remediation(
    rule_id: str,
    req: RemediationRequest,
    current_user: Dict[str, Any] = Depends(require_role("uploader", "reviewer"))
):
    """Renders Jinja2 remediation CLI, runs static conflict analysis and AI explanation.
    AST-enforced execution safety: Commands are strictly DISPLAY ONLY.
    """
    # 1. Structural safety assertion: confirm BOTH remediation_engine.py and main.py have zero execution imports
    try:
        rem_safety = remediation_engine.verify_safety_no_execution()
        api_safety = verify_api_safety_no_execution()
        safety_verified = rem_safety and api_safety
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Safety violation in remediation engine or API layer: {e}")

    # 2. Resolve target CSM
    csm = None
    if req.session_id:
        session = get_authenticated_session(req.session_id, current_user)
        csm = session["csm"]
    elif req.csm:
        csm = req.csm
    else:
        raise HTTPException(
            status_code=400,
            detail="Must provide either a valid session_id or a parsed csm object."
        )

    # 3. Generate remediation template
    try:
        remediation_cmd = remediation_engine.generate_remediation(rule_id, csm)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation template render error: {e}")

    # 4. Check static conflicts
    conflict_report = remediation_engine.check_static_conflicts(rule_id, csm, remediation_cmd)

    # 5. Generate plain-language failure explanation
    ai_exp = remediation_engine.explain_failure_ai(rule_id, csm, remediation_cmd)

    return {
        "rule_id": rule_id,
        "remediation_cmd": remediation_cmd,
        "conflicts": conflict_report["conflicts"],
        "has_conflicts": conflict_report["has_conflicts"],
        "conflict_count": conflict_report["conflict_count"],
        "why_it_failed": ai_exp["why_it_failed"],
        "what_remediation_does": ai_exp["what_remediation_does"],
        "safety_notice": "DISPLAY ONLY — NOT AUTO-EXECUTED. Execution on live devices is strictly prohibited by security architecture.",
        "execution_safety_verified": safety_verified
    }


# --- 6. POST /api/audit/finalize ---
@app.post("/api/audit/finalize")
async def finalize_audit(
    req: FinalizeRequest,
    current_user: Dict[str, Any] = Depends(require_role("uploader", "reviewer"))
):
    """Writes the real hash-chained audit log entry into SQLite audit_ledger
    (retaining compatibility logfile parameter), then generates the signed PDF compliance report.
    """
    session = get_authenticated_session(req.session_id, current_user)

    try:
        # Create chained entry
        audit_entry = audit_log.create_audit_entry(
            csm=session["csm"],
            evals=session["evals"],
            raw_config_text=session["raw_config_text"],
            remediation_summary=req.remediation_summary,
            logfile=LOG_FILE
        )
        entry_hash = audit_log.append_audit_entry(audit_entry, logfile=LOG_FILE)

        # Generate PDF report embedding entryHash and QR
        pdf_path_str = report_generator.generate_pdf_report(
            csm=session["csm"],
            evals=session["evals"],
            audit_entry=audit_entry,
            remediation_data=req.remediation_summary,
            output_path=PDF_FILE
        )
        pdf_path = pathlib.Path(pdf_path_str)

        return {
            "entry_id": audit_entry["entry_id"],
            "entryHash": entry_hash,
            "prevEntryHash": audit_entry["prevEntryHash"],
            "timestamp": audit_entry["timestamp"],
            "pdf_download_url": f"/api/report/{audit_entry['entry_id']}/download",
            "pdf_filename": pdf_path.name,
            "pdf_size_bytes": pdf_path.stat().st_size if pdf_path.exists() else 0
        }
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=409, detail=f"Duplicate finalization conflict: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Finalization failed: {e}")


# --- 7. GET /api/ledger ---
@app.get("/api/ledger")
async def get_ledger(
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Returns chronological list of all hash-chained audit entries from SQLite."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM audit_ledger ORDER BY id ASC')
    rows = cur.fetchall()
    conn.close()

    entries = []
    for row in rows:
        try:
            entry = {
                "entry_id": row["entry_id"],
                "timestamp": row["timestamp"],
                "device_hostname": row["device_hostname"],
                "config_file_hash": row["config_file_hash"],
                "audit_results": json.loads(row["audit_results"]) if row["audit_results"] else {},
                "remediation_summary": json.loads(row["remediation_summary"]) if row["remediation_summary"] else None,
                "prevEntryHash": row["prevEntryHash"],
                "entryHash": row["entryHash"]
            }
            entries.append(entry)
        except Exception:
            continue
    return entries


# --- 8. GET /api/ledger/verify ---
@app.get("/api/ledger/verify")
async def verify_ledger(
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Verifies complete cryptographic hash-chain integrity of SQLite audit_ledger."""
    try:
        is_valid, message, broken_idx = audit_log.verify_chain(LOG_FILE)
        payload = {
            "valid": is_valid,
            "message": message,
            "broken_entry_index": broken_idx,
            "detail": message
        }
        if not is_valid:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=409, content=payload)
        return payload
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chain verification failed: {e}")


# --- 9. GET /api/report/{entry_id}/download ---
@app.get("/api/report/{entry_id}/download")
async def download_report(
    entry_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Serves the generated PDF report for the given entry_id."""
    if not PDF_FILE.exists():
        raise HTTPException(status_code=404, detail="PDF report not found. Finalize audit first.")

    return FileResponse(
        path=str(PDF_FILE),
        media_type="application/pdf",
        filename=f"compliance_report_{entry_id}.pdf"
    )


# --- 10. GET /api/report/{entry_id}/verify ---
@app.get("/api/report/{entry_id}/verify")
async def verify_report(
    entry_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Validates embedded hash in generated PDF report against SQLite audit_ledger."""
    try:
        valid, msg = report_generator.verify_report_hash(PDF_FILE, LOG_FILE)
        return {
            "valid": valid,
            "message": msg,
            "entry_id": entry_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report verification failed: {e}")


# --- 11. GET /api/compliance/frameworks ---
@app.get("/api/compliance/frameworks", response_model=FrameworksListResponse)
async def list_compliance_frameworks(
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Returns list of registered deterministic compliance frameworks with metadata and control metrics."""
    registry = compliance_framework.get_default_registry()
    frameworks_meta = []
    
    for f in registry.list(enabled_only=False):
        evaluator = registry.get_evaluator(f.framework_id)
        control_count = 0
        severity_dist: Dict[str, int] = {}
        
        if evaluator is not None and hasattr(evaluator, "_controls"):
            controls_dict = evaluator._controls
            control_count = len(controls_dict)
            for ctrl in controls_dict.values():
                sev = ctrl.severity.lower() if ctrl.severity else "unknown"
                severity_dist[sev] = severity_dist.get(sev, 0) + 1
        
        frameworks_meta.append(
            FrameworkMetadataResponse(
                framework_id=f.framework_id,
                name=f.name,
                version=f.version,
                description=f.description,
                vendor_scope=f.vendor_scope,
                control_namespace=f.control_namespace,
                control_count=control_count,
                severity_distribution=severity_dist,
                enabled=f.enabled
            )
        )
    
    return FrameworksListResponse(
        frameworks=frameworks_meta,
        total_count=len(frameworks_meta)
    )


# --- 12. POST /api/compliance/evaluate ---
@app.post("/api/compliance/evaluate")
async def evaluate_compliance(
    req: ComplianceEvaluateRequest,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Executes deterministic multi-framework compliance evaluation against CSM or config.
    
    Consumes either session_id (with strict resource ownership enforcement),
    pre-parsed normalized CSM, or raw configuration text.
    Dispatches evaluation deterministically through FrameworkRegistry evaluators
    and aggregates verdicts via MultiFrameworkAggregator.
    """
    csm: Optional[Dict[str, Any]] = None
    audit_id: Optional[str] = None
    device_hostname: Optional[str] = None

    if req.session_id:
        session = get_authenticated_session(req.session_id, current_user)
        csm = session.get("csm")
        audit_id = req.session_id
        if isinstance(csm, dict):
            device_hostname = csm.get("device", {}).get("hostname", "unknown")
    elif req.csm is not None:
        if not isinstance(req.csm, dict):
            raise HTTPException(status_code=422, detail="CSM must be a valid JSON dictionary.")
        csm = req.csm
        device_hostname = csm.get("device", {}).get("hostname", "unknown")
    elif req.raw_config is not None:
        if not req.raw_config.strip():
            raise HTTPException(status_code=422, detail="raw_config must not be empty.")
        try:
            trusted_rules = load_trusted_rules()
            csm, _ = ingest_configuration(
                raw_text=req.raw_config,
                vendor=req.vendor,
                trusted_rules=trusted_rules,
            )
            device_hostname = csm.get("device", {}).get("hostname", "unknown")
        except (UnsupportedVendorError, UndeterminedVendorError) as ve:
            raise HTTPException(status_code=422, detail=str(ve))
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Failed to parse raw_config into CSM: {e}")
    else:
        raise HTTPException(
            status_code=422,
            detail="One of session_id, csm, or raw_config must be provided."
        )

    if not isinstance(csm, dict) or not csm:
        raise HTTPException(status_code=422, detail="CSM payload is empty or invalid.")

    registry = compliance_framework.get_default_registry()

    # Determine frameworks to evaluate
    if req.framework_ids:
        target_fids = []
        for fid in req.framework_ids:
            cleaned_fid = fid.strip().lower()
            if not registry.exists(cleaned_fid):
                raise HTTPException(
                    status_code=422,
                    detail=f"Framework '{fid}' is not registered."
                )
            target_fids.append(cleaned_fid)
    else:
        target_fids = [
            f.framework_id
            for f in registry.list(enabled_only=True)
            if registry.get_evaluator(f.framework_id) is not None
        ]

    all_results = []
    for fid in target_fids:
        evaluator = registry.get_evaluator(fid)
        if evaluator is None:
            raise HTTPException(
                status_code=422,
                detail=f"No evaluator registered for framework '{fid}'."
            )
        try:
            results = evaluator.evaluate(csm)
            all_results.extend(results)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Deterministic evaluation failed for framework '{fid}': {e}"
            )

    aggregator = compliance_aggregator.MultiFrameworkAggregator(registry=registry)
    try:
        audit_result = aggregator.aggregate(
            all_results,
            audit_id=audit_id,
            device_hostname=device_hostname
        )
        return audit_result.to_dict()
    except compliance_aggregator.ConflictingControlEvaluationError as ce:
        raise HTTPException(status_code=409, detail=f"Conflicting control evaluation: {ce}")
    except compliance_aggregator.InvalidEvaluationResultError as ie:
        raise HTTPException(status_code=422, detail=f"Invalid evaluation result: {ie}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Multi-framework evaluation aggregation failed: {e}")


# --- Self-Test AST Assertion on main.py itself (Adapter Safety Function) ---

import ast_safety


def verify_api_safety_no_execution(target_file: Optional[pathlib.Path] = None) -> bool:
    """AST code analysis asserting that no process execution or device communication
    libraries are imported or used in the specified file (defaults to main.py).
    """
    file_to_check = target_file if target_file is not None else pathlib.Path(__file__)
    return ast_safety.assert_no_execution_imports(file_to_check)

# Run immediate safety assertion on main.py at load time
verify_api_safety_no_execution()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
