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

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Direct imports of the backend modules
import src.ai_model_manager as ai_model_manager
import src.ai_suggester as ai_suggester
import src.audit_log as audit_log
import src.remediation_engine as remediation_engine
import src.report_generator as report_generator
import src.vendor_registry as vendor_registry
from src.vendor_registry import (
    get_default_vendor_registry,
    ingest_configuration,
    UnsupportedVendorError,
    UndeterminedVendorError,
)

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
RULES_FILE = BASE_DIR / "config" / "Rule_Library" / "vendor_rule_mapping.json"
TRUSTED_FILE = BASE_DIR / "data" / "trusted_mappings.json"
PENDING_FILE = BASE_DIR / "data" / "pending_suggestions.json"
LOG_FILE = BASE_DIR / "data" / "audit_log.jsonl"
PDF_FILE = BASE_DIR / "data" / "exports" / "cisco_compliance_report.pdf"

import src.auth as auth
import src.database as database
import src.compliance_framework as compliance_framework
import src.cis_benchmark_cisco_iosxe as cis_benchmark_cisco_iosxe
import src.disa_stig_cisco_iosxe as disa_stig_cisco_iosxe
import src.compliance_aggregator as compliance_aggregator
import src.audit_report as audit_report
import src.report_exporter as report_exporter

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


def load_trusted_rules(vendor: Optional[str] = None) -> List[dict]:
    """Loads approved trusted custom rules from SQLite trusted_mappings table.
    Enforces strict vendor isolation when vendor is specified."""
    mappings = [m for m in database.list_trusted_mappings(vendor=vendor) if m.get("status") != "retired"]
    rules = []
    for m in mappings:
        rules.append({
            "vendor_rule_id": m["vendor_rule_id"],
            "common_rule_id": m["common_rule_id"],
            "internalTitle": m["internalTitle"],
            "csmFieldChecked": m["csmFieldChecked"],
            "condition": m["condition"],
            "configuration_evidence": m["configuration_evidence"],
            "check_focus": m["check_focus"],
            "frameworkMappings": m["frameworkMappings"],
            "version_info": m["version_info"],
            "vendor": m["vendor"],
            "status": m["status"]
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
    vendor: Optional[str] = "cisco"


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
    multi_framework_result: Optional[dict] = None
    initial_editable_content: Optional[dict] = None
    conflict_warnings: Optional[List[dict]] = None
    ai_mapping_provenance: Optional[List[dict]] = None


class ReportPatchRequest(BaseModel):
    field_path: str
    new_value: Any
    expected_version: int


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


def check_report_ownership(report: Optional[Dict[str, Any]], current_user: Dict[str, Any], report_id: str) -> Dict[str, Any]:
    """Enforces audit report resource isolation and anti-enumeration.

    Reviewers and Viewers may access any report.
    Uploaders may only access reports where the authoritative owner_user_id == current_user['sub'].
    Cross-owner access attempts by uploaders raise HTTP 404 (not 403) to prevent resource enumeration.
    """
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found."
        )

    user_role = current_user.get("role")
    if user_role == "uploader":
        # Resolve authoritative owner using the application's existing ownership hierarchy
        owner_user_id = None
        session_id = report.get("session_id")
        if session_id:
            raw_session = database.get_session(session_id)
            if raw_session:
                owner_user_id = raw_session.get("owner_user_id")

        if not owner_user_id:
            audit_entry_id = report.get("audit_entry_id")
            if audit_entry_id:
                conn = database.get_connection()
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT owner_user_id FROM audit_ledger WHERE entry_id = ?", (audit_entry_id,))
                    row = cur.fetchone()
                    if row and row[0]:
                        owner_user_id = row[0]
                finally:
                    conn.close()

        if not owner_user_id:
            owner_user_id = report.get("created_by")

        if owner_user_id != current_user.get("sub"):
            raise HTTPException(
                status_code=404,
                detail=f"Report '{report_id}' not found."
            )

    return report


def get_authenticated_report(report_id: str, current_user: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieves an audit report from SQLite and enforces resource ownership isolation.

    Raises HTTP 404 if report does not exist or if caller is an uploader attempting
    cross-owner report access (anti-enumeration defense).
    """
    raw_report = database.get_audit_report(report_id)
    return check_report_ownership(raw_report, current_user, report_id)


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
        # Determine vendor adapter first to enforce vendor isolation on trusted mappings
        target_registry = get_default_vendor_registry()
        if vendor and vendor.strip() and vendor.strip().lower() != "auto":
            resolved_adapter = target_registry.get(vendor)
        else:
            resolved_adapter = target_registry.detect(text)
            if resolved_adapter is None:
                raise UndeterminedVendorError(
                    "Unable to determine vendor configuration type. Specify vendor explicitly or check configuration."
                )

        resolved_vendor = resolved_adapter.vendor_id
        baseline_rules = load_baseline_rules()
        trusted_rules = load_trusted_rules(vendor=resolved_vendor)

        # Step 1 & 2: Ingest configuration through vendor boundary and evaluate baseline rules
        csm, adapter = ingest_configuration(
            raw_text=text,
            filename=filename,
            vendor=resolved_vendor,
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

    vendor = (req.vendor or "cisco").lower().strip()
    try:
        rules_context = load_baseline_rules()
        suggestion = ai_suggester.suggest_mapping(line, rules_context=rules_context, vendor=vendor)
        suggestion_id = ai_suggester.store_suggestion(suggestion, filepath=PENDING_FILE, vendor=vendor)
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
    """Calls approve_suggestion(), updates trusted_mappings or rejects suggestion,
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
        err_msg = str(e)
        if "Conflict:" in err_msg:
            raise HTTPException(status_code=409, detail=err_msg)
        raise HTTPException(status_code=400, detail=err_msg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval workflow error: {e}")

    # If session_id is provided, re-evaluate rules with the updated trusted mappings (strictly vendor-isolated)
    updated_evals = None
    updated_unmapped = None
    if req.session_id:
        session = database.get_session(req.session_id)
        if session:
            session_vendor = session["csm"].get("device", {}).get("vendor", "cisco")
            baseline_rules = load_baseline_rules()
            trusted_rules = load_trusted_rules(vendor=session_vendor)

            # Re-parse and re-evaluate via registered vendor adapter
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
        "status": "rejected" if req.decision == "reject" else req.decision,
        "result": res,
        "updated_results": updated_evals,
        "unmapped_lines": updated_unmapped
    }


# --- 4a. Trusted Rule Library Management Endpoints ---

@app.get("/api/trusted-mappings")
async def list_trusted_mappings_endpoint(
    vendor: Optional[str] = None,
    status: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Returns list of trusted deterministic rule mappings from the Trusted Rule Library.
    Optionally filtered by vendor (cisco/juniper) and/or status (approved/corrected).
    Available to all authenticated roles.
    """
    mappings = database.list_trusted_mappings(vendor=vendor, status=status)
    return mappings


@app.get("/api/trusted-mappings/{vendor_rule_id}")
async def get_trusted_mapping_endpoint(
    vendor_rule_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Retrieves full specification and audit trail for a single trusted rule mapping."""
    mapping = database.get_trusted_mapping(vendor_rule_id)
    if not mapping:
        raise HTTPException(status_code=404, detail=f"Trusted mapping '{vendor_rule_id}' not found.")
    return mapping


@app.delete("/api/trusted-mappings/{vendor_rule_id}")
async def delete_trusted_mapping_endpoint(
    vendor_rule_id: str,
    current_user: Dict[str, Any] = Depends(require_role("reviewer", require_approver=True))
):
    """Deletes/retires a trusted rule mapping from the Trusted Rule Library.
    Strictly restricted to authorized reviewer approvers.
    """
    deleted = database.delete_trusted_mapping(vendor_rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Trusted mapping '{vendor_rule_id}' not found.")
    return {
        "success": True,
        "message": f"Trusted mapping '{vendor_rule_id}' successfully retired.",
        "vendor_rule_id": vendor_rule_id,
        "retired_by": current_user["sub"]
    }


@app.get("/api/ai/suggestions")
async def list_suggestions_endpoint(
    vendor: Optional[str] = None,
    status: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Returns list of AI-generated suggestions awaiting or having completed human review.
    Optionally filtered by vendor and/or status (pending/approved/rejected).
    """
    suggestions = database.list_pending_suggestions(vendor=vendor, status=status)
    return suggestions


@app.get("/api/ai/suggestions/{suggestion_id}")
async def get_suggestion_endpoint(
    suggestion_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Retrieves full AI suggestion details by suggestion_id."""
    suggestion = database.get_pending_suggestion(suggestion_id)
    if not suggestion:
        raise HTTPException(status_code=404, detail=f"Suggestion '{suggestion_id}' not found.")
    return suggestion



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

        # Create or get canonical AuditReport (Phase 3D Chunk 3)
        # Note: Must happen AFTER append_audit_entry so authoritative audit_ledger entry exists
        canonical_report = audit_report.create_or_get_canonical_report(
            audit_entry_id=audit_entry["entry_id"],
            session_id=session["session_id"],
            csm=session.get("csm"),
            evals=session.get("evals"),
            raw_config_text=session.get("raw_config_text"),
            remediation_summary=req.remediation_summary,
            multi_framework_result=req.multi_framework_result,
            ai_mapping_provenance=req.ai_mapping_provenance,
            conflict_warnings=req.conflict_warnings,
            initial_editable_content=req.initial_editable_content,
            created_by=current_user["sub"]
        )

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
            "report_id": canonical_report.report_id,
            "report_version": canonical_report.version,
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
    """Returns chronological list of all hash-chained audit entries from SQLite,
    including canonical report metadata (has_canonical_report, report_id) via LEFT JOIN
    to prevent client-side N+1 query loops.
    """
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT
            al.entry_id,
            al.timestamp,
            al.device_hostname,
            al.config_file_hash,
            al.audit_results,
            al.remediation_summary,
            al.prevEntryHash,
            al.entryHash,
            al.owner_user_id AS ledger_owner,
            ar.report_id AS canonical_report_id,
            ar.created_by AS report_created_by,
            s.owner_user_id AS session_owner
        FROM audit_ledger al
        LEFT JOIN audit_reports ar ON al.entry_id = ar.audit_entry_id
        LEFT JOIN audit_sessions s ON ar.session_id = s.session_id
        ORDER BY al.id ASC
    ''')
    rows = cur.fetchall()
    conn.close()

    user_role = current_user.get("role")
    user_id = current_user.get("sub")

    entries = []
    for row in rows:
        try:
            # Enforce anti-enumeration for uploaders
            is_authorized = True
            if user_role == "uploader":
                owner = row["session_owner"] or row["ledger_owner"] or row["report_created_by"]
                if owner and owner != user_id:
                    is_authorized = False

            rep_id = row["canonical_report_id"] if (is_authorized and row["canonical_report_id"]) else None

            entry = {
                "entry_id": row["entry_id"],
                "timestamp": row["timestamp"],
                "device_hostname": row["device_hostname"],
                "config_file_hash": row["config_file_hash"],
                "audit_results": json.loads(row["audit_results"]) if row["audit_results"] else {},
                "remediation_summary": json.loads(row["remediation_summary"]) if row["remediation_summary"] else None,
                "prevEntryHash": row["prevEntryHash"],
                "entryHash": row["entryHash"],
                "has_canonical_report": bool(rep_id),
                "report_id": rep_id
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
    vendor: Optional[str] = Query(None, description="Optional vendor filter to list only compatible frameworks"),
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Returns list of registered deterministic compliance frameworks with metadata and control metrics.
    If vendor is specified, only frameworks matching the vendor are returned.
    """
    registry = compliance_framework.get_default_registry()
    frameworks_meta = []

    frameworks_to_list = (
        registry.list_for_vendor(vendor, enabled_only=False)
        if vendor is not None and vendor.strip()
        else registry.list(enabled_only=False)
    )

    for f in frameworks_to_list:
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
            target_registry = get_default_vendor_registry()
            if req.vendor and req.vendor.strip() and req.vendor.strip().lower() != "auto":
                resolved_adapter = target_registry.get(req.vendor)
            else:
                resolved_adapter = target_registry.detect(req.raw_config)
                if resolved_adapter is None:
                    raise UndeterminedVendorError(
                        "Unable to determine vendor configuration type. Specify vendor explicitly or check configuration."
                    )
            resolved_vendor = resolved_adapter.vendor_id
            trusted_rules = load_trusted_rules(vendor=resolved_vendor)
            csm, _ = ingest_configuration(
                raw_text=req.raw_config,
                vendor=resolved_vendor,
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

    device_info = csm.get("device") if isinstance(csm.get("device"), dict) else {}
    raw_vendor = req.vendor or device_info.get("vendor") or device_info.get("platform") or "unknown"
    resolved_vendor = raw_vendor.strip().lower() if isinstance(raw_vendor, str) else "unknown"

    registry = compliance_framework.get_default_registry()
    compatible_fws = registry.list_for_vendor(resolved_vendor, enabled_only=True)
    compatible_fids = {f.framework_id for f in compatible_fws}

    # Determine frameworks to evaluate
    if req.framework_ids is None:
        target_fids = [
            f.framework_id
            for f in compatible_fws
            if registry.get_evaluator(f.framework_id) is not None
        ]
    else:
        target_fids = []
        for fid in req.framework_ids:
            cleaned_fid = fid.strip().lower()
            if not registry.exists(cleaned_fid):
                raise HTTPException(
                    status_code=422,
                    detail=f"Framework '{fid}' is not registered."
                )
            fw = registry.get(cleaned_fid)
            if fw is None or not fw.enabled:
                raise HTTPException(
                    status_code=422,
                    detail=f"Framework '{fid}' is disabled."
                )
            if cleaned_fid not in compatible_fids:
                raise HTTPException(
                    status_code=422,
                    detail=f"Framework '{fid}' is not compatible with vendor '{resolved_vendor}'."
                )
            if registry.get_evaluator(cleaned_fid) is None:
                raise HTTPException(
                    status_code=422,
                    detail=f"No evaluator registered for framework '{fid}'."
                )
            target_fids.append(cleaned_fid)

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


# --- 13. Canonical AuditReport Endpoints (Phase 3D.5) ---

@app.get("/api/reports/by-entry/{entry_id}")
async def get_canonical_report_by_entry(
    entry_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Retrieves the canonical AuditReport for a given audit ledger entry_id.

    Allows the frontend to bridge from a ledger entry_id (returned by /api/ledger)
    to the canonical report for that audit. Enforces the same ownership isolation as
    the report_id-based endpoint.
    """
    raw_report = database.get_audit_report_by_entry_id(entry_id)
    if not raw_report:
        raise HTTPException(status_code=404, detail=f"No canonical report found for entry '{entry_id}'.")
    return check_report_ownership(raw_report, current_user, raw_report.get("report_id", entry_id))


@app.get("/api/reports/{report_id}")
async def get_canonical_report(
    report_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Retrieves the full canonical AuditReport domain model.

    Enforces authentication and ownership isolation (anti-enumeration returns 404 for cross-owner access).
    """
    report_dict = get_authenticated_report(report_id, current_user)
    return report_dict


@app.patch("/api/reports/{report_id}")
async def patch_canonical_report(
    report_id: str,
    req: ReportPatchRequest,
    current_user: Dict[str, Any] = Depends(require_role("uploader", "reviewer"))
):
    """Applies human edits to allowlisted report content with optimistic concurrency control.

    Invariants:
    1. Authenticated user required (viewer returns 403 Forbidden).
    2. Enforces resource ownership (cross-owner uploader returns 404 anti-enumeration).
    3. Derives edited_by strictly from authenticated JWT claim current_user['sub'].
    4. Enforces expected_version: stale version returns HTTP 409 Conflict with version detail.
    5. Rejects system field edits and invalid paths with HTTP 400 Bad Request.
    """
    # 1. Ownership & anti-enumeration validation
    get_authenticated_report(report_id, current_user)

    # 2. Authoritative editor identity derived strictly from verified JWT
    authoritative_editor_id = current_user["sub"]

    try:
        updated_report = database.record_report_edit(
            report_id=report_id,
            field_path=req.field_path,
            new_value=req.new_value,
            edited_by=authoritative_editor_id,
            expected_version=req.expected_version
        )
        return updated_report
    except audit_report.StaleReportVersionError as e:
        curr = database.get_audit_report(report_id)
        curr_v = curr["version"] if curr else None
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Stale report version",
                "message": str(e),
                "expected_version": req.expected_version,
                "current_version": curr_v,
                "report_id": report_id,
            }
        )
    except (audit_report.InvalidFieldPathError, audit_report.SystemFieldImmutableError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except audit_report.ReportNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record report edit: {e}")


@app.get("/api/reports/{report_id}/edits")
async def get_canonical_report_edits(
    report_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Retrieves full chronological edit provenance history for a canonical report."""
    report_dict = get_authenticated_report(report_id, current_user)
    edits = report_dict.get("edit_metadata", [])
    return {
        "report_id": report_id,
        "version": report_dict.get("version", 1),
        "total_edits": len(edits),
        "edits": edits
    }


@app.post("/api/reports/{report_id}/export/pdf")
@app.get("/api/reports/{report_id}/export/pdf")
async def export_canonical_report_pdf(
    report_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Exports the canonical AuditReport directly to publication-quality PDF."""
    report_dict = get_authenticated_report(report_id, current_user)
    try:
        canonical_report = audit_report.AuditReport.from_dict(report_dict)
        pdf_path = report_exporter.export_pdf(canonical_report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF export failed: {e}")

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=pdf_path.name
    )


@app.post("/api/reports/{report_id}/export/docx")
@app.get("/api/reports/{report_id}/export/docx")
async def export_canonical_report_docx(
    report_id: str,
    current_user: Dict[str, Any] = Depends(require_role("viewer", "uploader", "reviewer"))
):
    """Exports the canonical AuditReport directly to Microsoft Word (.docx) using zero-dependency OOXML."""
    report_dict = get_authenticated_report(report_id, current_user)
    try:
        canonical_report = audit_report.AuditReport.from_dict(report_dict)
        docx_path = report_exporter.export_docx(canonical_report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DOCX export failed: {e}")

    return FileResponse(
        path=str(docx_path),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=docx_path.name
    )


# --- Self-Test AST Assertion on main.py itself (Adapter Safety Function) ---

import src.ast_safety as ast_safety


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
    uvicorn.run("src.main:app", host="127.0.0.1", port=8000, reload=True)
