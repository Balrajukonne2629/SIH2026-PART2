"""Thin FastAPI layer wrapping the 5 backend compliance modules for the React dashboard.
Exposes REST endpoints for:
1. POST /api/audit/upload
2. GET  /api/audit/{session_id}/results
3. POST /api/ai/suggest
4. POST /api/ai/approve
5. POST /api/remediation/{rule_id}
6. POST /api/audit/finalize
7. GET  /api/ledger
8. GET  /api/ledger/verify
9. GET  /api/report/{entry_id}/download
10. GET /api/report/{entry_id}/verify

Architectural Constraints & Safety Properties:
- In-memory session store keyed by session_id (UUID). Resets on server restart (expected for MVP).
- No database: audit_log.jsonl and JSON files remain the single source of truth.
- Authentication/user management is deferred to Phase 2.
- Core module signatures are NOT modified; thin adapter functions exist here if needed.
- AST execution safety: Remediation commands are strictly DISPLAY ONLY; no subprocess/exec paths exist.
"""
import ast
import datetime
import hashlib
import json
import pathlib
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Direct imports of the 5 wrapped backend modules
import ai_suggester
import audit_log
import cisco_auditor
import remediation_engine
import report_generator

BASE_DIR = pathlib.Path(__file__).parent.resolve()
RULES_FILE = BASE_DIR / "07_Compliance_Scanners" / "Rule_Library" / "extracted" / "Rule_Library" / "vendor_rule_mapping.json"
TRUSTED_FILE = BASE_DIR / "trusted_mappings.json"
PENDING_FILE = BASE_DIR / "pending_suggestions.json"
LOG_FILE = BASE_DIR / "audit_log.jsonl"
PDF_FILE = BASE_DIR / "cisco_compliance_report.pdf"

# In-memory session store for multi-step audit flows within one session
# State resets on server restart, which is expected for the MVP single-audit loop.
SESSIONS: Dict[str, Dict[str, Any]] = {}

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


# --- Helper Loaders (Adapter Layer) ---
def load_baseline_rules() -> List[dict]:
    """Loads baseline rules from Rule Library JSON without altering cisco_auditor signature."""
    if RULES_FILE.exists():
        data = json.loads(RULES_FILE.read_text(encoding="utf-8-sig"))
        return data["vendors"]["Cisco IOS-XE"]["rules"]
    return []


def load_trusted_rules() -> List[dict]:
    """Loads approved trusted custom rules from trusted_mappings.json."""
    if TRUSTED_FILE.exists():
        try:
            return json.loads(TRUSTED_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


# --- Pydantic Request Models ---
class SuggestRequest(BaseModel):
    unmapped_line: str


class ApproveRequest(BaseModel):
    suggestion_id: str
    reviewer_name: str
    decision: str  # 'approve', 'reject', or 'approve_with_correction'
    corrected_mapping: Optional[dict] = None
    session_id: Optional[str] = None


class RemediationRequest(BaseModel):
    session_id: Optional[str] = None
    csm: Optional[dict] = None


class FinalizeRequest(BaseModel):
    session_id: str
    remediation_summary: Optional[dict] = None


# --- 1. POST /api/audit/upload ---
@app.post("/api/audit/upload")
async def audit_upload(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_config: Optional[str] = Form(None)
):
    """Accepts uploaded config file (multipart) or raw text.
    Runs parse_cisco() + evaluate_rules().
    Caches results in-memory keyed by session_id.
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

        # Step 1 & 2: Parse to CSM and evaluate baseline + trusted rules
        csm = cisco_auditor.parse_cisco(text, filename=filename, trusted_rules=trusted_rules)
        evals = cisco_auditor.evaluate_rules(csm, baseline_rules, trusted_rules=trusted_rules)
        config_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        session_id = str(uuid.uuid4())
        SESSIONS[session_id] = {
            "session_id": session_id,
            "csm": csm,
            "evals": evals,
            "raw_config_text": text,
            "filename": filename,
            "config_file_hash": config_hash,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        pass_count = sum(1 for v in evals.values() if v.get("status") == "Pass")
        fail_count = sum(1 for v in evals.values() if v.get("status") == "Fail")
        unknown_count = sum(1 for v in evals.values() if v.get("status") == "Unknown")

        return {
            "session_id": session_id,
            "device_hostname": csm.get("device", {}).get("hostname", "unknown"),
            "platform": csm.get("device", {}).get("platform", "IOS-XE"),
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit parsing failed: {e}")


# --- 2. GET /api/audit/{session_id}/results ---
@app.get("/api/audit/{session_id}/results")
async def get_audit_results(session_id: str):
    """Returns cached audit results for the given session_id."""
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found or session expired on server restart."
        )

    evals = session["evals"]
    pass_count = sum(1 for v in evals.values() if v.get("status") == "Pass")
    fail_count = sum(1 for v in evals.values() if v.get("status") == "Fail")
    unknown_count = sum(1 for v in evals.values() if v.get("status") == "Unknown")

    return {
        "session_id": session_id,
        "device_hostname": session["csm"].get("device", {}).get("hostname", "unknown"),
        "platform": session["csm"].get("device", {}).get("platform", "IOS-XE"),
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
async def ai_suggest(req: SuggestRequest):
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
async def ai_approve(req: ApproveRequest):
    """Calls approve_suggestion(), updates trusted_mappings.json or rejects suggestion,
    and re-evaluates rules against active session if session_id provided.
    """
    try:
        res = ai_suggester.approve_suggestion(
            suggestion_id=req.suggestion_id,
            reviewer_name=req.reviewer_name,
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
    if req.session_id and req.session_id in SESSIONS:
        session = SESSIONS[req.session_id]
        baseline_rules = load_baseline_rules()
        trusted_rules = load_trusted_rules()

        # Re-parse and re-evaluate
        csm_re = cisco_auditor.parse_cisco(
            session["raw_config_text"],
            filename=session["filename"],
            trusted_rules=trusted_rules
        )
        evals_re = cisco_auditor.evaluate_rules(csm_re, baseline_rules, trusted_rules=trusted_rules)

        session["csm"] = csm_re
        session["evals"] = evals_re
        updated_evals = evals_re
        updated_unmapped = csm_re.get("unmapped_lines", [])

    return {
        "status": res.get("status", req.decision),
        "result": res,
        "updated_results": updated_evals,
        "unmapped_lines": updated_unmapped
    }


# --- 5. POST /api/remediation/{rule_id} ---
@app.post("/api/remediation/{rule_id}")
async def get_remediation(rule_id: str, req: RemediationRequest):
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
    if req.session_id and req.session_id in SESSIONS:
        csm = SESSIONS[req.session_id]["csm"]
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
async def finalize_audit(req: FinalizeRequest):
    """Writes the real hash-chained audit log entry into audit_log.jsonl,
    then generates the signed PDF compliance report with embedded QR code.
    """
    session = SESSIONS.get(req.session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{req.session_id}' not found. Cannot finalize uninitialized audit."
        )

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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Finalization failed: {e}")


# --- 7. GET /api/ledger ---
@app.get("/api/ledger")
async def get_ledger():
    """Returns chronological list of all hash-chained audit entries from audit_log.jsonl."""
    if not LOG_FILE.exists():
        return []

    entries = []
    lines = [l.strip() for l in LOG_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
    for line in lines:
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries


# --- 8. GET /api/ledger/verify ---
@app.get("/api/ledger/verify")
async def verify_ledger():
    """Verifies complete cryptographic hash-chain integrity of audit_log.jsonl."""
    try:
        is_valid, message, broken_idx = audit_log.verify_chain(LOG_FILE)
        return {
            "valid": is_valid,
            "message": message,
            "broken_entry_index": broken_idx
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chain verification failed: {e}")


# --- 9. GET /api/report/{entry_id}/download ---
@app.get("/api/report/{entry_id}/download")
async def download_report(entry_id: str):
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
async def verify_report(entry_id: str):
    """Validates embedded hash in generated PDF report against audit_log.jsonl."""
    try:
        valid, msg = report_generator.verify_report_hash(PDF_FILE, LOG_FILE)
        return {
            "valid": valid,
            "message": msg,
            "entry_id": entry_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report verification failed: {e}")


# --- Self-Test AST Assertion on main.py itself (Adapter Safety Function) ---
def verify_api_safety_no_execution(target_file: Optional[pathlib.Path] = None) -> bool:
    """AST code analysis asserting that no process execution or device communication
    libraries are imported or used in the specified file (defaults to main.py).
    """
    forbidden = {"subprocess", "os.system", "paramiko", "netmiko", "pexpect", "telnetlib", "socket"}
    file_to_check = target_file if target_file is not None else pathlib.Path(__file__)
    src = file_to_check.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name in forbidden:
                    raise RuntimeError(f"Safety Violation in {file_to_check.name}: Forbidden library '{n.name}' imported!")
        elif isinstance(node, ast.ImportFrom):
            if node.module in forbidden:
                raise RuntimeError(f"Safety Violation in {file_to_check.name}: Forbidden module '{node.module}' imported!")
    return True

# Run immediate safety assertion on main.py at load time
verify_api_safety_no_execution()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
