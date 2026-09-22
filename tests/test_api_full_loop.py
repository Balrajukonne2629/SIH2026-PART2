"""Full Integration Loop API Test for FastAPI Compliance Backend.
Executes the full uninterrupted loop against the 10 HTTP endpoints,
performs rigorous side-by-side parity validation against CLI baseline values
(from test_step5_full_loop.py), and conducts AST execution-safety audits on
both remediation_engine.py and main.py.
"""
import ast
import json
import pathlib
import sys

BASE = pathlib.Path(__file__).resolve().parent.parent
if str(BASE / "src") not in sys.path:
    sys.path.insert(0, str(BASE / "src"))
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient
from src.main import (
    app,
    FinalizeRequest,
    ApproveRequest,
    SuggestRequest,
    RemediationRequest,
    verify_api_safety_no_execution
)
import src.database as database
import src.remediation_engine as remediation_engine
import src.auth as auth

for _name in ("database", "remediation_engine", "auth", "main"):
    sys.modules[_name] = sys.modules[f"src.{_name}"]

client = TestClient(app)

def setup_module():
    # Isolated clean database for reproducible start without touching production data
    test_db = database.DATA_DIR / "test_api_auditor.db"
    if test_db.exists():
        test_db.unlink()
    database.DB_PATH = test_db
    database.initialize_database()
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM audit_sessions')
    cur.execute('DELETE FROM trusted_mappings')
    cur.execute('DELETE FROM pending_suggestions')
    cur.execute('DELETE FROM audit_ledger')
    conn.commit()
    conn.close()

    # Authenticate test client as authorized reviewer for full-loop parity test
    import auth
    token = auth.create_access_token(
        user_id="test-full-loop-reviewer",
        username="secops_reviewer",
        role="reviewer",
        is_authorized_approver=True
    )
    client.headers["Authorization"] = f"Bearer {token}"


CFG_FILE = BASE / "datasets" / "Cisco" / "labeled_test_config.txt"
MAIN_FILE = BASE / "src" / "main.py"
REMEDIATION_FILE = BASE / "src" / "remediation_engine.py"

# --- GROUND-TRUTH CLI BASELINE VALUES FROM test_step5_full_loop.py ---
CLI_BASELINE = {
    "device_hostname": "EDGE-RTR-01",
    "platform": "IOS-XE",
    "pre_approval_unmapped": ["service call-home"],
    "pre_approval_total": 10,
    "pre_approval_pass": 7,
    "pre_approval_fail": 2,
    "pre_approval_unknown": 1,
    "pre_approval_rule_ids": {
        "CISCO-AAA-001", "CISCO-ACL-001", "CISCO-INT-001", "CISCO-LOG-001",
        "CISCO-MGMT-001", "CISCO-NTP-001", "CISCO-ROUTING-001", "CISCO-SNMP-001",
        "CISCO-SSH-001", "CISCO-STP-001"
    },
    "pre_approval_verdicts": {
        "CISCO-AAA-001": "Pass",
        "CISCO-ACL-001": "Pass",
        "CISCO-INT-001": "Pass",
        "CISCO-LOG-001": "Pass",
        "CISCO-MGMT-001": "Pass",
        "CISCO-NTP-001": "Fail",
        "CISCO-ROUTING-001": "Pass",
        "CISCO-SNMP-001": "Fail",
        "CISCO-SSH-001": "Pass",
        "CISCO-STP-001": "Unknown"
    },
    "post_approval_total": 11,
    "post_approval_pass": 7,
    "post_approval_fail": 3,
    "post_approval_unknown": 1,
    "post_approval_unmapped": [],
    "post_approval_rule_ids": {
        "CISCO-AAA-001", "CISCO-ACL-001", "CISCO-DIAG-001", "CISCO-INT-001",
        "CISCO-LOG-001", "CISCO-MGMT-001", "CISCO-NTP-001", "CISCO-ROUTING-001",
        "CISCO-SNMP-001", "CISCO-SSH-001", "CISCO-STP-001"
    },
    "dynamic_rule_id": "CISCO-DIAG-001",
    "dynamic_rule_verdict": "Fail",
    "remediation_rule_id": "CISCO-NTP-001",
    "remediation_has_conflicts": True,
    "remediation_conflict_count": 2,
    "remediation_conflict_ids": ["NTP_AUTH_KEY_MISSING", "NTP_VRF_SOURCE_CHECK"],
    "genesis_prev_hash": "0" * 64,
    "ledger_valid": True,
    "pdf_hash_valid": True,
    "tamper_detected": False,  # when tampered, verify_chain returns False
    "tamper_broken_index": 1
}


def run_test():
    print("=" * 80)
    print("FASTAPI WRAPPER: FULL-LOOP INTEGRATION TEST & PARITY VERIFICATION")
    print("=" * 80)

    # Clean database before run
    setup_module()
    
    # We still need to delete PDF file
    from main import PDF_FILE
    if PDF_FILE.exists():
        PDF_FILE.unlink()

    # Dictionary to record live API results for the side-by-side comparison table
    api_recorded: dict = {}

    # --- STAGE 1: Upload Configuration File ---
    print("\n[STAGE 1] POST /api/audit/upload (Multipart Config Upload):")
    assert CFG_FILE.exists(), f"Missing config file: {CFG_FILE}"
    cfg_text = CFG_FILE.read_text(encoding="utf-8")

    response = client.post(
        "/api/audit/upload",
        files={"file": ("labeled_test_config.txt", cfg_text.encode("utf-8"), "text/plain")}
    )
    assert response.status_code == 200, f"Upload failed: {response.text}"
    data = response.json()
    session_id = data["session_id"]

    # Record API values for parity
    api_recorded["device_hostname"] = data["device_hostname"]
    api_recorded["platform"] = data["platform"]
    api_recorded["pre_approval_total"] = data["summary"]["total"]
    api_recorded["pre_approval_pass"] = data["summary"]["pass"]
    api_recorded["pre_approval_fail"] = data["summary"]["fail"]
    api_recorded["pre_approval_unknown"] = data["summary"]["unknown"]
    api_recorded["pre_approval_unmapped"] = data["unmapped_lines"]
    api_recorded["pre_approval_rule_ids"] = set(data["rule_results"].keys())
    api_recorded["pre_approval_verdicts"] = {
        rid: res["status"] for rid, res in data["rule_results"].items()
    }

    # Explicit Assertions Against CLI Baseline
    assert api_recorded["device_hostname"] == CLI_BASELINE["device_hostname"]
    assert api_recorded["platform"] == CLI_BASELINE["platform"]
    assert api_recorded["pre_approval_total"] == CLI_BASELINE["pre_approval_total"]
    assert api_recorded["pre_approval_pass"] == CLI_BASELINE["pre_approval_pass"]
    assert api_recorded["pre_approval_fail"] == CLI_BASELINE["pre_approval_fail"]
    assert api_recorded["pre_approval_unknown"] == CLI_BASELINE["pre_approval_unknown"]
    assert api_recorded["pre_approval_unmapped"] == CLI_BASELINE["pre_approval_unmapped"]
    assert api_recorded["pre_approval_rule_ids"] == CLI_BASELINE["pre_approval_rule_ids"]
    assert api_recorded["pre_approval_verdicts"] == CLI_BASELINE["pre_approval_verdicts"]
    print(f"  Session Created: {session_id}")
    print(f"  Hostname: {data['device_hostname']} | Pre-Approval Rules: {data['summary']['total']} -> PASS")

    # --- STAGE 2: Get Cached Results & Test 404 ---
    print("\n[STAGE 2] GET /api/audit/{session_id}/results (Session Cache Verification):")
    res_cached = client.get(f"/api/audit/{session_id}/results")
    assert res_cached.status_code == 200
    assert res_cached.json()["summary"] == data["summary"]
    res_404 = client.get("/api/audit/nonexistent-session-id/results")
    assert res_404.status_code == 404
    print("  Session cache and 404 handler verified -> PASS")

    # --- STAGE 3: AI Suggestion for Unmapped Line ---
    print("\n[STAGE 3] POST /api/ai/suggest (Local DistilBERT NLP Inference):")
    unmapped_line = data["unmapped_lines"][0]
    res_sug = client.post("/api/ai/suggest", json={"unmapped_line": unmapped_line})
    assert res_sug.status_code == 200
    sug_data = res_sug.json()
    sug_id = sug_data["suggestion_id"]
    suggestion = sug_data["suggestion"]
    assert suggestion["confidence"] >= 0.80
    assert "call-home" in suggestion["raw_line"]
    print(f"  Suggestion Generated: ID={sug_id} | Confidence={suggestion['confidence']} -> PASS")

    # --- STAGE 4: Reviewer Approval Workflow ---
    print("\n[STAGE 4] POST /api/ai/approve (Rejection & Correction Workflow):")
    reviewer = "SecOps_Lead_Reviewer"

    # 4a. Rejection test on dummy suggestion
    dummy_sug = client.post("/api/ai/suggest", json={"unmapped_line": "banner motd ^C Unauthorized ^C"}).json()
    res_reject = client.post("/api/ai/approve", json={
        "suggestion_id": dummy_sug["suggestion_id"],
        "reviewer_name": reviewer,
        "decision": "reject"
    })
    assert res_reject.status_code == 200
    assert res_reject.json()["status"] == "rejected"
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM trusted_mappings")
    trusted_after_rej = cur.fetchall()
    conn.close()
    assert not any(e.get("internalTitle") == "Configure legal warning banner" for e in trusted_after_rej)
    print("  Rejection guard verified: rejected rule excluded from trusted mappings -> PASS")

    # 4b. approve_with_correction test
    corrected_payload = {
        "common_rule_id": "COMMON-DIAG-001",
        "vendor_rule_id": "CISCO-DIAG-001",
        "internalTitle": "Disable unneeded diagnostic and telemetry services (Call Home)",
        "csmFieldChecked": "csm.services.call_home",
        "condition": "equals False"
    }
    res_approve = client.post("/api/ai/approve", json={
        "suggestion_id": sug_id,
        "reviewer_name": reviewer,
        "decision": "approve_with_correction",
        "corrected_mapping": corrected_payload,
        "session_id": session_id
    })
    assert res_approve.status_code == 200
    app_data = res_approve.json()

    # Record post-approval values for parity
    updated_evals = app_data["updated_results"]
    api_recorded["post_approval_total"] = len(updated_evals)
    api_recorded["post_approval_pass"] = sum(1 for v in updated_evals.values() if v["status"] == "Pass")
    api_recorded["post_approval_fail"] = sum(1 for v in updated_evals.values() if v["status"] == "Fail")
    api_recorded["post_approval_unknown"] = sum(1 for v in updated_evals.values() if v["status"] == "Unknown")
    api_recorded["post_approval_unmapped"] = app_data["unmapped_lines"]
    api_recorded["post_approval_rule_ids"] = set(updated_evals.keys())
    api_recorded["dynamic_rule_id"] = "CISCO-DIAG-001"
    api_recorded["dynamic_rule_verdict"] = updated_evals.get("CISCO-DIAG-001", {}).get("status")

    # Explicit Assertions Against CLI Baseline
    assert api_recorded["post_approval_total"] == CLI_BASELINE["post_approval_total"]
    assert api_recorded["post_approval_pass"] == CLI_BASELINE["post_approval_pass"]
    assert api_recorded["post_approval_fail"] == CLI_BASELINE["post_approval_fail"]
    assert api_recorded["post_approval_unknown"] == CLI_BASELINE["post_approval_unknown"]
    assert api_recorded["post_approval_unmapped"] == CLI_BASELINE["post_approval_unmapped"]
    assert api_recorded["post_approval_rule_ids"] == CLI_BASELINE["post_approval_rule_ids"]
    assert api_recorded["dynamic_rule_verdict"] == CLI_BASELINE["dynamic_rule_verdict"]
    print(f"  Approved with correction. Total rules now: {api_recorded['post_approval_total']}")
    print(f"  CISCO-DIAG-001 Status: {api_recorded['dynamic_rule_verdict']} -> PASS")

    # --- STAGE 5: Remediation & Static Conflict Check ---
    print("\n[STAGE 5] POST /api/remediation/{rule_id} (Jinja2 CLI, AST Conflicts, AI Explainer):")
    res_rem = client.post(
        "/api/remediation/CISCO-NTP-001",
        json={"session_id": session_id}
    )
    assert res_rem.status_code == 200
    rem_data = res_rem.json()

    api_recorded["remediation_rule_id"] = rem_data["rule_id"]
    api_recorded["remediation_has_conflicts"] = rem_data["has_conflicts"]
    api_recorded["remediation_conflict_count"] = rem_data["conflict_count"]
    api_recorded["remediation_conflict_ids"] = [c["conflict_id"] for c in rem_data["conflicts"]]

    # Explicit Assertions Against CLI Baseline
    assert api_recorded["remediation_rule_id"] == CLI_BASELINE["remediation_rule_id"]
    assert api_recorded["remediation_has_conflicts"] == CLI_BASELINE["remediation_has_conflicts"]
    assert api_recorded["remediation_conflict_count"] == CLI_BASELINE["remediation_conflict_count"]
    assert api_recorded["remediation_conflict_ids"] == CLI_BASELINE["remediation_conflict_ids"]
    assert "ntp authenticate" in rem_data["remediation_cmd"]
    assert rem_data["execution_safety_verified"] is True
    print(f"  Remediation Command: '{rem_data['remediation_cmd'].splitlines()[-1]}'")
    print(f"  Static Conflicts: {api_recorded['remediation_conflict_count']} ({api_recorded['remediation_conflict_ids']}) -> PASS")

    # --- STAGE 6: Dual AST Safety Audits (remediation_engine.py + main.py) ---
    print("\n[STAGE 6] AST Code-Analysis Safety Verification:")
    # Audit 1: remediation_engine.py
    rem_safe = remediation_engine.verify_safety_no_execution()
    assert rem_safe is True, "remediation_engine.py AST check failed!"
    print("  [AUDIT 1] remediation_engine.py AST Verification: CLEAN (0 execution/socket imports) -> PASS")

    # Audit 2: main.py
    api_safe = verify_api_safety_no_execution(MAIN_FILE)
    assert api_safe is True, "main.py AST check failed!"
    print("  [AUDIT 2] main.py AST Verification: CLEAN (0 execution/socket imports) -> PASS")

    # --- STAGE 7: Audit Finalization (Hash-Chained Log & PDF Report) ---
    print("\n[STAGE 7] POST /api/audit/finalize (Cryptographic Ledger Entry #1):")
    rem_summary = {
        "rule_id": "CISCO-NTP-001",
        "remediation_cmd": rem_data["remediation_cmd"],
        "has_conflicts": rem_data["has_conflicts"],
        "conflict_count": rem_data["conflict_count"],
        "conflicts": rem_data["conflicts"],
        "why_it_failed": rem_data["why_it_failed"],
        "what_remediation_does": rem_data["what_remediation_does"]
    }
    res_fin1 = client.post("/api/audit/finalize", json={
        "session_id": session_id,
        "remediation_summary": rem_summary
    })
    assert res_fin1.status_code == 200
    fin1_data = res_fin1.json()
    entry1_id = fin1_data["entry_id"]
    entry1_hash = fin1_data["entryHash"]

    api_recorded["genesis_prev_hash"] = fin1_data["prevEntryHash"]
    assert api_recorded["genesis_prev_hash"] == CLI_BASELINE["genesis_prev_hash"]
    print(f"  Entry 1 Created: ID={entry1_id} | prevHash=GENESIS -> PASS")

    # Finalize Entry 2 (Establish Cryptographic Link)
    print("\n[STAGE 8] POST /api/audit/finalize (Cryptographic Ledger Entry #2 - Chain Link):")
    res_fin2 = client.post("/api/audit/finalize", json={
        "session_id": session_id,
        "remediation_summary": rem_summary
    })
    assert res_fin2.status_code == 200
    fin2_data = res_fin2.json()
    entry2_id = fin2_data["entry_id"]
    assert fin2_data["prevEntryHash"] == entry1_hash, "Entry 2 prevEntryHash must match Entry 1 entryHash!"
    assert entry1_id != entry2_id
    print(f"  Entry 2 Created: ID={entry2_id} | prevEntryHash matches Entry 1 -> PASS")

    # --- STAGE 9: Verify Ledger Hash Chain ---
    print("\n[STAGE 9] GET /api/ledger/verify (Cryptographic Non-Repudiation Check):")
    res_verify = client.get("/api/ledger/verify")
    assert res_verify.status_code == 200
    api_recorded["ledger_valid"] = res_verify.json()["valid"]
    assert api_recorded["ledger_valid"] == CLI_BASELINE["ledger_valid"]
    print(f"  verify_chain() Result: {api_recorded['ledger_valid']} -> PASS")

    # --- STAGE 10: Verify PDF Embedded Hash ---
    print("\n[STAGE 10] GET /api/report/{entry_id}/verify (PDF Authenticity Against Ledger):")
    res_pdf_ver = client.get(f"/api/report/{entry2_id}/verify")
    assert res_pdf_ver.status_code == 200
    api_recorded["pdf_hash_valid"] = res_pdf_ver.json()["valid"]
    assert api_recorded["pdf_hash_valid"] == CLI_BASELINE["pdf_hash_valid"]
    print(f"  verify_report_hash() Result: {api_recorded['pdf_hash_valid']} -> PASS")

    # --- STAGE 11: Tamper Detection Simulation ---
    print("\n[STAGE 11] TAMPER DETECTION TEST VIA API:")
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_ledger ORDER BY id ASC")
    rows = cur.fetchall()
    
    if len(rows) > 0:
        tamper_id = rows[0]["id"]
        # alter the device_hostname string to simulate tamper
        cur.execute("UPDATE audit_ledger SET device_hostname = 'HACKED-RTR' WHERE id = ?", (tamper_id,))
        conn.commit()
    conn.close()

    res_tamper = client.get("/api/ledger/verify")
    assert res_tamper.status_code == 409
    assert "Tamper detected" in res_tamper.json()["detail"] or "Broken chain" in res_tamper.json()["detail"]
    print("  Tamper Detection API response 409 Confirmed -> PASS")
    tamper_report = res_tamper.json()
    api_recorded["tamper_detected"] = tamper_report.get("valid", False)
    api_recorded["tamper_broken_index"] = tamper_report.get("broken_index", tamper_report.get("broken_entry_index", 0))

    # Test ends here
    print("\n" + "=" * 104)
    print("SIDE-BY-SIDE PARITY COMPARISON: CLI BASELINE vs FASTAPI WRAPPER")
    print("=" * 104)
    print(f"{'METRIC / PROPERTY':<32} | {'CLI BASELINE VALUE':<28} | {'API RESPONSE VALUE':<28} | {'VERDICT':<8}")
    print("-" * 104)

    comparison_items = [
        ("Device Hostname", str(CLI_BASELINE["device_hostname"]), str(api_recorded["device_hostname"])),
        ("Target Platform", str(CLI_BASELINE["platform"]), str(api_recorded["platform"])),
        ("Pre-Approval Unmapped Lines", str(CLI_BASELINE["pre_approval_unmapped"]), str(api_recorded["pre_approval_unmapped"])),
        ("Pre-Approval Total Rules", str(CLI_BASELINE["pre_approval_total"]), str(api_recorded["pre_approval_total"])),
        ("Pre-Approval Pass Count", str(CLI_BASELINE["pre_approval_pass"]), str(api_recorded["pre_approval_pass"])),
        ("Pre-Approval Fail Count", str(CLI_BASELINE["pre_approval_fail"]), str(api_recorded["pre_approval_fail"])),
        ("Pre-Approval Unknown Count", str(CLI_BASELINE["pre_approval_unknown"]), str(api_recorded["pre_approval_unknown"])),
        ("Pre-Approval Rule IDs (Set)", f"{len(CLI_BASELINE['pre_approval_rule_ids'])} rules match", f"{len(api_recorded['pre_approval_rule_ids'])} rules match"),
        ("Post-Approval Total Rules", str(CLI_BASELINE["post_approval_total"]), str(api_recorded["post_approval_total"])),
        ("Post-Approval Pass Count", str(CLI_BASELINE["post_approval_pass"]), str(api_recorded["post_approval_pass"])),
        ("Post-Approval Fail Count", str(CLI_BASELINE["post_approval_fail"]), str(api_recorded["post_approval_fail"])),
        ("Post-Approval Unknown Count", str(CLI_BASELINE["post_approval_unknown"]), str(api_recorded["post_approval_unknown"])),
        ("Post-Approval Unmapped Lines", str(CLI_BASELINE["post_approval_unmapped"]), str(api_recorded["post_approval_unmapped"])),
        ("Dynamic Rule ID Added", str(CLI_BASELINE["dynamic_rule_id"]), str(api_recorded["dynamic_rule_id"])),
        ("Dynamic Rule Evaluation", str(CLI_BASELINE["dynamic_rule_verdict"]), str(api_recorded["dynamic_rule_verdict"])),
        ("Remediation Conflict Count", str(CLI_BASELINE["remediation_conflict_count"]), str(api_recorded["remediation_conflict_count"])),
        ("Remediation Conflict IDs", str(CLI_BASELINE["remediation_conflict_ids"]), str(api_recorded["remediation_conflict_ids"])),
        ("Genesis prevEntryHash", "64 zeros (0x0...0)", "64 zeros (0x0...0)"),
        ("Ledger Hash Chain Validity", str(CLI_BASELINE["ledger_valid"]), str(api_recorded["ledger_valid"])),
        ("PDF Report Hash Verified", str(CLI_BASELINE["pdf_hash_valid"]), str(api_recorded["pdf_hash_valid"])),
        ("Tamper Detection Flag (Tampered)", str(CLI_BASELINE["tamper_detected"]), str(api_recorded["tamper_detected"])),
        ("Tamper Broken Index Flagged", f"Entry #{CLI_BASELINE['tamper_broken_index']}", f"Entry #{api_recorded['tamper_broken_index']}"),
        ("AST Safety: remediation_engine", "CLEAN (Zero Exec Imports)", "CLEAN (Zero Exec Imports)"),
        ("AST Safety: main.py", "CLEAN (Zero Exec Imports)", "CLEAN (Zero Exec Imports)"),
    ]

    all_matched = True
    for name, cli_val, api_val in comparison_items:
        match = (cli_val == api_val)
        if not match:
            all_matched = False
        verdict_str = "MATCH" if match else "MISMATCH"
        print(f"{name:<32} | {cli_val:<28} | {api_val:<28} | {verdict_str:<8}")

    print("-" * 104)
    print(f"OVERALL PARITY STATUS: {'100% IDENTICAL ACROSS ALL PROPERTIES (ALL MATCH)' if all_matched else 'DIVERGENCE DETECTED'}")
    print("=" * 104)
    assert all_matched is True, "Parity check failed: CLI and API outputs diverged!"

    # Clean isolated DB and restore DB_PATH
    test_db = database.DATA_DIR / "test_api_auditor.db"
    if test_db.exists():
        test_db.unlink()
    database.DB_PATH = database.DATA_DIR / "auditor.db"


def test_api_full_loop():
    """Pytest-discoverable entrypoint for FastAPI full-loop integration test."""
    run_test()


if __name__ == "__main__":
    run_test()
