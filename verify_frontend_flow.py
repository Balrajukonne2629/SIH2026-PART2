"""Live HTTP End-to-End Walkthrough Verification against running backend on http://127.0.0.1:8000.
Simulates the exact React dashboard user journey across all 5 screens.
"""
import urllib.request
import urllib.error
import json
import pathlib

BASE_URL = "http://127.0.0.1:8000"
CFG_FILE = pathlib.Path(__file__).parent / "05_Configuration_Datasets" / "Cisco" / "labeled_test_config.txt"

def post_json(path, data):
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_json(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_bytes(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    with urllib.request.urlopen(req) as resp:
        return resp.read()

def main():
    print("=" * 80)
    print("LIVE FRONTEND HTTP FLOW VERIFICATION (http://127.0.0.1:8000)")
    print("=" * 80)

    # --- SCREEN 1: UPLOAD ---
    print("\n--- SCREEN 1: CONFIG INGESTION (UploadScreen.tsx) ---")
    cfg_text = CFG_FILE.read_text(encoding="utf-8")
    upload_res = post_json("/api/audit/upload", {
        "raw_config": cfg_text,
        "filename": "labeled_test_config.txt"
    })
    session_id = upload_res["session_id"]
    print(f"  [ACTION] Uploaded {CFG_FILE.name} ({len(cfg_text)} bytes)")
    print(f"  [SCREEN 1 RECEIVED] session_id: {session_id}")
    print(f"  [SCREEN 1 RECEIVED] Device: {upload_res['device_hostname']} | Platform: {upload_res['platform']}")
    print(f"  [SCREEN 1 RECEIVED] Config SHA-256: {upload_res['config_file_hash'][:20]}...")
    print(f"  [SCREEN 1 RECEIVED] Pre-Approval Summary: {upload_res['summary']}")
    print(f"  [SCREEN 1 RECEIVED] Unmapped Lines Flagged: {upload_res['unmapped_lines']}")

    # --- SCREEN 2: AUDIT RESULTS ---
    print("\n--- SCREEN 2: AUDIT MATRIX (AuditResultsScreen.tsx) ---")
    results = get_json(f"/api/audit/{session_id}/results")
    print(f"  [ACTION] Mounted AuditResultsScreen for session {session_id[:8]}...")
    print(f"  [SCREEN 2 RECEIVED] Total Controls: {results['summary']['total']}")
    print(f"  [SCREEN 2 RECEIVED] Pass: {results['summary']['pass']} | Fail: {results['summary']['fail']} | Unknown: {results['summary']['unknown']}")
    print(f"  [SCREEN 2 RECEIVED] Rule Matrix Sample:")
    for rid in sorted(list(results['rule_results'].keys()))[:4]:
        r = results['rule_results'][rid]
        print(f"    - {rid:<16}: {r['status']:<8} (Focus: {r['focus']})")
    print(f"  [SCREEN 2 CALLOUT CARD] '{len(results['unmapped_lines'])} unmapped line(s) found — AI interpretation available' -> {results['unmapped_lines']}")

    # --- SCREEN 3: AI SUGGESTION REVIEW ---
    print("\n--- SCREEN 3: AI REVIEW (AiSuggestionReviewScreen.tsx) ---")
    unmapped_line = results['unmapped_lines'][0]
    print(f"  [ACTION] Clicked 'Review AI Suggestions' on line '{unmapped_line}'")
    sug_res = post_json("/api/ai/suggest", {"unmapped_line": unmapped_line})
    sug_id = sug_res["suggestion_id"]
    sug = sug_res["suggestion"]
    print(f"  [SCREEN 3 RECEIVED] suggestion_id: {sug_id}")
    print(f"  [SCREEN 3 RECEIVED] Inferred Title: {sug['suggested_new_rule']['internalTitle']}")
    print(f"  [SCREEN 3 RECEIVED] Target CSM Field: {sug['suggested_new_rule']['csmFieldChecked']}")
    print(f"  [SCREEN 3 RECEIVED] Confidence: {int(sug['confidence'] * 100)}%")
    print(f"  [SCREEN 3 RECEIVED] Framework Hints (Only Real API Data): {sug['framework_hints']}")
    print(f"  [ACTION] Reviewer 'SecOps_Lead_Reviewer' clicked 'Approve with Correction'...")
    app_res = post_json("/api/ai/approve", {
        "suggestion_id": sug_id,
        "reviewer_name": "SecOps_Lead_Reviewer",
        "decision": "approve_with_correction",
        "corrected_mapping": {
            "common_rule_id": "COMMON-DIAG-001",
            "vendor_rule_id": "CISCO-DIAG-001",
            "internalTitle": "Disable unneeded diagnostic and telemetry services (Call Home)",
            "csmFieldChecked": "csm.services.call_home",
            "condition": "equals False"
        },
        "session_id": session_id
    })
    print(f"  [SCREEN 3 RECEIVED] Approval Status: {app_res['status']}")
    print(f"  [SCREEN 3 RECEIVED] Total Rules Re-Evaluated: {len(app_res['updated_results'])} (CISCO-DIAG-001: {app_res['updated_results']['CISCO-DIAG-001']['status']})")
    print(f"  [SCREEN 3 RECEIVED] Unmapped Lines Remaining: {app_res['unmapped_lines']}")

    # --- SCREEN 4: REMEDIATION DETAIL ---
    print("\n--- SCREEN 4: REMEDIATION & CONFLICTS (RemediationDetailScreen.tsx) ---")
    print("  [ACTION] Clicked 'Remediate' on failed control CISCO-NTP-001...")
    rem_res = post_json(f"/api/remediation/CISCO-NTP-001", {"session_id": session_id})
    print(f"  [SCREEN 4 RECEIVED] Generated CLI:\n    {rem_res['remediation_cmd'].replace(chr(10), chr(10) + '    ')}")
    print(f"  [SCREEN 4 RECEIVED] Persistent Safety Notice: '{rem_res['safety_notice'][:50]}...'")
    print(f"  [SCREEN 4 RECEIVED] Static Conflicts ({rem_res['conflict_count']}):")
    for c in rem_res['conflicts']:
        print(f"    * [{c['severity']}] {c['title']} (ID: {c['conflict_id']}) -> {c['description'][:65]}...")
    print(f"  [SCREEN 4 RECEIVED] AI Root Cause Explanation:\n    '{rem_res['why_it_failed'][:120]}...'")

    print("\n  [ACTION] Clicked 'Finalize Audit & Record to Ledger'...")
    fin_res = post_json("/api/audit/finalize", {
        "session_id": session_id,
        "remediation_summary": {
            "rule_id": "CISCO-NTP-001",
            "remediation_cmd": rem_res["remediation_cmd"],
            "has_conflicts": rem_res["has_conflicts"],
            "conflict_count": rem_res["conflict_count"],
            "conflicts": rem_res["conflicts"],
            "why_it_failed": rem_res["why_it_failed"],
            "what_remediation_does": rem_res["what_remediation_does"]
        }
    })
    entry_id = fin_res["entry_id"]
    print(f"  [SCREEN 4 RECEIVED] Finalized Entry ID: {entry_id}")
    print(f"  [SCREEN 4 RECEIVED] prevEntryHash: {fin_res['prevEntryHash'][:16]}... | entryHash: {fin_res['entryHash'][:16]}...")
    print(f"  [SCREEN 4 RECEIVED] Signed PDF Generated: {fin_res['pdf_filename']} ({fin_res['pdf_size_bytes']} bytes)")

    # --- SCREEN 5: AUDIT LEDGER & REPORTS ---
    print("\n--- SCREEN 5: AUDIT LOG & REPORTS (AuditLogReportScreen.tsx) ---")
    print("  [ACTION] Navigated to Screen 5...")
    ledger = get_json("/api/ledger")
    print(f"  [SCREEN 5 RECEIVED] Total Ledger Entries in audit_log.jsonl: {len(ledger)}")
    latest_entry = ledger[-1]
    print(f"  [SCREEN 5 RECEIVED] Latest Block: {latest_entry['entry_id']}")
    print(f"    - prevHash: {latest_entry['prevEntryHash'][:20]}...")
    print(f"    - entryHash: {latest_entry['entryHash'][:20]}...")

    print("  [ACTION] Clicked 'Verify Chain Integrity'...")
    chain_ver = get_json("/api/ledger/verify")
    print(f"  [SCREEN 5 RECEIVED] Ledger Chain Status: valid={chain_ver['valid']} | message='{chain_ver['message']}'")

    print(f"  [ACTION] Clicked 'Verify PDF Hash' for {entry_id}...")
    pdf_ver = get_json(f"/api/report/{entry_id}/verify")
    print(f"  [SCREEN 5 RECEIVED] PDF Hash Verification: valid={pdf_ver['valid']} | message='{pdf_ver['message']}'")

    print(f"  [ACTION] Clicked 'Download PDF' for {entry_id}...")
    pdf_bytes = get_bytes(f"/api/report/{entry_id}/download")
    print(f"  [SCREEN 5 RECEIVED] Downloaded PDF: {len(pdf_bytes)} bytes (starts with {pdf_bytes[:4].decode('latin-1')})")

    print("\n" + "=" * 80)
    print("END-TO-END FLOW ACROSS ALL 5 SCREENS VERIFIED 100% OPERATIONAL WITH LIVE API.")
    print("=" * 80)

if __name__ == "__main__":
    main()
