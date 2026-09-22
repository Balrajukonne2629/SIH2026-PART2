"""NTRO PS26155 — Phase 3D Report Workflow Repair Verification Suite.

Covers the 14 required test scenarios from the repair spec:
 1. reviewer can GET own report
 2. reviewer can edit an allowed field
 3. edit increments report version
 4. edit history records canonical JWT identity
 5. stale version returns 409
 6. immutable field edit is rejected
 7. reviewer can export PDF
 8. reviewer can export DOCX
 9. viewer/uploader permissions remain correct
10. cross-owner access remains 404/anti-enumerated
11. export does not mutate report
12. export does not invoke evaluator or AI
13. PDF/DOCX contain the same canonical report data
14. existing report/export/lifecycle tests remain green (verified by running those suites)
"""

import io
import json
import zipfile
from unittest.mock import patch

import pypdf
import pytest
from fastapi.testclient import TestClient

import audit_log
import audit_report
import auth
import database
from main import app

client = TestClient(app)


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    orig = database.DB_PATH
    database.DB_PATH = tmp_path / "repair_test.db"
    database.initialize_database()
    yield
    database.DB_PATH = orig


def _make_token(user_id: str, role: str, is_approver: bool = True) -> str:
    return auth.create_access_token(
        user_id=user_id,
        username=f"user_{user_id.replace('-', '_')}",
        role=role,
        is_authorized_approver=is_approver,
    )


def _seed_report(session_id: str, entry_id: str, owner_id: str) -> audit_report.AuditReport:
    """Seeds session + ledger entry + canonical report owned by owner_id."""
    session_data = {
        "session_id": session_id,
        "csm": {
            "device": {
                "hostname": "rtr-test-01",
                "vendor": "cisco",
                "platform": "Cisco IOS-XE",
                "management_ip": "10.0.0.1",
            },
            "interfaces": [],
            "unmapped_lines": [],
        },
        "evals": {
            "RULE-001": {"status": "Pass", "focus": "Security", "evidence_found": []},
            "RULE-002": {"status": "Fail", "focus": "HTTP", "evidence_found": []},
        },
        "raw_config_text": "hostname rtr-test-01\n",
        "filename": "rtr-test-01.cfg",
        "config_file_hash": "e3b0c44298fc1c149afbf4c8996fb924",
        "created_at": "2026-09-20T10:00:00Z",
        "owner_user_id": owner_id,
    }
    database.save_session(session_data)

    entry = {
        "entry_id": entry_id,
        "timestamp": "2026-09-20T10:00:00Z",
        "device_hostname": "rtr-test-01",
        "config_file_hash": session_data["config_file_hash"],
        "audit_results": session_data["evals"],
        "remediation_summary": None,
        "prevEntryHash": "GENESIS",
        "entryHash": "mock_hash_001",
        "owner_user_id": owner_id,
    }
    audit_log.append_audit_entry(entry)

    return audit_report.create_or_get_canonical_report(
        audit_entry_id=entry_id,
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"],
        created_by=owner_id,
    )


# ==============================================================================
# 1. Reviewer can GET own report
# ==============================================================================
def test_reviewer_can_get_own_report():
    """Scenario 1: reviewer-authenticated user retrieves their canonical report."""
    reviewer_id = "usr-reviewer-r1"
    rep = _seed_report("sess-r1", "entry-r1", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    res = client.get(f"/api/reports/{rep.report_id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["report_id"] == rep.report_id
    assert "editable_content" in data
    assert "frameworks" in data


# ==============================================================================
# 2. Reviewer can edit an allowed field
# ==============================================================================
def test_reviewer_can_edit_allowed_field():
    """Scenario 2: reviewer can PATCH an allowlisted editable field."""
    reviewer_id = "usr-reviewer-r2"
    rep = _seed_report("sess-r2", "entry-r2", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Reviewed by SecOps.", "expected_version": 1},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json()["editable_content"]["executive_summary"] == "Reviewed by SecOps."


# ==============================================================================
# 3. Edit increments report version
# ==============================================================================
def test_edit_increments_version():
    """Scenario 3: each valid edit monotonically increments the report version."""
    reviewer_id = "usr-reviewer-r3"
    rep = _seed_report("sess-r3", "entry-r3", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    r1 = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "v2", "expected_version": 1},
        headers=headers,
    )
    assert r1.json()["version"] == 2

    r2 = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "recommendations", "new_value": "Upgrade firmware.", "expected_version": 2},
        headers=headers,
    )
    assert r2.json()["version"] == 3


# ==============================================================================
# 4. Edit history records canonical JWT identity
# ==============================================================================
def test_edit_history_records_jwt_identity():
    """Scenario 4: edit_metadata.edited_by is derived from the JWT sub claim, never from request body."""
    reviewer_id = "usr-reviewer-r4"
    rep = _seed_report("sess-r4", "entry-r4", "usr-uploader-x")
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={
            "field_path": "final_reviewer_notes",
            "new_value": "Signed off.",
            "expected_version": 1,
            "edited_by": "spoofed-attacker",  # must be ignored
        },
        headers=headers,
    )
    assert res.status_code == 200
    edits = res.json()["edit_metadata"]
    assert len(edits) == 1
    assert edits[0]["edited_by"] == reviewer_id
    assert edits[0]["edited_by"] != "spoofed-attacker"


# ==============================================================================
# 5. Stale version returns 409
# ==============================================================================
def test_stale_version_returns_409():
    """Scenario 5: submitting an edit with stale expected_version → 409 Conflict."""
    reviewer_id = "usr-reviewer-r5"
    rep = _seed_report("sess-r5", "entry-r5", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "stale", "expected_version": 99},
        headers=headers,
    )
    assert res.status_code == 409
    err = res.json()["detail"]
    assert err["expected_version"] == 99
    assert err["current_version"] == 1


# ==============================================================================
# 6. Immutable field edit is rejected
# ==============================================================================
def test_immutable_field_edit_rejected():
    """Scenario 6: editing a system-immutable field returns 400."""
    reviewer_id = "usr-reviewer-r6"
    rep = _seed_report("sess-r6", "entry-r6", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    for forbidden in ["vendor", "frameworks", "status", "evidence", "report_id"]:
        res = client.patch(
            f"/api/reports/{rep.report_id}",
            json={"field_path": forbidden, "new_value": "hacked", "expected_version": 1},
            headers=headers,
        )
        assert res.status_code == 400, f"Expected 400 for immutable field '{forbidden}', got {res.status_code}"


# ==============================================================================
# 7. Reviewer can export PDF
# ==============================================================================
def test_reviewer_can_export_pdf():
    """Scenario 7: reviewer-authenticated user can download the PDF export."""
    reviewer_id = "usr-reviewer-r7"
    rep = _seed_report("sess-r7", "entry-r7", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    res = client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
    assert res.status_code == 200, f"Reviewer PDF export failed: {res.status_code} — {res.text}"
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF")

    reader = pypdf.PdfReader(io.BytesIO(res.content))
    assert len(reader.pages) > 0


# ==============================================================================
# 8. Reviewer can export DOCX
# ==============================================================================
def test_reviewer_can_export_docx():
    """Scenario 8: reviewer-authenticated user can download the DOCX export."""
    reviewer_id = "usr-reviewer-r8"
    rep = _seed_report("sess-r8", "entry-r8", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    res = client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)
    assert res.status_code == 200, f"Reviewer DOCX export failed: {res.status_code} — {res.text}"
    assert "wordprocessingml" in res.headers["content-type"]

    with zipfile.ZipFile(io.BytesIO(res.content), "r") as zf:
        assert "word/document.xml" in zf.namelist()


# ==============================================================================
# 9. Viewer/uploader permissions remain correct
# ==============================================================================
def test_viewer_can_read_and_export_but_not_patch():
    """Scenario 9a: viewer can GET and export but not PATCH."""
    owner_id = "usr-uploader-v9"
    rep = _seed_report("sess-v9", "entry-v9", owner_id)
    viewer_headers = {"Authorization": f"Bearer {_make_token('usr-viewer-v9', 'viewer', is_approver=False)}"}

    assert client.get(f"/api/reports/{rep.report_id}", headers=viewer_headers).status_code == 200
    assert client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=viewer_headers).status_code == 200
    assert client.post(f"/api/reports/{rep.report_id}/export/docx", headers=viewer_headers).status_code == 200

    patch_res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "viewer hack", "expected_version": 1},
        headers=viewer_headers,
    )
    assert patch_res.status_code == 403


def test_uploader_can_edit_own_report():
    """Scenario 9b: uploader can PATCH their own report."""
    owner_id = "usr-uploader-u9"
    rep = _seed_report("sess-u9", "entry-u9", owner_id)
    headers = {"Authorization": f"Bearer {_make_token(owner_id, 'uploader', is_approver=False)}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "auditor_observations", "new_value": "Uploader obs", "expected_version": 1},
        headers=headers,
    )
    assert res.status_code == 200


# ==============================================================================
# 10. Cross-owner access remains 404/anti-enumerated
# ==============================================================================
def test_cross_owner_access_is_404():
    """Scenario 10: uploader B cannot access uploader A's report."""
    rep_a = _seed_report("sess-cross-a", "entry-cross-a", "usr-uploader-a")
    headers_b = {"Authorization": f"Bearer {_make_token('usr-uploader-b', 'uploader', is_approver=False)}"}

    assert client.get(f"/api/reports/{rep_a.report_id}", headers=headers_b).status_code == 404
    assert client.patch(
        f"/api/reports/{rep_a.report_id}",
        json={"field_path": "executive_summary", "new_value": "x", "expected_version": 1},
        headers=headers_b,
    ).status_code == 404
    assert client.post(f"/api/reports/{rep_a.report_id}/export/pdf", headers=headers_b).status_code == 404
    assert client.post(f"/api/reports/{rep_a.report_id}/export/docx", headers=headers_b).status_code == 404


# ==============================================================================
# 11. Export does not mutate report
# ==============================================================================
def test_export_does_not_mutate_report():
    """Scenario 11: exporting does not change report version, content, or edit history."""
    reviewer_id = "usr-reviewer-r11"
    rep = _seed_report("sess-r11", "entry-r11", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    before = database.get_audit_report(rep.report_id)
    client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
    client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)
    after = database.get_audit_report(rep.report_id)

    assert before == after, "Report was mutated during export!"


# ==============================================================================
# 12. Export does not invoke evaluator or AI
# ==============================================================================
def test_export_does_not_invoke_evaluator_or_ai():
    """Scenario 12: PDF/DOCX export endpoints never call compliance evaluators or AI."""
    reviewer_id = "usr-reviewer-r12"
    rep = _seed_report("sess-r12", "entry-r12", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    with patch("cisco_auditor.evaluate_rules", side_effect=RuntimeError("Evaluator called!")):
        with patch("ai_suggester.suggest_mapping", side_effect=RuntimeError("AI called!")):
            res_pdf = client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
            res_docx = client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)

    assert res_pdf.status_code == 200
    assert res_docx.status_code == 200


# ==============================================================================
# 13. PDF and DOCX contain the same canonical report data
# ==============================================================================
def test_pdf_and_docx_contain_same_canonical_data():
    """Scenario 13: both export formats faithfully represent the same canonical report."""
    reviewer_id = "usr-reviewer-r13"
    rep = _seed_report("sess-r13", "entry-r13", reviewer_id)
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    # Add an editable field first so we have something distinctive
    client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Cross-format parity check.", "expected_version": 1},
        headers=headers,
    )

    res_pdf = client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
    res_docx = client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)
    assert res_pdf.status_code == 200
    assert res_docx.status_code == 200

    # Extract PDF text
    reader = pypdf.PdfReader(io.BytesIO(res_pdf.content))
    pdf_text = "\n".join(page.extract_text() or "" for page in reader.pages)

    # Extract DOCX XML
    with zipfile.ZipFile(io.BytesIO(res_docx.content), "r") as zf:
        docx_xml = zf.read("word/document.xml").decode("utf-8")

    # Both must contain the hostname and the edited summary
    assert "rtr-test-01" in pdf_text
    assert "rtr-test-01" in docx_xml
    assert "Cross-format parity check." in pdf_text
    assert "Cross-format parity check." in docx_xml

    # [Edited manually] provenance must appear in both (since we made an edit)
    assert "[Edited manually]" in pdf_text
    assert "[Edited manually]" in docx_xml


# ==============================================================================
# 15. Ledger exposes canonical report metadata and handles legacy entries cleanly
# ==============================================================================
def test_ledger_exposes_canonical_report_metadata():
    """Scenario 15: GET /api/ledger returns has_canonical_report and report_id,
    with legacy entries returning False/None without failing or requiring N+1 lookups.
    """
    reviewer_id = "usr-reviewer-r15"
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    # Seed 1: Legacy entry (only ledger entry, no audit_report)
    legacy_entry = {
        "entry_id": "AUDIT-LEGACY-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "device_hostname": "rtr-legacy",
        "config_file_hash": "hash_legacy",
        "audit_results": {},
        "remediation_summary": None,
        "prevEntryHash": "GENESIS",
        "entryHash": "entry_hash_leg",
        "owner_user_id": reviewer_id,
    }
    audit_log.append_audit_entry(legacy_entry)

    # Seed 2: Canonical entry (session + ledger + audit_report)
    rep = _seed_report("sess-can-002", "AUDIT-CAN-002", reviewer_id)

    res = client.get("/api/ledger", headers=headers)
    assert res.status_code == 200
    entries = res.json()
    assert len(entries) >= 2

    # Map by entry_id
    by_id = {e["entry_id"]: e for e in entries}

    # Verify legacy entry
    assert "AUDIT-LEGACY-001" in by_id
    assert by_id["AUDIT-LEGACY-001"]["has_canonical_report"] is False
    assert by_id["AUDIT-LEGACY-001"]["report_id"] is None

    # Verify canonical entry
    assert "AUDIT-CAN-002" in by_id
    assert by_id["AUDIT-CAN-002"]["has_canonical_report"] is True
    assert by_id["AUDIT-CAN-002"]["report_id"] == rep.report_id


# ==============================================================================
# 16. Ledger uploader anti-enumeration for canonical report metadata
# ==============================================================================
def test_ledger_uploader_anti_enumeration():
    """Scenario 16: Uploader only sees report_id/has_canonical_report for their own audits."""
    uploader_a = "usr-uploader-a"
    uploader_b = "usr-uploader-b"
    _seed_report("sess-a", "AUDIT-A", uploader_a)
    _seed_report("sess-b", "AUDIT-B", uploader_b)

    headers_a = {"Authorization": f"Bearer {_make_token(uploader_a, 'uploader', is_approver=False)}"}
    res_a = client.get("/api/ledger", headers=headers_a)
    assert res_a.status_code == 200
    entries_a = {e["entry_id"]: e for e in res_a.json()}

    # Uploader A sees their own report
    assert entries_a["AUDIT-A"]["has_canonical_report"] is True
    assert entries_a["AUDIT-A"]["report_id"] is not None

    # Uploader A cannot enumerate Uploader B's report
    assert entries_a["AUDIT-B"]["has_canonical_report"] is False
    assert entries_a["AUDIT-B"]["report_id"] is None


# ==============================================================================
# 17. End-to-end new audit finalization and export workflow
# ==============================================================================
def test_new_audit_finalization_and_export_workflow():
    """Scenario 17: Full lifecycle for new audit: finalize -> canonical report -> ledger metadata -> exports."""
    reviewer_id = "usr-reviewer-new"
    headers = {"Authorization": f"Bearer {_make_token(reviewer_id, 'reviewer')}"}

    # 1. Seed audit session
    session_id = "sess-new-e2e"
    session_data = {
        "session_id": session_id,
        "csm": {
            "device": {"hostname": "core-sw-01", "vendor": "cisco", "platform": "IOS-XE", "management_ip": "192.168.1.1"},
            "interfaces": [],
            "unmapped_lines": [],
        },
        "evals": {
            "RULE-SEC-01": {"status": "Pass", "focus": "AAA", "evidence_found": ["aaa new-model"]},
        },
        "raw_config_text": "hostname core-sw-01\naaa new-model\n",
        "filename": "core-sw-01.cfg",
        "config_file_hash": "abcdef1234567890abcdef1234567890abcdef12",
        "created_at": "2026-09-22T10:00:00Z",
        "owner_user_id": reviewer_id,
    }
    database.save_session(session_data)

    # 2. Finalize audit
    fin_res = client.post("/api/audit/finalize", json={
        "session_id": session_id,
        "remediation_summary": {"RULE-SEC-01": "remediated"}
    }, headers=headers)
    assert fin_res.status_code == 200
    fin_data = fin_res.json()
    assert "report_id" in fin_data
    assert "entry_id" in fin_data
    report_id = fin_data["report_id"]
    entry_id = fin_data["entry_id"]

    # 3. Verify ledger exposes canonical report metadata directly
    ledger_res = client.get("/api/ledger", headers=headers)
    assert ledger_res.status_code == 200
    ledger_items = {e["entry_id"]: e for e in ledger_res.json()}
    assert entry_id in ledger_items
    assert ledger_items[entry_id]["has_canonical_report"] is True
    assert ledger_items[entry_id]["report_id"] == report_id

    # 4. Verify canonical report lookup
    rep_res = client.get(f"/api/reports/{report_id}", headers=headers)
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["report_id"] == report_id
    assert rep_data["audit_entry_id"] == entry_id

    # 5. Verify PDF export
    pdf_res = client.post(f"/api/reports/{report_id}/export/pdf", headers=headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 0

    # 6. Verify DOCX export
    docx_res = client.post(f"/api/reports/{report_id}/export/docx", headers=headers)
    assert docx_res.status_code == 200
    assert "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in docx_res.headers["content-type"]
    assert len(docx_res.content) > 0

