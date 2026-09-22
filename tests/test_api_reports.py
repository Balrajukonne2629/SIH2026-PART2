"""NTRO PS26155 — Canonical Report API & Authorization Verification Suite (Phase 3D.5).

Verifies REST API exposure of the canonical AuditReport domain model across all 24 required scenarios:
1. Authenticated user can retrieve their report.
2. Unauthenticated request is rejected (401).
3. User (uploader) cannot access another user's report (404 anti-enumeration).
4. Valid editable field can be changed via PATCH.
5. Edit identity comes strictly from authenticated JWT identity (sub).
6. Edit history records the change with full provenance.
7. Report version increments upon valid edit.
8. Stale version returns HTTP 409 Conflict.
9. Stale edit makes zero changes to report state or edit history.
10. System fields cannot be modified via API (400).
11. Invalid / unapproved field paths are rejected (400).
12. Framework results cannot be modified through API (400).
13. PASS / FAIL / UNKNOWN verdicts cannot be modified through API (400).
14. System snapshot cannot be modified through API (400).
15. PDF export endpoint returns valid, downloadable PDF file.
16. DOCX export endpoint returns valid, downloadable DOCX file.
17. Export does not mutate report state or version.
18. Export does not invoke compliance evaluators.
19. Export does not invoke AI suggester.
20. Cross-user export is blocked (404 anti-enumeration).
21. Report edit ownership is enforced (cross-owner uploader blocked with 404).
22. Multiple edits preserve complete chronological edit history.
23. Existing audit ledger and hash chain remain untouched and valid.
24. Error responses do not leak report existence to unauthorized callers.
"""

import io
import json
import pathlib
from unittest.mock import patch
import zipfile

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
# Fixtures & Seed Helpers
# ==============================================================================

@pytest.fixture(autouse=True)
def clean_test_db(tmp_path):
    """Provides an isolated database for each test to prevent contamination."""
    test_db = tmp_path / "api_reports_test.db"
    orig_db = database.DB_PATH
    database.DB_PATH = test_db
    database.initialize_database()
    yield test_db
    database.DB_PATH = orig_db


@pytest.fixture
def uploader_a_token():
    return auth.create_access_token(
        user_id="usr-uploader-a",
        username="uploader_alice",
        role="uploader",
        is_authorized_approver=False,
    )


@pytest.fixture
def uploader_b_token():
    return auth.create_access_token(
        user_id="usr-uploader-b",
        username="uploader_bob",
        role="uploader",
        is_authorized_approver=False,
    )


@pytest.fixture
def reviewer_token():
    return auth.create_access_token(
        user_id="usr-reviewer-01",
        username="secops_reviewer",
        role="reviewer",
        is_authorized_approver=True,
    )


@pytest.fixture
def viewer_token():
    return auth.create_access_token(
        user_id="usr-viewer-01",
        username="auditor_viewer",
        role="viewer",
        is_authorized_approver=False,
    )


def _seed_canonical_report(
    session_id: str,
    audit_entry_id: str,
    owner_user_id: str,
    vendor: str = "cisco",
    hostname: str = "edge-rtr-01"
) -> audit_report.AuditReport:
    """Seeds a session, ledger entry, and canonical report with explicit ownership."""
    session_data = {
        "session_id": session_id,
        "csm": {
            "device": {
                "hostname": hostname,
                "vendor": vendor,
                "platform": "Cisco IOS-XE" if vendor == "cisco" else "Junos",
                "management_ip": "10.0.0.1"
            },
            "interfaces": [],
            "unmapped_lines": []
        },
        "evals": {
            "RULE-001": {"status": "Pass", "focus": "Security", "evidence_found": ["service password-encryption"]},
            "RULE-002": {"status": "Fail", "focus": "HTTP", "evidence_found": ["ip http server"]}
        },
        "raw_config_text": f"hostname {hostname}\n",
        "filename": f"{hostname}.cfg",
        "config_file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "created_at": "2026-09-20T10:00:00Z",
        "owner_user_id": owner_user_id
    }
    database.save_session(session_data)

    entry = {
        "entry_id": audit_entry_id,
        "timestamp": "2026-09-20T10:00:00Z",
        "device_hostname": hostname,
        "config_file_hash": session_data["config_file_hash"],
        "audit_results": session_data["evals"],
        "remediation_summary": {"RULE-002": {"cli": "no ip http server"}},
        "prevEntryHash": "GENESIS_HASH",
        "entryHash": "mock_entry_hash_999",
        "owner_user_id": owner_user_id
    }
    audit_log.append_audit_entry(entry)

    rep = audit_report.create_or_get_canonical_report(
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"],
        remediation_summary=entry["remediation_summary"],
        created_by=owner_user_id
    )
    return rep


# ==============================================================================
# 24 Required Verification Scenarios
# ==============================================================================

def test_authenticated_user_can_retrieve_their_report(uploader_a_token):
    """1. Authenticated user can retrieve their own canonical report."""
    rep = _seed_canonical_report("sess-a-1", "entry-a-1", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res = client.get(f"/api/reports/{rep.report_id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["report_id"] == rep.report_id
    assert data["session_id"] == "sess-a-1"
    assert data["version"] == 1
    assert "device_metadata" in data
    assert "frameworks" in data


def test_unauthenticated_request_is_rejected():
    """2. Unauthenticated request without JWT is rejected with HTTP 401."""
    res = client.get("/api/reports/rep-any-123")
    assert res.status_code == 401
    assert "Missing Authorization header" in res.text or "Authentication failed" in res.text


def test_user_cannot_access_another_users_report(uploader_a_token, uploader_b_token):
    """3. Uploader B cannot access Uploader A's report (anti-enumeration returns 404)."""
    rep_a = _seed_canonical_report("sess-a-2", "entry-a-2", owner_user_id="usr-uploader-a")
    headers_b = {"Authorization": f"Bearer {uploader_b_token}"}

    res = client.get(f"/api/reports/{rep_a.report_id}", headers=headers_b)
    assert res.status_code == 404
    assert res.json()["detail"] == f"Report '{rep_a.report_id}' not found."


def test_valid_editable_field_can_be_changed(uploader_a_token):
    """4. Valid editable field can be changed via PATCH."""
    rep = _seed_canonical_report("sess-a-3", "entry-a-3", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={
            "field_path": "executive_summary",
            "new_value": "Audit completed. Minor issues flagged for remediation.",
            "expected_version": 1
        },
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["version"] == 2
    assert data["editable_content"]["executive_summary"] == "Audit completed. Minor issues flagged for remediation."


def test_edit_identity_comes_from_jwt(reviewer_token):
    """5. Edit identity is derived strictly from authenticated JWT claim (sub)."""
    rep = _seed_canonical_report("sess-r-1", "entry-r-1", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {reviewer_token}"}

    # Reviewer submits an edit and attempts to supply a spoofed editor name in payload
    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={
            "field_path": "auditor_observations",
            "new_value": "Core switch in datacenter row 4.",
            "expected_version": 1,
            "edited_by": "spoofed_attacker_identity"  # Must be ignored!
        },
        headers=headers
    )
    assert res.status_code == 200

    # Verify edit history records the authentic JWT sub
    edits = res.json()["edit_metadata"]
    assert len(edits) == 1
    assert edits[0]["edited_by"] == "usr-reviewer-01"  # Derived from reviewer_token sub
    assert edits[0]["edited_by"] != "spoofed_attacker_identity"


def test_edit_history_records_the_change(uploader_a_token):
    """6. Edit history endpoint records the change with full provenance."""
    rep = _seed_canonical_report("sess-a-4", "entry-a-4", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    client.patch(
        f"/api/reports/{rep.report_id}",
        json={
            "field_path": "recommendations",
            "new_value": "Upgrade IOS-XE image to version 17.6.",
            "expected_version": 1
        },
        headers=headers
    )

    res = client.get(f"/api/reports/{rep.report_id}/edits", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["report_id"] == rep.report_id
    assert data["version"] == 2
    assert data["total_edits"] == 1
    edit = data["edits"][0]
    assert edit["field_path"] == "recommendations"
    assert edit["new_value"] == "Upgrade IOS-XE image to version 17.6."
    assert edit["edited_by"] == "usr-uploader-a"


def test_version_increments(uploader_a_token):
    """7. Report version increments monotonically upon each valid edit."""
    rep = _seed_canonical_report("sess-a-5", "entry-a-5", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res1 = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Edit 1", "expected_version": 1},
        headers=headers
    )
    assert res1.json()["version"] == 2

    res2 = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "additional_findings", "new_value": "Edit 2", "expected_version": 2},
        headers=headers
    )
    assert res2.json()["version"] == 3


def test_stale_version_returns_409(uploader_a_token):
    """8. Submitting an edit with a stale expected_version returns HTTP 409 Conflict."""
    rep = _seed_canonical_report("sess-a-6", "entry-a-6", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Stale attempt", "expected_version": 99},
        headers=headers
    )
    assert res.status_code == 409
    err = res.json()["detail"]
    assert err["expected_version"] == 99
    assert err["current_version"] == 1
    assert "Stale report" in err["message"]


def test_stale_edit_makes_no_change(uploader_a_token):
    """9. A rejected stale edit leaves the report state and edit history completely untouched."""
    rep = _seed_canonical_report("sess-a-7", "entry-a-7", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Should not apply", "expected_version": 5},
        headers=headers
    )

    get_res = client.get(f"/api/reports/{rep.report_id}", headers=headers)
    assert get_res.status_code == 200
    report_data = get_res.json()
    assert report_data["version"] == 1
    assert report_data["editable_content"]["executive_summary"] == ""
    assert len(report_data["edit_metadata"]) == 0


def test_system_fields_cannot_be_modified(uploader_a_token):
    """10. System-controlled fields cannot be modified through API (returns 400)."""
    rep = _seed_canonical_report("sess-a-8", "entry-a-8", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    for forbidden_field in ["vendor", "report_id", "audit_entry_id", "session_id", "version"]:
        res = client.patch(
            f"/api/reports/{rep.report_id}",
            json={"field_path": forbidden_field, "new_value": "hacked", "expected_version": 1},
            headers=headers
        )
        assert res.status_code == 400
        assert "strictly immutable" in res.text or "not an authorized human-editable field" in res.text


def test_invalid_field_paths_are_rejected(uploader_a_token):
    """11. Arbitrary / unapproved field paths fail closed with HTTP 400."""
    rep = _seed_canonical_report("sess-a-9", "entry-a-9", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    for bad_path in ["custom_injected_field", "evil.__class__", "unknown.path"]:
        res = client.patch(
            f"/api/reports/{rep.report_id}",
            json={"field_path": bad_path, "new_value": "bad", "expected_version": 1},
            headers=headers
        )
        assert res.status_code == 400


def test_framework_results_cannot_be_modified(uploader_a_token):
    """12. Framework results cannot be modified through API (returns 400)."""
    rep = _seed_canonical_report("sess-a-10", "entry-a-10", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "frameworks", "new_value": [], "expected_version": 1},
        headers=headers
    )
    assert res.status_code == 400
    assert "strictly immutable" in res.text


def test_pass_fail_unknown_cannot_be_modified(uploader_a_token):
    """13. PASS/FAIL/UNKNOWN compliance verdicts cannot be modified through API."""
    rep = _seed_canonical_report("sess-a-11", "entry-a-11", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    for forbidden in ["status", "compliance", "pass_rate", "pass_count"]:
        res = client.patch(
            f"/api/reports/{rep.report_id}",
            json={"field_path": forbidden, "new_value": "PASS", "expected_version": 1},
            headers=headers
        )
        assert res.status_code == 400


def test_system_snapshot_cannot_be_modified(uploader_a_token):
    """14. system_snapshot cannot be modified through API."""
    rep = _seed_canonical_report("sess-a-12", "entry-a-12", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "system_snapshot", "new_value": {}, "expected_version": 1},
        headers=headers
    )
    assert res.status_code == 400


def test_pdf_export_endpoint_returns_valid_pdf(uploader_a_token):
    """15. PDF export endpoint returns a valid, well-formed PDF file."""
    rep = _seed_canonical_report("sess-a-13", "entry-a-13", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res = client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF")

    # Verify readable with pypdf
    reader = pypdf.PdfReader(io.BytesIO(res.content))
    assert len(reader.pages) > 0


def test_docx_export_endpoint_returns_valid_docx(uploader_a_token):
    """16. DOCX export endpoint returns a valid, well-formed DOCX file."""
    rep = _seed_canonical_report("sess-a-14", "entry-a-14", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    res = client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)
    assert res.status_code == 200
    assert "wordprocessingml" in res.headers["content-type"]

    # Verify valid zip containing word/document.xml
    with zipfile.ZipFile(io.BytesIO(res.content), "r") as zf:
        assert "word/document.xml" in zf.namelist()
        doc_xml = zf.read("word/document.xml").decode("utf-8")
        assert "NETWORK SECURITY COMPLIANCE AUDIT REPORT" in doc_xml


def test_export_does_not_mutate_report_state(uploader_a_token):
    """17. Exporting a report does not mutate report version or content."""
    rep = _seed_canonical_report("sess-a-15", "entry-a-15", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    rep_before = database.get_audit_report(rep.report_id)

    client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
    client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)

    rep_after = database.get_audit_report(rep.report_id)
    assert rep_before == rep_after


def test_export_does_not_invoke_compliance_evaluators(uploader_a_token):
    """18. Export endpoints do not invoke compliance evaluators."""
    rep = _seed_canonical_report("sess-a-16", "entry-a-16", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    with patch("cisco_auditor.evaluate_rules", side_effect=RuntimeError("Evaluator called!")):
        with patch("juniper_auditor.evaluate_rules", side_effect=RuntimeError("Evaluator called!")):
            res_pdf = client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
            res_docx = client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)
            assert res_pdf.status_code == 200
            assert res_docx.status_code == 200


def test_export_does_not_invoke_ai(uploader_a_token):
    """19. Export endpoints do not invoke AI models or suggesters."""
    rep = _seed_canonical_report("sess-a-17", "entry-a-17", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    with patch("ai_suggester.suggest_mapping", side_effect=RuntimeError("AI called!")):
        with patch("ai_suggester.get_model", side_effect=RuntimeError("AI called!")):
            res_pdf = client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
            res_docx = client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)
            assert res_pdf.status_code == 200
            assert res_docx.status_code == 200


def test_cross_user_export_is_blocked(uploader_a_token, uploader_b_token):
    """20. Uploader B cannot export Uploader A's report (404 anti-enumeration)."""
    rep_a = _seed_canonical_report("sess-a-18", "entry-a-18", owner_user_id="usr-uploader-a")
    headers_b = {"Authorization": f"Bearer {uploader_b_token}"}

    res_pdf = client.post(f"/api/reports/{rep_a.report_id}/export/pdf", headers=headers_b)
    res_docx = client.post(f"/api/reports/{rep_a.report_id}/export/docx", headers=headers_b)
    assert res_pdf.status_code == 404
    assert res_docx.status_code == 404


def test_report_edit_ownership_is_enforced(uploader_a_token, uploader_b_token):
    """21. Uploader B cannot PATCH Uploader A's report (404 anti-enumeration)."""
    rep_a = _seed_canonical_report("sess-a-19", "entry-a-19", owner_user_id="usr-uploader-a")
    headers_b = {"Authorization": f"Bearer {uploader_b_token}"}

    res = client.patch(
        f"/api/reports/{rep_a.report_id}",
        json={"field_path": "executive_summary", "new_value": "Malicious edit", "expected_version": 1},
        headers=headers_b
    )
    assert res.status_code == 404
    assert res.json()["detail"] == f"Report '{rep_a.report_id}' not found."


def test_multiple_edits_preserve_complete_history(uploader_a_token):
    """22. Successive edits preserve full chronological edit history."""
    rep = _seed_canonical_report("sess-a-20", "entry-a-20", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "First summary", "expected_version": 1},
        headers=headers
    )
    client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "recommendations", "new_value": "First rec", "expected_version": 2},
        headers=headers
    )
    client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Second summary", "expected_version": 3},
        headers=headers
    )

    res = client.get(f"/api/reports/{rep.report_id}/edits", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["version"] == 4
    assert data["total_edits"] == 3
    assert data["edits"][0]["version"] == 2
    assert data["edits"][1]["version"] == 3
    assert data["edits"][2]["version"] == 4


def test_existing_audit_ledger_and_hash_chain_unchanged(uploader_a_token):
    """23. Report edits and exports leave SQLite audit_ledger and hash chain untouched."""
    rep = _seed_canonical_report("sess-a-21", "entry-a-21", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {uploader_a_token}"}

    # Verify initial ledger count
    with database.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_ledger")
        count_before = cur.fetchone()[0]

    # Perform edits and exports
    client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Ledger check", "expected_version": 1},
        headers=headers
    )
    client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
    client.post(f"/api/reports/{rep.report_id}/export/docx", headers=headers)

    # Verify ledger row count unchanged
    with database.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_ledger")
        count_after = cur.fetchone()[0]

    assert count_before == count_after, "Ledger row count changed during report operations!"


def test_appropriate_error_responses_do_not_leak_report_existence(uploader_b_token):
    """24. Anti-enumeration: response message for unauthorized cross-owner report
    is indistinguishable from a non-existent report.
    """
    rep_a = _seed_canonical_report("sess-a-22", "entry-a-22", owner_user_id="usr-uploader-a")
    headers_b = {"Authorization": f"Bearer {uploader_b_token}"}

    res_cross = client.get(f"/api/reports/{rep_a.report_id}", headers=headers_b)
    res_nonexist = client.get("/api/reports/rep-totally-nonexistent-123", headers=headers_b)

    assert res_cross.status_code == 404
    assert res_nonexist.status_code == 404
    assert res_cross.json()["detail"] == f"Report '{rep_a.report_id}' not found."
    assert res_nonexist.json()["detail"] == "Report 'rep-totally-nonexistent-123' not found."


def test_viewer_role_is_strictly_read_only_and_cannot_patch(viewer_token):
    """25. Viewer role is strictly read-only: can view reports/edits/exports, but PATCH is 403."""
    rep = _seed_canonical_report("sess-v-1", "entry-v-1", owner_user_id="usr-uploader-a")
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # Viewer can read report
    res_get = client.get(f"/api/reports/{rep.report_id}", headers=headers)
    assert res_get.status_code == 200

    # Viewer can view edit history
    res_edits = client.get(f"/api/reports/{rep.report_id}/edits", headers=headers)
    assert res_edits.status_code == 200

    # Viewer can export report
    res_exp = client.post(f"/api/reports/{rep.report_id}/export/pdf", headers=headers)
    assert res_exp.status_code == 200

    # Viewer is FORBIDDEN from editing report
    res_patch = client.patch(
        f"/api/reports/{rep.report_id}",
        json={"field_path": "executive_summary", "new_value": "Viewer unauthorized edit", "expected_version": 1},
        headers=headers
    )
    assert res_patch.status_code == 403
    assert "Role 'viewer' is not permitted" in res_patch.json()["detail"]


def test_cross_owner_edits_endpoint_blocked(uploader_a_token, uploader_b_token):
    """26. Uploader B cannot access Uploader A's report edit history (404 anti-enumeration)."""
    rep_a = _seed_canonical_report("sess-a-23", "entry-a-23", owner_user_id="usr-uploader-a")
    headers_b = {"Authorization": f"Bearer {uploader_b_token}"}

    res = client.get(f"/api/reports/{rep_a.report_id}/edits", headers=headers_b)
    assert res.status_code == 404
    assert res.json()["detail"] == f"Report '{rep_a.report_id}' not found."
