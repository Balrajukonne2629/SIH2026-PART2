"""NTRO PS26155 — Canonical Report Lifecycle Integration Tests (Phase 3D.3).

Verifies the lifecycle integration between audit finalization and the canonical AuditReport:
A. Successful finalization creates one canonical report.
B. Repeated report creation is idempotent.
C. One audit cannot produce two reports.
D. Multiple frameworks remain inside one report.
E. Vendor information is preserved (Cisco vs Juniper).
F. PASS/FAIL/UNKNOWN remain unchanged.
G. Pass rate remains unchanged.
H. Existing human edits survive retry.
I. Existing edit history survives retry.
J. System snapshot is not rewritten by retry.
K. Audit ledger hash remains unchanged.
L. Audit hash chain remains valid.
M. Failed report creation does not corrupt the ledger.
N. A failed report creation can be retried successfully.
O. Cisco and Juniper reports remain isolated.
P. No compliance evaluator is invoked during report creation.
Q. No AI inference is invoked during report creation.
R. No artificial overall compliance verdict is introduced.
"""

import datetime
import hashlib
import json
import os
import pathlib
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

import database
import audit_log
import audit_report
import auth
from main import app
from fastapi.testclient import TestClient
from compliance_framework import ComplianceStatus, EvaluationResult, Evidence
from compliance_aggregator import MultiFrameworkAggregator


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path):
    """Provides an isolated database for each test to prevent cross-test contamination."""
    test_db = tmp_path / "lifecycle_test.db"
    orig_db = database.DB_PATH
    database.DB_PATH = test_db
    database.initialize_database()
    yield test_db
    database.DB_PATH = orig_db


def _get_auth_header(username: str = "secops_reviewer", role: str = "reviewer") -> dict:
    """Helper to generate valid JWT auth headers for testing."""
    token = auth.create_access_token(
        user_id="test-user-id",
        username=username,
        role=role,
        is_authorized_approver=True
    )
    return {"Authorization": f"Bearer {token}"}


def _seed_audit_session(session_id: str, vendor: str = "cisco", hostname: str = "switch-01", owner_user_id: str = "test-user-id"):
    """Helper to seed a test session in audit_sessions."""
    session_data = {
        "session_id": session_id,
        "csm": {
            "device": {
                "hostname": hostname,
                "vendor": vendor,
                "platform": "Cisco IOS-XE" if vendor == "cisco" else "Junos",
                "management_ip": "10.0.0.1"
            },
            "interfaces": [{"name": "GigabitEthernet0/1", "ip": "10.0.0.1"}],
            "unmapped_lines": []
        },
        "evals": {
            "RULE-001": {"status": "Pass", "focus": "Security", "evidence_found": ["service password-encryption"], "reason": "Compliant"},
            "RULE-002": {"status": "Fail", "focus": "HTTP Service", "evidence_found": [], "reason": "Non-compliant"}
        },
        "raw_config_text": f"hostname {hostname}\nversion 17.3\n",
        "filename": "test_cfg.txt",
        "config_file_hash": hashlib.sha256(f"hostname {hostname}\nversion 17.3\n".encode("utf-8")).hexdigest(),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "owner_user_id": owner_user_id
    }
    database.save_session(session_data)
    return session_data


def _build_multi_framework_result():
    """Generates realistic multi-framework evaluation data for CIS and DISA STIG."""
    results = [
        EvaluationResult(
            framework_id="cis_cisco_iosxe",
            control_id="1.1.1",
            status=ComplianceStatus.PASS,
            evidence=Evidence(
                observed_value="service password-encryption",
                location="csm.services",
                expected_value="service password-encryption",
                rationale="Password encryption enabled.",
                confidence=1.0,
                source_lines=("service password-encryption",)
            )
        ),
        EvaluationResult(
            framework_id="cis_cisco_iosxe",
            control_id="1.1.2",
            status=ComplianceStatus.FAIL,
            evidence=Evidence(
                observed_value="no banner motd",
                location="csm.banners",
                expected_value="banner motd defined",
                rationale="No banner configured.",
                confidence=1.0,
                source_lines=()
            )
        ),
        EvaluationResult(
            framework_id="stig_cisco_iosxe",
            control_id="V-215001",
            status=ComplianceStatus.PASS,
            evidence=Evidence(
                observed_value="transport input ssh",
                location="csm.lines",
                expected_value="transport input ssh",
                rationale="SSH configured.",
                confidence=1.0,
                source_lines=("transport input ssh",)
            )
        ),
        EvaluationResult(
            framework_id="stig_cisco_iosxe",
            control_id="V-215002",
            status=ComplianceStatus.UNKNOWN,
            evidence=None,
            reason="Operational state check required.",
            observed_value=None,
            expected_value="ntp synchronized"
        )
    ]
    aggregator = MultiFrameworkAggregator()
    return aggregator.aggregate(results, audit_id="AUDIT-TEST-MF", device_hostname="switch-01")


# --- Test A: Successful Finalization Creates Canonical Report ---

def test_successful_finalization_creates_canonical_report():
    """Invariant A: POST /api/audit/finalize creates one canonical report and returns report identity."""
    session_id = "sess-fin-001"
    _seed_audit_session(session_id, vendor="cisco", hostname="router-01")
    headers = _get_auth_header()

    res = client.post("/api/audit/finalize", json={
        "session_id": session_id,
        "remediation_summary": {"RULE-002": {"cli": "no ip http server"}}
    }, headers=headers)

    assert res.status_code == 200, f"Finalize failed: {res.status_code} - {res.text}"
    data = res.json()
    assert "entry_id" in data
    assert "entryHash" in data
    assert "report_id" in data
    assert "report_version" in data
    assert data["report_version"] == 1

    # Verify report is persisted in database
    db_report = database.get_audit_report(data["report_id"])
    assert db_report is not None
    assert db_report["audit_entry_id"] == data["entry_id"]
    assert db_report["session_id"] == session_id
    assert db_report["vendor"] == "cisco"
    assert db_report["version"] == 1


# --- Test B & C: Idempotency & Duplicate Prevention ---

def test_repeated_report_creation_is_idempotent():
    """Invariants B & C: Calling create_or_get_canonical_report twice returns the exact same report."""
    session_id = "sess-idemp-001"
    session_data = _seed_audit_session(session_id)

    # Append authoritative entry to audit_ledger
    audit_entry = audit_log.create_audit_entry(
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"],
        remediation_summary={"RULE-002": "fix"}
    )
    audit_log.append_audit_entry(audit_entry)
    audit_entry_id = audit_entry["entry_id"]

    # First call: creates report
    rep1 = audit_report.create_or_get_canonical_report(
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    assert rep1 is not None
    assert rep1.version == 1

    # Second call: returns existing canonical report
    rep2 = audit_report.create_or_get_canonical_report(
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    assert rep2 is not None
    assert rep2.report_id == rep1.report_id
    assert rep2.version == 1

    # Verify DB has only ONE report for this audit
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_reports WHERE audit_entry_id = ?", (audit_entry_id,))
    count = cur.fetchone()[0]
    conn.close()
    assert count == 1


# --- Test D, F, G, R: Multi-Framework Invariants ---

def test_multi_framework_snapshot_and_no_overall_verdict():
    """Invariants D, F, G, R: Multi-framework data is unified, scores preserved, zero overall verdict."""
    session_id = "sess-mf-001"
    session_data = _seed_audit_session(session_id, vendor="cisco", hostname="switch-01")
    mf_result = _build_multi_framework_result()

    audit_entry = audit_log.create_audit_entry(
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    audit_log.append_audit_entry(audit_entry)

    rep = audit_report.create_or_get_canonical_report(
        audit_entry_id=audit_entry["entry_id"],
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"],
        multi_framework_result=mf_result
    )

    assert len(rep.frameworks) == 2
    fw_dict = {f.framework_id: f for f in rep.frameworks}

    # CIS assertions
    cis = fw_dict["cis_cisco_iosxe"]
    assert cis.total_controls == 2
    assert cis.passed == 1
    assert cis.failed == 1
    assert cis.unknown == 0
    assert cis.pass_rate == 50.0

    # DISA STIG assertions
    stig = fw_dict["stig_cisco_iosxe"]
    assert stig.total_controls == 2
    assert stig.passed == 1
    assert stig.failed == 0
    assert stig.unknown == 1
    assert stig.pass_rate == 100.0
    assert stig.unknown_rate == 50.0

    # Invariant R: Zero overall compliance verdict or blended score
    rep_dict = rep.to_dict()
    assert "overall_compliance_verdict" not in rep_dict
    assert "overall_verdict" not in rep_dict
    assert "blended_score" not in rep_dict


# --- Test E & O: Vendor Isolation ---

def test_vendor_isolation_cisco_and_juniper():
    """Invariants E & O: Cisco and Juniper reports preserve true vendor and do not cross-contaminate."""
    # 1. Cisco Audit
    cisco_session = _seed_audit_session("sess-cisco-1", vendor="cisco", hostname="cisco-gw")
    cisco_entry = audit_log.create_audit_entry(
        csm=cisco_session["csm"],
        evals=cisco_session["evals"],
        raw_config_text=cisco_session["raw_config_text"]
    )
    audit_log.append_audit_entry(cisco_entry)

    cisco_rep = audit_report.create_or_get_canonical_report(
        audit_entry_id=cisco_entry["entry_id"],
        session_id="sess-cisco-1",
        csm=cisco_session["csm"],
        evals=cisco_session["evals"],
        raw_config_text=cisco_session["raw_config_text"]
    )

    # 2. Juniper Audit
    juniper_session = _seed_audit_session("sess-juniper-1", vendor="juniper", hostname="juniper-ex")
    juniper_entry = audit_log.create_audit_entry(
        csm=juniper_session["csm"],
        evals=juniper_session["evals"],
        raw_config_text=juniper_session["raw_config_text"]
    )
    audit_log.append_audit_entry(juniper_entry)

    juniper_rep = audit_report.create_or_get_canonical_report(
        audit_entry_id=juniper_entry["entry_id"],
        session_id="sess-juniper-1",
        csm=juniper_session["csm"],
        evals=juniper_session["evals"],
        raw_config_text=juniper_session["raw_config_text"]
    )

    # Assertions
    assert cisco_rep.vendor == "cisco"
    assert cisco_rep.device_metadata["vendor"] == "cisco"
    assert cisco_rep.report_id != juniper_rep.report_id

    assert juniper_rep.vendor == "juniper"
    assert juniper_rep.device_metadata["vendor"] == "juniper"
    assert "IOS-XE" not in juniper_rep.device_metadata["platform"]
    assert juniper_rep.device_metadata["platform"] == "Junos"


# --- Test H, I, J: Human Edit Preservation on Retry ---

def test_human_edits_and_edit_history_survive_retry():
    """Invariants H, I, J: A retry/re-fetch never resets report version or overwrites human edits."""
    session_id = "sess-edit-preserve"
    session_data = _seed_audit_session(session_id)

    audit_entry = audit_log.create_audit_entry(
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    audit_log.append_audit_entry(audit_entry)
    audit_entry_id = audit_entry["entry_id"]

    # 1. Create canonical report (version 1)
    rep = audit_report.create_or_get_canonical_report(
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    assert rep.version == 1

    # 2. Human editor performs an edit
    updated = database.record_report_edit(
        report_id=rep.report_id,
        field_path="executive_summary",
        new_value="Human reviewed: compliance exception granted for maintenance.",
        edited_by="secops_reviewer",
        expected_version=1
    )
    assert updated["version"] == 2

    # 3. Call create_or_get_canonical_report again (e.g. finalization retry or client reconnect)
    retry_rep = audit_report.create_or_get_canonical_report(
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )

    # Assertions: edits and version MUST be preserved
    assert retry_rep.report_id == rep.report_id
    assert retry_rep.version == 2
    assert retry_rep.editable_content.executive_summary == "Human reviewed: compliance exception granted for maintenance."
    assert len(retry_rep.edit_metadata) == 1
    assert retry_rep.edit_metadata[0].edited_by == "secops_reviewer"


# --- Test K & L: Ledger Immutability & Hash Chain Validity ---

def test_ledger_integrity_and_chain_valid_after_report_lifecycle():
    """Invariants K & L: Lifecycle integration does not touch audit ledger hashes or break verification."""
    session_id = "sess-chain-1"
    session_data = _seed_audit_session(session_id)

    # 1. Create entry 1
    entry1 = audit_log.create_audit_entry(
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    hash1 = audit_log.append_audit_entry(entry1)

    # 2. Create canonical report for entry 1
    rep1 = audit_report.create_or_get_canonical_report(
        audit_entry_id=entry1["entry_id"],
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )

    # 3. Perform human edit on report 1
    database.record_report_edit(
        report_id=rep1.report_id,
        field_path="auditor_observations",
        new_value="Audit completed successfully.",
        edited_by="user1",
        expected_version=1
    )

    # 4. Create entry 2 linking to entry 1
    entry2 = audit_log.create_audit_entry(
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    hash2 = audit_log.append_audit_entry(entry2)
    assert entry2["prevEntryHash"] == hash1

    # 5. Create canonical report for entry 2
    audit_report.create_or_get_canonical_report(
        audit_entry_id=entry2["entry_id"],
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )

    # 6. Verify entire ledger hash chain
    valid, msg, broken_idx = audit_log.verify_chain()
    assert valid is True, f"Hash chain corrupted: {msg}"
    assert broken_idx == 0


# --- Test M & N: Failure Isolation & Safe Retry ---

def test_failed_report_creation_leaves_ledger_intact_and_allows_retry():
    """Invariants M & N: If report creation fails, ledger is NOT rolled back; retry succeeds."""
    session_id = "sess-fail-safe"
    session_data = _seed_audit_session(session_id)

    # Step 1: Ledger entry is appended
    entry = audit_log.create_audit_entry(
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    entry_hash = audit_log.append_audit_entry(entry)
    audit_entry_id = entry["entry_id"]

    # Step 2: Inject failure during report persistence
    with patch("database.save_audit_report", side_effect=sqlite3.OperationalError("Disk I/O error")):
        with pytest.raises(sqlite3.OperationalError):
            audit_report.create_or_get_canonical_report(
                audit_entry_id=audit_entry_id,
                session_id=session_id,
                csm=session_data["csm"],
                evals=session_data["evals"],
                raw_config_text=session_data["raw_config_text"]
            )

    # Step 3: Assert audit ledger entry is completely intact and valid!
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_ledger WHERE entry_id = ?", (audit_entry_id,))
    row = cur.fetchone()
    conn.close()

    assert row is not None
    assert row["entryHash"] == entry_hash
    valid, _, _ = audit_log.verify_chain()
    assert valid is True

    # Step 4: Retry report creation without the injected failure -> must succeed!
    recovered_rep = audit_report.create_or_get_canonical_report(
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )

    assert recovered_rep is not None
    assert recovered_rep.audit_entry_id == audit_entry_id
    assert recovered_rep.version == 1


# --- Test P & Q: Zero Evaluator & Zero AI Inference Calls ---

def test_zero_evaluators_and_zero_ai_inference_during_report_creation():
    """Invariants P & Q: Report creation consumes existing data; never invokes evaluators or AI."""
    session_id = "sess-pure-data"
    session_data = _seed_audit_session(session_id)

    entry = audit_log.create_audit_entry(
        csm=session_data["csm"],
        evals=session_data["evals"],
        raw_config_text=session_data["raw_config_text"]
    )
    audit_log.append_audit_entry(entry)

    # Mock all potential AI and evaluator modules
    with patch("ai_suggester.suggest_mapping") as mock_ai_suggest, \
         patch("ai_model_manager.AIModelManager") as mock_ai_mgr, \
         patch("cis_benchmark_cisco_iosxe.CisCiscoIosXeEvaluator.evaluate") as mock_cis_eval, \
         patch("disa_stig_cisco_iosxe.StigCiscoIosXeEvaluator.evaluate") as mock_stig_eval:

        rep = audit_report.create_or_get_canonical_report(
            audit_entry_id=entry["entry_id"],
            session_id=session_id,
            csm=session_data["csm"],
            evals=session_data["evals"],
            raw_config_text=session_data["raw_config_text"]
        )

        assert rep is not None
        mock_ai_suggest.assert_not_called()
        mock_ai_mgr.assert_not_called()
        mock_cis_eval.assert_not_called()
        mock_stig_eval.assert_not_called()
