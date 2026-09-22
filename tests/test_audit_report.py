"""NTRO PS26155 — Unified Canonical Audit Report Domain & Persistence Tests (Phase 3D.2).

Verifies all core invariants for the canonical editable AuditReport model:
A. One audit creates one canonical report identity.
B. Multiple frameworks exist inside the same report.
C. Framework results preserve their authoritative values.
D. PASS/FAIL/UNKNOWN remain unchanged.
E. Backend pass_rate is preserved exactly.
F. System-generated fields cannot be modified through editable-content operations.
G. Human-editable fields can be persisted.
H. Manual edit records editor identity and timestamp.
I. Previous value is preserved in edit history.
J. Report version increments correctly.
K. Multiple edits preserve history.
L. Original audit ledger entry remains unchanged.
M. Cross-report isolation works.
N. Unauthorized field paths are rejected (fail closed).
O. AI/trusted mapping provenance remains system-controlled.
P. Report survives serialization/deserialization without losing framework/evidence identity.
Q. SQLite foreign-key enforcement rejects invalid relationships (Mandatory Adjustment 1).
R. system_snapshot immutability across multiple edits and chain verification (Mandatory Adjustment 2).
S. Stale version / optimistic concurrency protection rejects stale edits (Mandatory Adjustment 3).
"""

import datetime
import hashlib
import json
import os
import pathlib
import sqlite3
import pytest

import database
import audit_log
import audit_report
from compliance_framework import ComplianceStatus, EvaluationResult, Evidence
from compliance_aggregator import MultiFrameworkAggregator


@pytest.fixture(autouse=True)
def clean_db(tmp_path):
    """Initializes a fresh isolated database for each test."""
    test_db = tmp_path / "test_auditor_report.db"
    orig_db_path = database.DB_PATH
    database.DB_PATH = test_db
    database.initialize_database()
    yield test_db
    database.DB_PATH = orig_db_path


def _create_sample_audit_ledger_entry(entry_id: str = "AUDIT-TEST-0001", hostname: str = "core-router-01"):
    """Helper to seed an authoritative audit record in audit_ledger."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO audit_ledger
        (entry_id, timestamp, device_hostname, config_file_hash, audit_results, remediation_summary, prevEntryHash, entryHash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        entry_id,
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        hostname,
        "hash-12345",
        json.dumps({"CIS-1.1": "Pass", "CIS-1.2": "Fail"}),
        json.dumps({"CIS-1.2": {"cli": "no ip http server"}}),
        "0" * 64,
        "entry-hash-abcde"
    ))
    conn.commit()
    conn.close()
    return entry_id


def _create_sample_multi_framework_result():
    """Helper to generate a MultiFrameworkAuditResult with CIS and DISA-STIG."""
    results = [
        EvaluationResult(
            framework_id="cis_cisco_iosxe",
            control_id="1.1.1",
            status=ComplianceStatus.PASS,
            evidence=Evidence(
                observed_value="service password-encryption",
                location="csm.services",
                expected_value="service password-encryption",
                rationale="Password encryption service is enabled.",
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
                rationale="MOTD login banner is not configured.",
                confidence=1.0,
                source_lines=()
            )
        ),
        EvaluationResult(
            framework_id="cis_cisco_iosxe",
            control_id="1.1.3",
            status=ComplianceStatus.UNKNOWN,
            evidence=None,
            reason="Control requires operational state verification.",
            observed_value=None,
            expected_value="ntp server synchronized"
        ),
        EvaluationResult(
            framework_id="stig_cisco_iosxe",
            control_id="V-215001",
            status=ComplianceStatus.PASS,
            evidence=Evidence(
                observed_value="transport input ssh",
                location="csm.lines",
                expected_value="transport input ssh",
                rationale="Telnet is disabled on VTY lines.",
                confidence=1.0,
                source_lines=("transport input ssh",)
            )
        ),
        EvaluationResult(
            framework_id="stig_cisco_iosxe",
            control_id="V-215002",
            status=ComplianceStatus.FAIL,
            evidence=Evidence(
                observed_value="snmp-server community public RO",
                location="csm.snmp",
                expected_value="SNMPv3 required",
                rationale="Insecure default community string present.",
                confidence=1.0,
                source_lines=("snmp-server community public RO",)
            )
        )
    ]
    aggregator = MultiFrameworkAggregator()
    return aggregator.aggregate(results, audit_id="AUDIT-TEST-0001", device_hostname="core-router-01")


# --- Test A & Q: One Audit = One Canonical Report & Foreign Key Enforcement ---

def test_foreign_key_rejection_for_nonexistent_audit():
    """Mandatory Adjustment 1: Prove SQLite foreign keys reject reports referencing nonexistent audits."""
    report = audit_report.create_report_from_audit_data(
        audit_entry_id="AUDIT-NONEXISTENT-9999",
        session_id="sess-001",
        vendor="cisco",
        device_metadata={"hostname": "r1"},
        configuration_metadata={"config_file_hash": "abc"}
    )
    with pytest.raises(sqlite3.IntegrityError):
        database.save_audit_report(report)


def test_foreign_key_rejection_for_nonexistent_report_edit():
    """Mandatory Adjustment 1: Prove SQLite foreign keys reject edits referencing nonexistent reports."""
    conn = database.get_connection()
    cur = conn.cursor()
    with pytest.raises(sqlite3.IntegrityError):
        cur.execute('''
            INSERT INTO audit_report_edits
            (edit_id, report_id, version, field_path, previous_value, new_value, edited_by, edited_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ("edit-1", "NONEXISTENT-REPORT", 1, "executive_summary", "old", "new", "user1", "2026-01-01T00:00:00Z"))
        conn.commit()
    conn.close()


def test_one_audit_creates_one_canonical_report():
    """Invariant A: Exactly ONE canonical report identity per audit record."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-CANONICAL-1")

    rep1 = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-1",
        vendor="cisco",
        device_metadata={"hostname": "r1"},
        configuration_metadata={"config_file_hash": "abc123"}
    )
    database.save_audit_report(rep1)

    fetched = database.get_audit_report(rep1.report_id)
    assert fetched is not None
    assert fetched["report_id"] == rep1.report_id
    assert fetched["audit_entry_id"] == audit_id

    # Attempting to save a second report for the same audit must be rejected
    rep2 = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-2",
        vendor="cisco",
        device_metadata={"hostname": "r1"},
        configuration_metadata={"config_file_hash": "abc123"}
    )
    with pytest.raises(audit_report.DuplicateReportError):
        database.save_audit_report(rep2)


# --- Test B, C, D, E: Multi-Framework Representation & Invariants ---

def test_multi_framework_representation_and_verdict_preservation():
    """Invariants B, C, D, E: Multiple frameworks exist inside report; verdicts and pass rates preserved."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-MF-1")
    mf_result = _create_sample_multi_framework_result()

    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-mf",
        vendor="cisco",
        device_metadata={"hostname": "core-router-01"},
        configuration_metadata={"config_file_hash": "cfghash99"},
        multi_framework_result=mf_result
    )
    database.save_audit_report(rep)

    loaded = database.get_audit_report(rep.report_id)
    frameworks = loaded["frameworks"]
    assert len(frameworks) == 2

    fw_map = {f["framework_id"]: f for f in frameworks}
    assert "cis_cisco_iosxe" in fw_map
    assert "stig_cisco_iosxe" in fw_map

    # CIS assertions
    cis = fw_map["cis_cisco_iosxe"]
    assert cis["total_controls"] == 3
    assert cis["passed"] == 1
    assert cis["failed"] == 1
    assert cis["unknown"] == 1
    # Pass rate: 1 pass / (1 pass + 1 fail) = 50.0%
    assert cis["pass_rate"] == 50.0
    assert cis["unknown_rate"] == round((1 / 3) * 100.0, 2)

    # DISA-STIG assertions
    stig = fw_map["stig_cisco_iosxe"]
    assert stig["total_controls"] == 2
    assert stig["passed"] == 1
    assert stig["failed"] == 1
    assert stig["unknown"] == 0
    assert stig["pass_rate"] == 50.0

    # Verify exact control results and evidence preserved
    cis_controls = {c["control_id"]: c for c in cis["control_results"]}
    assert cis_controls["1.1.1"]["status"] == "Pass"
    assert cis_controls["1.1.2"]["status"] == "Fail"
    assert cis_controls["1.1.3"]["status"] == "Unknown"

    stig_controls = {c["control_id"]: c for c in stig["control_results"]}
    assert stig_controls["V-215001"]["status"] == "Pass"
    assert stig_controls["V-215002"]["status"] == "Fail"


# --- Test F, N: Security & Allowlist Enforcement ---

def test_system_generated_fields_cannot_be_modified():
    """Invariant F: System-generated fields reject edit operations with SystemFieldImmutableError."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-SEC-1")
    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-sec",
        vendor="cisco"
    )
    database.save_audit_report(rep)

    forbidden_targets = [
        "compliance.status",
        "status",
        "pass_rate",
        "frameworks",
        "evidence",
        "audit_entry_id",
        "system_snapshot",
        "entryHash",
        "device_metadata"
    ]

    for target in forbidden_targets:
        with pytest.raises(audit_report.SystemFieldImmutableError):
            database.record_report_edit(
                report_id=rep.report_id,
                field_path=target,
                new_value="tampered_value",
                edited_by="malicious_actor",
                expected_version=1
            )


def test_unauthorized_field_paths_rejected_fail_closed():
    """Invariant N: Arbitrary field paths not in allowlist are rejected fail-closed."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-SEC-2")
    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-sec2",
        vendor="cisco"
    )
    database.save_audit_report(rep)

    invalid_paths = [
        "random_field",
        "admin_notes",
        "executive_summary.nested",
        "__proto__",
        "constructor",
        "",
        "   "
    ]

    for path in invalid_paths:
        with pytest.raises(audit_report.InvalidFieldPathError):
            database.record_report_edit(
                report_id=rep.report_id,
                field_path=path,
                new_value="injected",
                edited_by="user1",
                expected_version=1
            )


# --- Test G, H, I, J, K: Human-Editable Content, Edit Provenance & Versioning ---

def test_human_editable_persistence_and_provenance():
    """Invariants G, H, I, J, K: Human edits succeed, increment version, and record full provenance."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-PROV-1")
    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-prov",
        vendor="cisco"
    )
    database.save_audit_report(rep)
    assert rep.version == 1

    # Edit 1: Update executive summary
    updated1 = database.record_report_edit(
        report_id=rep.report_id,
        field_path="executive_summary",
        new_value="Audit completed with 2 findings requiring remediation.",
        edited_by="auditor_jane",
        expected_version=1
    )
    assert updated1["version"] == 2
    assert updated1["editable_content"]["executive_summary"] == "Audit completed with 2 findings requiring remediation."

    # Edit 2: Add control note
    updated2 = database.record_report_edit(
        report_id=rep.report_id,
        field_path="control_notes.CIS-1.1.2",
        new_value="Banner missing due to recent migration maintenance window.",
        edited_by="secops_reviewer",
        expected_version=2
    )
    assert updated2["version"] == 3
    assert updated2["editable_content"]["control_notes"]["CIS-1.1.2"] == "Banner missing due to recent migration maintenance window."

    # Edit 3: Update executive summary again to check previous_value retention
    updated3 = database.record_report_edit(
        report_id=rep.report_id,
        field_path="executive_summary",
        new_value="Final approved executive summary.",
        edited_by="secops_reviewer",
        expected_version=3
    )
    assert updated3["version"] == 4
    assert updated3["editable_content"]["executive_summary"] == "Final approved executive summary."

    # Check edit history provenance
    edits = database.list_report_edits(rep.report_id)
    assert len(edits) == 3

    assert edits[0]["version"] == 2
    assert edits[0]["field_path"] == "executive_summary"
    assert edits[0]["previous_value"] == ""
    assert edits[0]["new_value"] == "Audit completed with 2 findings requiring remediation."
    assert edits[0]["edited_by"] == "auditor_jane"
    assert edits[0]["edited_at"] is not None

    assert edits[1]["version"] == 3
    assert edits[1]["field_path"] == "control_notes.CIS-1.1.2"
    assert edits[1]["previous_value"] is None
    assert edits[1]["new_value"] == "Banner missing due to recent migration maintenance window."
    assert edits[1]["edited_by"] == "secops_reviewer"

    assert edits[2]["version"] == 4
    assert edits[2]["field_path"] == "executive_summary"
    assert edits[2]["previous_value"] == "Audit completed with 2 findings requiring remediation."
    assert edits[2]["new_value"] == "Final approved executive summary."
    assert edits[2]["edited_by"] == "secops_reviewer"


# --- Test L & R: Mandatory Adjustment 2: System Snapshot & Ledger Integrity ---

def test_system_snapshot_and_audit_ledger_remain_untouched_after_edits():
    """Mandatory Adjustment 2 & Invariant L: Edits never mutate system_snapshot or audit_ledger."""
    raw_config = "hostname core-switch\nservice password-encryption\n"
    csm = {"device": {"hostname": "core-switch"}}
    evals = {"RULE-1": {"status": "Pass"}}

    # Create real hash-chained entry in audit_ledger
    audit_entry = audit_log.create_audit_entry(
        csm=csm,
        evals=evals,
        raw_config_text=raw_config,
        remediation_summary={"RULE-1": "none"}
    )
    initial_entry_hash = audit_log.append_audit_entry(audit_entry)
    audit_id = audit_entry["entry_id"]

    # Verify chain before report creation
    valid, _, _ = audit_log.verify_chain()
    assert valid is True

    # Create and persist canonical report
    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-chain-1",
        vendor="cisco",
        device_metadata={"hostname": "core-switch"},
        configuration_metadata={"config_file_hash": hashlib.sha256(raw_config.encode("utf-8")).hexdigest()},
        evals=evals
    )
    database.save_audit_report(rep)

    initial_report = database.get_audit_report(rep.report_id)
    initial_snapshot = json.dumps(initial_report["frameworks"], sort_keys=True)

    # Perform multiple successive edits
    for i in range(1, 4):
        database.record_report_edit(
            report_id=rep.report_id,
            field_path="auditor_observations",
            new_value=f"Observation update #{i}",
            edited_by=f"editor_{i}",
            expected_version=i
        )

    # Verify report state
    final_report = database.get_audit_report(rep.report_id)
    assert final_report["version"] == 4
    final_snapshot = json.dumps(final_report["frameworks"], sort_keys=True)

    # 1. system_snapshot is unchanged
    assert initial_snapshot == final_snapshot

    # 2 & 3. audit_ledger entry and entryHash are unchanged
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_ledger WHERE entry_id = ?", (audit_id,))
    ledger_row = cur.fetchone()
    conn.close()

    assert ledger_row["entryHash"] == initial_entry_hash

    # 4. Hash chain verification still passes
    chain_valid, chain_msg, _ = audit_log.verify_chain()
    assert chain_valid is True, f"Audit hash chain broken after report edit: {chain_msg}"


# --- Test S: Mandatory Adjustment 3: Stale Version / Concurrency Protection ---

def test_stale_version_protection_rejects_concurrent_edits():
    """Mandatory Adjustment 3: Optimistic concurrency rejects stale edits cleanly."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-CONCUR-1")
    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="session-concur",
        vendor="cisco"
    )
    database.save_audit_report(rep)
    assert rep.version == 1

    # Both Editor A and Editor B read version 1
    # Editor A saves edit based on version 1 -> succeeds, version becomes 2
    database.record_report_edit(
        report_id=rep.report_id,
        field_path="executive_summary",
        new_value="Editor A changes summary.",
        edited_by="editor_a",
        expected_version=1
    )

    # Editor B attempts to save based on stale version 1 -> must be rejected
    with pytest.raises(audit_report.StaleReportVersionError) as exc_info:
        database.record_report_edit(
            report_id=rep.report_id,
            field_path="executive_summary",
            new_value="Editor B overwrites summary.",
            edited_by="editor_b",
            expected_version=1
        )
    assert "Stale report edit rejected" in str(exc_info.value)

    # Verify that Editor B's edit was NOT recorded, and report remains version 2
    current_report = database.get_audit_report(rep.report_id)
    assert current_report["version"] == 2
    assert current_report["editable_content"]["executive_summary"] == "Editor A changes summary."

    edits = database.list_report_edits(rep.report_id)
    assert len(edits) == 1
    assert edits[0]["edited_by"] == "editor_a"


# --- Test M: Cross-Report Isolation ---

def test_cross_report_isolation():
    """Invariant M: Edits to Report 1 do not leak into or affect Report 2."""
    id1 = _create_sample_audit_ledger_entry("AUDIT-ISO-1", "host-1")
    id2 = _create_sample_audit_ledger_entry("AUDIT-ISO-2", "host-2")

    rep1 = audit_report.create_report_from_audit_data(
        audit_entry_id=id1,
        session_id="sess-1",
        vendor="cisco",
        device_metadata={"hostname": "host-1"}
    )
    database.save_audit_report(rep1)

    rep2 = audit_report.create_report_from_audit_data(
        audit_entry_id=id2,
        session_id="sess-2",
        vendor="juniper",
        device_metadata={"hostname": "host-2"}
    )
    database.save_audit_report(rep2)

    # Edit Report 1
    database.record_report_edit(
        report_id=rep1.report_id,
        field_path="executive_summary",
        new_value="Summary for host 1 only.",
        edited_by="user1",
        expected_version=1
    )

    # Verify Report 2 is untouched
    rep2_fetched = database.get_audit_report(rep2.report_id)
    assert rep2_fetched["version"] == 1
    assert rep2_fetched["editable_content"]["executive_summary"] == ""
    assert len(database.list_report_edits(rep2.report_id)) == 0


# --- Test O: AI / Trusted Mapping Provenance Preservation ---

def test_ai_mapping_provenance_preservation():
    """Invariant O: AI suggestion and human approval provenance are preserved and immutable."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-AI-PROV-1")
    provenance = [
        {
            "suggestion_id": "sug-1234",
            "unmapped_line": "set system root-authentication encrypted-password xyz",
            "vendor": "juniper",
            "model_used": "distilbert-base-uncased",
            "confidence": 0.94,
            "status": "approved",
            "reviewed_by": "secops_reviewer",
            "reviewed_at": "2026-09-21T20:00:00Z",
            "suggested_rule": "JUNOS-001"
        }
    ]

    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="sess-ai",
        vendor="juniper",
        ai_mapping_provenance=provenance
    )
    database.save_audit_report(rep)

    loaded = database.get_audit_report(rep.report_id)
    assert loaded["ai_mapping_provenance"] == provenance

    # Ensure edits cannot mutate ai_mapping_provenance
    with pytest.raises(audit_report.SystemFieldImmutableError):
        database.record_report_edit(
            report_id=rep.report_id,
            field_path="ai_mapping_provenance",
            new_value=[],
            edited_by="attacker",
            expected_version=1
        )


# --- Test P: Serialization & Deserialization Round-Trip ---

def test_serialization_round_trip():
    """Invariant P: AuditReport survives JSON serialization and deserialization without data loss."""
    audit_id = _create_sample_audit_ledger_entry("AUDIT-SER-1")
    mf_result = _create_sample_multi_framework_result()

    initial_content = audit_report.HumanEditableContent(
        executive_summary="Preliminary audit review.",
        control_notes={"1.1.1": "Approved exception"},
        recommendations="Implement 802.1X"
    )

    rep = audit_report.create_report_from_audit_data(
        audit_entry_id=audit_id,
        session_id="sess-ser",
        vendor="cisco",
        device_metadata={"hostname": "r1", "platform": "Cisco IOS-XE"},
        configuration_metadata={"config_file_hash": "abcdef12345"},
        multi_framework_result=mf_result,
        initial_editable_content=initial_content
    )

    json_str = rep.to_json()
    reconstituted = audit_report.AuditReport.from_json(json_str)

    assert reconstituted.report_id == rep.report_id
    assert reconstituted.audit_entry_id == rep.audit_entry_id
    assert reconstituted.session_id == rep.session_id
    assert reconstituted.vendor == rep.vendor
    assert reconstituted.version == rep.version
    assert len(reconstituted.frameworks) == len(rep.frameworks)

    for orig_fw, recon_fw in zip(rep.frameworks, reconstituted.frameworks):
        assert orig_fw.framework_id == recon_fw.framework_id
        assert orig_fw.pass_rate == recon_fw.pass_rate
        assert orig_fw.passed == recon_fw.passed
        assert orig_fw.failed == recon_fw.failed
        assert orig_fw.unknown == recon_fw.unknown
        assert len(orig_fw.control_results) == len(recon_fw.control_results)

    assert reconstituted.editable_content.executive_summary == "Preliminary audit review."
    assert reconstituted.editable_content.control_notes["1.1.1"] == "Approved exception"
    assert reconstituted.editable_content.recommendations == "Implement 802.1X"
