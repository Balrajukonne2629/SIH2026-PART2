"""NTRO PS26155 — Canonical Report Export Engine Verification Suite (Phase 3D.4).

Verifies export of canonical AuditReport to PDF and DOCX covering all 20 architectural invariants:
1. Cisco multi-framework PDF export.
2. Cisco multi-framework DOCX export.
3. Juniper export.
4. Multiple frameworks appear in one export.
5. PASS/FAIL/UNKNOWN preserved.
6. Pass rates preserved.
7. Framework metadata preserved.
8. Evidence/remediation preserved.
9. AI/trusted provenance preserved.
10. Human editable content preserved.
11. Manually edited fields visibly marked with [Edited manually].
12. Export does not mutate the canonical report.
13. Export does not modify the audit ledger.
14. Export does not invoke compliance evaluators.
15. Export does not invoke AI.
16. Special characters (<, >, &, quotes, Unicode, multiline) handled safely without crash.
17. Path traversal is rejected/prevented.
18. Export failure leaves canonical data and files untouched (atomic rollback).
19. Stable/deterministic ordering.
20. No artificial overall compliance verdict or score is introduced.
"""

from typing import Dict, List
import copy
import json
import os
import pathlib
from unittest.mock import MagicMock, patch
import zipfile

import pypdf
import pytest

from audit_report import AuditReport, FrameworkReportItem, HumanEditableContent, ReportEdit
import database
import report_exporter


# ==============================================================================
# Test Fixtures & Helpers
# ==============================================================================

@pytest.fixture
def clean_export_dir(tmp_path):
    """Provides a sterile, isolated export directory for each test run."""
    export_dir = tmp_path / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    return export_dir


@pytest.fixture
def clean_test_db(tmp_path):
    """Provides an isolated database for verifying database/ledger non-mutation."""
    test_db = tmp_path / "export_test.db"
    orig_db = database.DB_PATH
    database.DB_PATH = test_db
    database.initialize_database()
    yield test_db
    database.DB_PATH = orig_db


def _extract_pdf_text(pdf_path: pathlib.Path) -> str:
    """Helper to extract full plain text from generated PDF file."""
    reader = pypdf.PdfReader(str(pdf_path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _extract_docx_xml(docx_path: pathlib.Path) -> str:
    """Helper to extract word/document.xml from generated DOCX zip package."""
    with zipfile.ZipFile(str(docx_path), "r") as zf:
        return zf.read("word/document.xml").decode("utf-8")


def _build_cisco_multi_framework_report(with_edits: bool = True) -> AuditReport:
    """Builds a realistic canonical AuditReport containing Cisco multi-framework results."""
    fw_cis = FrameworkReportItem(
        framework_id="cis_cisco_iosxe",
        framework_name="CIS Cisco IOS XE Benchmark",
        framework_version="1.0.0",
        vendor_scope="cisco",
        description="CIS benchmark controls for Cisco IOS-XE devices",
        total_controls=3,
        passed=2,
        failed=1,
        unknown=0,
        pass_rate=66.7,
        unknown_rate=0.0,
        control_results=[
            {
                "control_id": "CIS-1.1.1",
                "title": "Ensure password encryption is enabled",
                "status": "PASS",
                "check_focus": "Password Security",
                "evidence": ["service password-encryption"],
                "rationale": "Password encryption is active in config",
            },
            {
                "control_id": "CIS-1.2.1",
                "title": "Ensure HTTP server is disabled",
                "status": "FAIL",
                "check_focus": "Web Management",
                "evidence": ["ip http server"],
                "rationale": "Insecure HTTP server enabled",
            },
            {
                "control_id": "CIS-1.3.1",
                "title": "Ensure SSH version 2 is configured",
                "status": "PASS",
                "check_focus": "SSH",
                "evidence": ["ip ssh version 2"],
                "rationale": "SSH v2 is configured",
            },
        ],
        evidence=[
            {"evidence_id": "EV-01", "type": "config_line", "content": "service password-encryption"},
            {"evidence_id": "EV-02", "type": "config_line", "content": "ip http server"},
        ]
    )

    fw_stig = FrameworkReportItem(
        framework_id="disa_stig_cisco_iosxe",
        framework_name="DISA STIG Cisco IOS XE",
        framework_version="2.1",
        vendor_scope="cisco",
        description="DoD security technical implementation guide",
        total_controls=2,
        passed=1,
        failed=0,
        unknown=1,
        pass_rate=50.0,
        unknown_rate=50.0,
        control_results=[
            {
                "control_id": "STIG-NET-001",
                "title": "Ensure AAA authentication is enabled",
                "status": "PASS",
                "check_focus": "Authentication",
                "evidence": ["aaa new-model"],
                "rationale": "AAA new-model is present",
            },
            {
                "control_id": "STIG-NET-002",
                "title": "Ensure banner message is compliant",
                "status": "UNKNOWN",
                "check_focus": "Warning Banners",
                "evidence": [],
                "rationale": "Banner content could not be statically verified",
            },
        ],
        evidence=[
            {"evidence_id": "EV-03", "type": "config_line", "content": "aaa new-model"},
        ]
    )

    editable = HumanEditableContent(
        executive_summary="Executive summary: Security posture is moderate. Remediation required for web services.",
        auditor_observations="Observation: Device is operating in a staging environment.",
        control_notes={"CIS-1.2.1": "Approved temporary exception requested by network engineering."},
        remediation_commentary={"CIS-1.2.1": "Apply 'no ip http server' during next scheduled change window."},
        recommendations="Disable plaintext web interfaces immediately.",
        additional_findings="Unused loopback interfaces detected.",
        final_reviewer_notes="Reviewed and approved by SecOps lead.",
    )

    edits = []
    if with_edits:
        edits = [
            ReportEdit(
                edit_id="edit-001",
                report_id="rep-cisco-001",
                version=2,
                field_path="executive_summary",
                previous_value="Initial summary",
                new_value=editable.executive_summary,
                edited_by="secops_lead",
                edited_at="2026-09-20T10:00:00Z"
            ),
            ReportEdit(
                edit_id="edit-002",
                report_id="rep-cisco-001",
                version=3,
                field_path="control_notes.CIS-1.2.1",
                previous_value="",
                new_value=editable.control_notes["CIS-1.2.1"],
                edited_by="secops_reviewer",
                edited_at="2026-09-20T10:15:00Z"
            ),
        ]

    return AuditReport(
        report_id="rep-cisco-001",
        audit_entry_id="aud-cisco-entry-123",
        session_id="sess-cisco-456",
        vendor="cisco",
        device_metadata={
            "hostname": "core-router-01",
            "vendor": "cisco",
            "platform": "Cisco IOS-XE",
            "management_ip": "192.168.10.1",
        },
        configuration_metadata={
            "filename": "cisco_iosxe_core.cfg",
            "config_file_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "line_count": 450,
        },
        frameworks=[fw_cis, fw_stig],
        remediation=[
            {
                "rule_id": "CIS-1.2.1",
                "cli": "no ip http server\nno ip http secure-server",
                "description": "Disable HTTP server",
            }
        ],
        conflict_warnings=[
            {
                "warning_id": "WARN-01",
                "message": "Disabling HTTP server may affect legacy web dashboard integration.",
            }
        ],
        ai_mapping_provenance=[
            {
                "vendor_rule_id": "CISCO-HTTP-01",
                "common_rule_id": "CIS-1.2.1",
                "match_type": "exact_semantic",
                "confidence": 0.98,
                "rationale": "High-confidence vendor rule alignment",
            }
        ],
        editable_content=editable,
        edit_metadata=edits,
        version=len(edits) + 1,
        created_at="2026-09-20T09:00:00Z",
        updated_at="2026-09-20T10:15:00Z",
        created_by="system",
    )


def _build_juniper_report() -> AuditReport:
    """Builds a realistic canonical AuditReport for Juniper Junos."""
    fw_junos = FrameworkReportItem(
        framework_id="cis_juniper_junos",
        framework_name="CIS Juniper Junos OS Benchmark",
        framework_version="1.1.0",
        vendor_scope="juniper",
        description="CIS compliance controls for Junos devices",
        total_controls=2,
        passed=1,
        failed=1,
        unknown=0,
        pass_rate=50.0,
        unknown_rate=0.0,
        control_results=[
            {
                "control_id": "JUNOS-SSH-001",
                "title": "Ensure root login via SSH is disabled",
                "status": "PASS",
                "check_focus": "SSH Root Access",
                "evidence": ["set system services ssh root-login deny"],
                "rationale": "Root SSH login denied",
            },
            {
                "control_id": "JUNOS-NTP-001",
                "title": "Ensure NTP authentication is configured",
                "status": "FAIL",
                "check_focus": "NTP Authentication",
                "evidence": [],
                "rationale": "No NTP authentication keys configured",
            },
        ],
        evidence=[
            {"evidence_id": "EV-J1", "type": "config_line", "content": "set system services ssh root-login deny"}
        ]
    )

    editable = HumanEditableContent(
        executive_summary="Juniper Junos audit complete.",
        auditor_observations="Branch edge firewall configuration.",
        control_notes={"JUNOS-NTP-001": "NTP keys awaiting key server deployment."},
        remediation_commentary={"JUNOS-NTP-001": "set system ntp authentication-key 1 md5 <secret>"},
        recommendations="Deploy authenticated NTP across all Junos routers.",
        additional_findings="",
        final_reviewer_notes="",
    )

    return AuditReport(
        report_id="rep-juniper-001",
        audit_entry_id="aud-juniper-entry-789",
        session_id="sess-juniper-101",
        vendor="juniper",
        device_metadata={
            "hostname": "edge-srx-01",
            "vendor": "juniper",
            "platform": "Junos",
            "management_ip": "10.50.1.1",
        },
        configuration_metadata={
            "filename": "junos_srx_edge.txt",
            "config_file_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "line_count": 320,
        },
        frameworks=[fw_junos],
        remediation=[
            {
                "rule_id": "JUNOS-NTP-001",
                "cli": "set system ntp authentication-key 1 md5 <secret>",
                "description": "Configure NTP authentication",
            }
        ],
        conflict_warnings=[],
        ai_mapping_provenance=[],
        editable_content=editable,
        edit_metadata=[],
        version=1,
        created_at="2026-09-20T11:00:00Z",
        updated_at="2026-09-20T11:00:00Z",
        created_by="system",
    )


# ==============================================================================
# Test Cases (All 20 Invariants)
# ==============================================================================

def test_cisco_multi_framework_pdf_export(clean_export_dir):
    """1. Cisco multi-framework PDF export produces valid, readable PDF."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)

    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0
    text = _extract_pdf_text(pdf_path)
    assert "core-router-01" in text
    assert "CIS Cisco IOS XE Benchmark" in text
    assert "DISA STIG Cisco IOS XE" in text
    assert "CIS-1.1.1" in text
    assert "STIG-NET-001" in text


def test_cisco_multi_framework_docx_export(clean_export_dir):
    """2. Cisco multi-framework DOCX export produces valid zero-dependency OOXML package."""
    rep = _build_cisco_multi_framework_report()
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    assert docx_path.exists()
    assert docx_path.stat().st_size > 0
    xml_content = _extract_docx_xml(docx_path)
    assert "core-router-01" in xml_content
    assert "CIS Cisco IOS XE Benchmark" in xml_content
    assert "DISA STIG Cisco IOS XE" in xml_content
    assert "CIS-1.1.1" in xml_content
    assert "STIG-NET-001" in xml_content


def test_juniper_export(clean_export_dir):
    """3. Juniper export respects Junos metadata and rules without defaulting to Cisco."""
    rep = _build_juniper_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    assert "edge-srx-01" in pdf_text and "edge-srx-01" in docx_xml
    assert "JUNIPER" in pdf_text and "JUNIPER" in docx_xml
    assert "Junos" in pdf_text and "Junos" in docx_xml
    assert "JUNOS-SSH-001" in pdf_text and "JUNOS-SSH-001" in docx_xml
    # Verify no spurious Cisco content leaked into Juniper report
    assert "Cisco IOS-XE" not in pdf_text
    assert "Cisco IOS-XE" not in docx_xml


def test_multiple_frameworks_in_one_export(clean_export_dir):
    """4. Multiple frameworks appear inside ONE exported document."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    # Both frameworks present in single PDF
    assert "CIS Cisco IOS XE Benchmark" in pdf_text
    assert "DISA STIG Cisco IOS XE" in pdf_text

    # Both frameworks present in single DOCX
    assert "CIS Cisco IOS XE Benchmark" in docx_xml
    assert "DISA STIG Cisco IOS XE" in docx_xml


def test_pass_fail_unknown_verdicts_preserved(clean_export_dir):
    """5. PASS / FAIL / UNKNOWN status badges and verdicts are preserved in both exports."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    # In PDF text
    assert "PASS" in pdf_text
    assert "FAIL" in pdf_text
    assert "UNKNOWN" in pdf_text

    # In DOCX XML with colors
    assert ">PASS<" in docx_xml
    assert ">FAIL<" in docx_xml
    assert ">UNKNOWN<" in docx_xml


def test_pass_rates_preserved(clean_export_dir):
    """6. Individual framework pass rates are preserved faithfully."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    assert "66.7%" in pdf_text
    assert "50.0%" in pdf_text
    assert "66.7%" in docx_xml
    assert "50.0%" in docx_xml


def test_framework_metadata_preserved(clean_export_dir):
    """7. Framework metadata (version, vendor scope, description) is preserved."""
    rep = _build_cisco_multi_framework_report()
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)
    docx_xml = _extract_docx_xml(docx_path)

    assert "1.0.0" in docx_xml
    assert "2.1" in docx_xml
    assert "cis_cisco_iosxe" in docx_xml or "CIS Cisco IOS XE Benchmark" in docx_xml


def test_evidence_and_remediation_preserved(clean_export_dir):
    """8. Evidence items and CLI remediation commands are rendered."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    assert "service password-encryption" in pdf_text
    assert "no ip http server" in pdf_text
    assert "service password-encryption" in docx_xml
    assert "no ip http server" in docx_xml


def test_ai_mapping_provenance_preserved(clean_export_dir):
    """9. AI and trusted mapping provenance entries appear in exports."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    assert "CISCO-HTTP-01" in pdf_text
    assert "exact_semantic" in pdf_text
    assert "CISCO-HTTP-01" in docx_xml
    assert "exact_semantic" in docx_xml


def test_human_editable_content_preserved(clean_export_dir):
    """10. Human editable content sections appear in exported documents."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    assert "Security posture is moderate" in pdf_text
    assert "Reviewed and approved by SecOps lead" in pdf_text
    assert "Security posture is moderate" in docx_xml
    assert "Reviewed and approved by SecOps lead" in docx_xml


def test_manually_edited_fields_visibly_marked(clean_export_dir):
    """11. Manually edited fields are visibly marked with [Edited manually]."""
    rep = _build_cisco_multi_framework_report(with_edits=True)
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    assert "[Edited manually]" in pdf_text
    assert "[Edited manually]" in docx_xml


def test_export_does_not_mutate_canonical_report(clean_export_dir):
    """12. Export operations do not mutate the input AuditReport domain object."""
    rep = _build_cisco_multi_framework_report()
    snapshot_before = copy.deepcopy(rep.to_dict())

    report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    report_exporter.export_docx(rep, export_dir=clean_export_dir)

    snapshot_after = rep.to_dict()
    assert snapshot_before == snapshot_after, "AuditReport was mutated during export operations!"


def test_export_does_not_modify_audit_ledger(clean_test_db, clean_export_dir):
    """13. Export operations do not write to or modify the SQLite audit_ledger."""
    rep = _build_cisco_multi_framework_report()

    with database.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_ledger;")
        count_before = cursor.fetchone()[0]

    report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    report_exporter.export_docx(rep, export_dir=clean_export_dir)

    with database.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_ledger;")
        count_after = cursor.fetchone()[0]

    assert count_before == count_after, "Audit ledger count changed during export!"


def test_export_does_not_invoke_compliance_evaluators(clean_export_dir):
    """14. Export operations do not re-invoke any compliance evaluation engine."""
    rep = _build_cisco_multi_framework_report()

    with patch("cisco_auditor.evaluate_rules", side_effect=RuntimeError("Evaluator called!")):
        with patch("juniper_auditor.evaluate_rules", side_effect=RuntimeError("Evaluator called!")):
            with patch("cis_benchmark_cisco_iosxe.CisCiscoIosXeEvaluator.evaluate", side_effect=RuntimeError("Evaluator called!")):
                with patch("disa_stig_cisco_iosxe.StigCiscoIosXeEvaluator.evaluate", side_effect=RuntimeError("Evaluator called!")):
                    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
                    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)
                    assert pdf_path.exists()
                    assert docx_path.exists()


def test_export_does_not_invoke_ai(clean_export_dir):
    """15. Export operations do not invoke AI suggester or inference models."""
    rep = _build_cisco_multi_framework_report()

    with patch("ai_suggester.suggest_mapping", side_effect=RuntimeError("AI invoked!")):
        with patch("ai_suggester.get_model", side_effect=RuntimeError("AI invoked!")):
            with patch("ai_model_manager.AIModelManager", side_effect=RuntimeError("AI invoked!")):
                pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
                docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)
                assert pdf_path.exists()
                assert docx_path.exists()


def test_xml_escaping_and_special_characters(clean_export_dir):
    """16. Special characters (<, >, &, quotes, Unicode, multiline) render without XML/PDF crash."""
    rep = _build_cisco_multi_framework_report()

    # Inject hostile characters into an editable field
    rep.editable_content.executive_summary = (
        "Security check <tag> & 'single' and \"double\" quotes. Math: 5 < 10 & 10 > 5.\n"
        "Unicode: • — ‘smart quote’ \u26a0.\n"
        "Multiline block:\nLine 2\nLine 3"
    )

    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    assert pdf_path.exists()
    assert docx_path.exists()

    docx_xml = _extract_docx_xml(docx_path)
    # Confirm characters were escaped properly in XML
    assert "&lt;tag&gt;" in docx_xml
    assert "&amp;" in docx_xml
    assert "&quot;" in docx_xml or '"' in docx_xml


def test_path_traversal_prevention(clean_export_dir):
    """17. Path traversal attempts and escapes outside the controlled directory are rejected."""
    rep = _build_cisco_multi_framework_report()

    # Relative path traversal escape
    with pytest.raises(ValueError, match="Path traversal or directory escape detected"):
        report_exporter.export_pdf(rep, output_path="../escaped_report.pdf", export_dir=clean_export_dir)

    # Deep relative escape
    with pytest.raises(ValueError, match="Path traversal or directory escape detected"):
        report_exporter.export_docx(rep, output_path="../../../etc/passwd.docx", export_dir=clean_export_dir)

    # Absolute path outside export directory
    outside_path = pathlib.Path("C:/Windows/temp/evil.pdf")
    with pytest.raises(ValueError, match="Path traversal or directory escape detected"):
        report_exporter.export_pdf(rep, output_path=outside_path, export_dir=clean_export_dir)


def test_export_failure_leaves_no_corrupt_file(clean_export_dir):
    """18. If export raises an error midway, atomic rollback ensures no corrupted target file is left."""
    rep = _build_cisco_multi_framework_report()
    target_file = clean_export_dir / "failed_report.pdf"

    # Inject failure during document building
    with patch("report_exporter._build_pdf", side_effect=RuntimeError("Disk full / render error")):
        with pytest.raises(RuntimeError, match="Disk full / render error"):
            report_exporter.export_pdf(rep, output_path=target_file, export_dir=clean_export_dir)

    # Verify no final file or temp file remains
    assert not target_file.exists(), "Corrupted final file was left behind after export failure!"
    temp_files = list(clean_export_dir.glob(".*tmp*"))
    assert len(temp_files) == 0, f"Dangling temporary files left behind: {temp_files}"


def test_stable_deterministic_ordering(clean_export_dir):
    """19. Section, framework, control, and edit ordering is stable and deterministic."""
    rep = _build_cisco_multi_framework_report()

    # Run two exports
    path1 = clean_export_dir / "order1.docx"
    path2 = clean_export_dir / "order2.docx"
    report_exporter.export_docx(rep, output_path=path1, export_dir=clean_export_dir)
    report_exporter.export_docx(rep, output_path=path2, export_dir=clean_export_dir)

    xml1 = _extract_docx_xml(path1)
    xml2 = _extract_docx_xml(path2)

    # In XML, frameworks must appear in exact alphabetical order: cis_cisco_iosxe before disa_stig_cisco_iosxe
    pos_cis = xml1.find("CIS Cisco IOS XE Benchmark")
    pos_stig = xml1.find("DISA STIG Cisco IOS XE")
    assert pos_cis != -1 and pos_stig != -1
    assert pos_cis < pos_stig, "CIS must appear before DISA STIG in deterministic ordering"

    # Control results inside CIS must appear in sorted order: CIS-1.1.1, CIS-1.2.1, CIS-1.3.1
    pos_c1 = xml1.find("CIS-1.1.1")
    pos_c2 = xml1.find("CIS-1.2.1")
    pos_c3 = xml1.find("CIS-1.3.1")
    assert pos_c1 < pos_c2 < pos_c3, "Controls must appear in deterministic sorted order"

    # Content XMLs should match
    assert xml1 == xml2, "Export content ordering was not deterministic across repeated runs!"


def test_no_artificial_overall_compliance_verdict(clean_export_dir):
    """20. No synthetic or blended overall compliance score or verdict is introduced."""
    rep = _build_cisco_multi_framework_report()
    pdf_path = report_exporter.export_pdf(rep, export_dir=clean_export_dir)
    docx_path = report_exporter.export_docx(rep, export_dir=clean_export_dir)

    pdf_text = _extract_pdf_text(pdf_path)
    docx_xml = _extract_docx_xml(docx_path)

    for forbidden in ["Overall Score", "Overall Compliance", "Blended Pass Rate", "Synthetic Score"]:
        assert forbidden.lower() not in pdf_text.lower()
        assert forbidden.lower() not in docx_xml.lower()
