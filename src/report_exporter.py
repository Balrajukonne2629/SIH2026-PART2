"""NTRO PS26155 — Canonical Audit Report Export Engine (Phase 3D.4).

Exports the canonical AuditReport domain model to:
1. PDF (via ReportLab)
2. DOCX (via Python Standard Library OOXML / zipfile)

Invariants & Security:
- Single Source of Truth: Consumes AuditReport directly.
- Multi-framework: All evaluated frameworks appear in ONE unified document.
- Zero Compliance Re-evaluation and Zero AI Inference.
- Zero Mutation: AuditReport, audit ledger, and database are completely untouched.
- Manual Edit Provenance: Fields modified by human editors are visibly marked with [Edited manually].
- Path Traversal Defense: Validates resolved paths against controlled export directory.
- Atomic Export: Writes to a temporary file first and renames atomically upon success.
- Zero New Pip Dependencies: DOCX exporter uses pure Python standard library OOXML.
"""

from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
import html
import io
import os
import pathlib
import uuid
import xml.sax.saxutils
import zipfile

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.audit_report import AuditReport, FrameworkReportItem, ReportEdit

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_EXPORT_DIR = (BASE_DIR / "data" / "exports").resolve()


# ==============================================================================
# Path Security & Atomic File Management
# ==============================================================================

def resolve_and_validate_export_path(
    output_path: Optional[Union[str, pathlib.Path]],
    default_filename: str,
    export_dir: Optional[Union[str, pathlib.Path]] = None,
) -> pathlib.Path:
    """Resolves and strictly validates that the final target path resides within the export directory.

    Prevents path traversal attacks (e.g. '../') and unauthorized directory escapes.
    """
    base_dir = pathlib.Path(export_dir).resolve() if export_dir else DEFAULT_EXPORT_DIR
    base_dir.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        target = (base_dir / default_filename).resolve()
    else:
        raw_path = pathlib.Path(output_path)
        if raw_path.is_absolute():
            target = raw_path.resolve()
        else:
            target = (base_dir / raw_path).resolve()

    # Verify target is strictly within base_dir (fail closed on traversal / escape)
    try:
        target.relative_to(base_dir)
    except ValueError:
        raise ValueError(
            f"Path traversal or directory escape detected: target '{target}' "
            f"is outside controlled export directory '{base_dir}'"
        )

    return target


def _atomic_export(target_path: pathlib.Path, write_fn: Callable[[pathlib.Path], None]) -> pathlib.Path:
    """Executes export write into a temporary file and atomically renames upon completion.

    If write_fn raises an exception, the temporary file is deleted and no partial/corrupted
    file remains at target_path.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.with_name(f".{target_path.stem}_{uuid.uuid4().hex[:8]}.tmp{target_path.suffix}")
    try:
        write_fn(temp_path)
        os.replace(temp_path, target_path)
        return target_path
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def _get_edited_fields(report: AuditReport) -> Set[str]:
    """Identifies the set of field paths that have been manually edited from edit provenance."""
    if not report or not report.edit_metadata:
        return set()
    return {e.field_path for e in report.edit_metadata}


# ==============================================================================
# Helper Formatting Utilities
# ==============================================================================

def _clean_unicode(text: Any) -> str:
    """Normalizes Unicode text to safe representations for standard document fonts."""
    if text is None:
        return ""
    s = str(text)
    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",
        "\u2014": "--",
        "\u2022": "*",
        "\u2026": "...",
    }
    for orig, rep in replacements.items():
        s = s.replace(orig, rep)
    return s


def _format_pass_rate(val: Optional[float]) -> str:
    if val is None:
        return "N/A"
    return f"{val:.1f}%"


# ==============================================================================
# PDF Exporter (ReportLab)
# ==============================================================================

def _pdf_escape(text: Any) -> str:
    """Escapes dynamic text for safe insertion into ReportLab Paragraphs."""
    s = _clean_unicode(text)
    s = html.escape(s, quote=True)
    return s.replace("\n", "<br/>")


def _build_pdf(report: AuditReport, target_file: pathlib.Path) -> None:
    """Constructs the comprehensive multi-framework PDF audit report."""
    doc = SimpleDocTemplate(
        str(target_file),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=f"Compliance Audit Report - {report.report_id}",
        author="NTRO Compliance Engine",
        subject=f"AuditEntryID:{report.audit_entry_id}"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=10
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceBefore=8,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#334155")
    )
    mono_style = ParagraphStyle(
        "ReportMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )
    edited_badge_html = "<font color='#b45309'><b>[Edited manually]</b></font>"

    edited_fields = _get_edited_fields(report)
    story: List[Any] = []

    # --- Title & Header ---
    story.append(Paragraph("<b>NETWORK SECURITY COMPLIANCE AUDIT REPORT</b>", title_style))
    story.append(Paragraph(
        f"Canonical Report ID: <code>{_pdf_escape(report.report_id)}</code> &nbsp;|&nbsp; "
        f"Version: <b>v{report.version}</b> &nbsp;|&nbsp; "
        f"Vendor: <b>{_pdf_escape(report.vendor.upper())}</b> &nbsp;|&nbsp; "
        f"Audit Entry: <code>{_pdf_escape(report.audit_entry_id)}</code>",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=8))

    # --- Metadata Table ---
    dev = report.device_metadata or {}
    cfg = report.configuration_metadata or {}
    meta_data = [
        [
            Paragraph("<b>Target Hostname:</b>", body_style),
            Paragraph(_pdf_escape(dev.get("hostname", "Unknown")), mono_style),
            Paragraph("<b>Platform / OS:</b>", body_style),
            Paragraph(_pdf_escape(dev.get("platform", "Unknown")), body_style),
        ],
        [
            Paragraph("<b>Management IP:</b>", body_style),
            Paragraph(_pdf_escape(dev.get("management_ip", "Unknown")), mono_style),
            Paragraph("<b>Config Filename:</b>", body_style),
            Paragraph(_pdf_escape(cfg.get("filename", "Unknown")), mono_style),
        ],
        [
            Paragraph("<b>Config SHA-256:</b>", body_style),
            Paragraph(_pdf_escape(cfg.get("config_file_hash", "Unknown")), mono_style),
            Paragraph("<b>Audit Session ID:</b>", body_style),
            Paragraph(_pdf_escape(report.session_id), mono_style),
        ],
        [
            Paragraph("<b>Created At:</b>", body_style),
            Paragraph(_pdf_escape(report.created_at), body_style),
            Paragraph("<b>Last Updated:</b>", body_style),
            Paragraph(_pdf_escape(report.updated_at), body_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[100, 170, 100, 170])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # --- Executive Summary & Observations ---
    story.append(Paragraph("Executive Summary", h1_style))
    exec_summary_text = report.editable_content.executive_summary or "No executive summary provided."
    exec_header = f" {edited_badge_html}" if "executive_summary" in edited_fields else ""
    story.append(Paragraph(f"{_pdf_escape(exec_summary_text)}{exec_header}", body_style))
    story.append(Spacer(1, 6))

    if report.editable_content.auditor_observations:
        story.append(Paragraph("Auditor Observations", h1_style))
        obs_header = f" {edited_badge_html}" if "auditor_observations" in edited_fields else ""
        story.append(Paragraph(f"{_pdf_escape(report.editable_content.auditor_observations)}{obs_header}", body_style))
        story.append(Spacer(1, 6))

    # --- Multi-Framework Sections ---
    story.append(Paragraph("Evaluated Compliance Frameworks", h1_style))

    # Deterministic sorting of frameworks by framework_id
    sorted_frameworks = sorted(report.frameworks, key=lambda f: f.framework_id)
    for fw in sorted_frameworks:
        fw_name = fw.framework_name or fw.framework_id
        fw_ver = f" (v{fw.framework_version})" if fw.framework_version else ""
        story.append(Paragraph(f"Framework: {_pdf_escape(fw_name)}{_pdf_escape(fw_ver)}", h2_style))

        # Summary scorecard for this framework
        scorecard = [
            [
                Paragraph("<b>Total Controls</b>", body_style),
                Paragraph("<b>Passed</b>", body_style),
                Paragraph("<b>Failed</b>", body_style),
                Paragraph("<b>Unknown</b>", body_style),
                Paragraph("<b>Pass Rate</b>", body_style),
            ],
            [
                Paragraph(str(fw.total_controls), mono_style),
                Paragraph(f"<font color='#166534'><b>{fw.passed}</b></font>", mono_style),
                Paragraph(f"<font color='#991b1b'><b>{fw.failed}</b></font>", mono_style),
                Paragraph(f"<font color='#854d0e'><b>{fw.unknown}</b></font>", mono_style),
                Paragraph(f"<b>{_format_pass_rate(fw.pass_rate)}</b>", mono_style),
            ]
        ]
        score_table = Table(scorecard, colWidths=[100, 110, 110, 110, 110])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 6))

        # Control Results Table (ordered deterministically by control_id)
        if fw.control_results:
            ctrl_rows = [
                [
                    Paragraph("<b>Control ID</b>", body_style),
                    Paragraph("<b>Focus / Title</b>", body_style),
                    Paragraph("<b>Status</b>", body_style),
                    Paragraph("<b>Evidence / Findings</b>", body_style),
                ]
            ]

            sorted_ctrls = sorted(fw.control_results, key=lambda c: str(c.get("control_id", "")))
            for ctrl in sorted_ctrls:
                cid = str(ctrl.get("control_id", ""))
                c_status = str(ctrl.get("status", "Unknown")).upper()

                if "PASS" in c_status:
                    badge_html = "<font color='#166534'><b>PASS</b></font>"
                elif "FAIL" in c_status:
                    badge_html = "<font color='#991b1b'><b>FAIL</b></font>"
                else:
                    badge_html = "<font color='#854d0e'><b>UNKNOWN</b></font>"

                # Title & Focus
                focus = ctrl.get("check_focus") or ctrl.get("title") or "Compliance Check"
                if isinstance(focus, list):
                    focus = " / ".join(str(x) for x in focus)

                # Evidence & Rationale
                ev_items = ctrl.get("evidence", [])
                ev_str = ", ".join(str(e) for e in ev_items) if ev_items else ""
                rationale = ctrl.get("rationale") or ""
                evidence_text = ev_str or rationale or "No evidence reported"

                # Check if human added control notes
                note_key = f"control_notes.{cid}"
                c_note = report.editable_content.control_notes.get(cid, "")
                if c_note:
                    edited_marker = f" {edited_badge_html}" if note_key in edited_fields else ""
                    evidence_text += f"<br/><b>Auditor Note:</b> {_pdf_escape(c_note)}{edited_marker}"

                ctrl_rows.append([
                    Paragraph(f"<b>{_pdf_escape(cid)}</b>", mono_style),
                    Paragraph(_pdf_escape(str(focus)), body_style),
                    Paragraph(badge_html, body_style),
                    Paragraph(_pdf_escape(evidence_text), mono_style),
                ])

            ctrl_table = Table(ctrl_rows, colWidths=[100, 160, 70, 210])
            ts_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 3.5),
            ]
            ctrl_table.setStyle(TableStyle(ts_cmds))
            story.append(KeepTogether([ctrl_table]))
            story.append(Spacer(1, 8))

    # --- Remediation & Commentary ---
    if report.remediation:
        story.append(Paragraph("Remediation Commands & Guidance", h1_style))
        rem_rows = [
            [
                Paragraph("<b>Rule / Control</b>", body_style),
                Paragraph("<b>Recommended CLI Remediation</b>", body_style),
                Paragraph("<b>Commentary</b>", body_style),
            ]
        ]
        sorted_rem = sorted(report.remediation, key=lambda r: str(r.get("rule_id", "")))
        for rem in sorted_rem:
            rid = str(rem.get("rule_id", ""))
            cli = str(rem.get("cli", ""))

            comm_key = f"remediation_commentary.{rid}"
            comm_val = report.editable_content.remediation_commentary.get(rid, "")
            comm_marker = f" {edited_badge_html}" if comm_key in edited_fields else ""
            comm_cell = f"{_pdf_escape(comm_val)}{comm_marker}" if comm_val else "None"

            rem_rows.append([
                Paragraph(f"<b>{_pdf_escape(rid)}</b>", mono_style),
                Paragraph(_pdf_escape(cli), mono_style),
                Paragraph(comm_cell, body_style),
            ])

        rem_table = Table(rem_rows, colWidths=[110, 250, 180])
        rem_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(KeepTogether([rem_table]))
        story.append(Spacer(1, 8))

    # --- Conflict Warnings ---
    if report.conflict_warnings:
        story.append(Paragraph("Static Conflict Warnings", h1_style))
        for warn in report.conflict_warnings:
            msg = warn.get("message") or str(warn)
            story.append(Paragraph(f"• <font color='#991b1b'><b>WARNING:</b></font> {_pdf_escape(msg)}", body_style))
        story.append(Spacer(1, 6))

    # --- AI & Mapping Provenance ---
    if report.ai_mapping_provenance:
        story.append(Paragraph("AI & Trusted Mapping Provenance", h1_style))
        ai_rows = [
            [
                Paragraph("<b>Vendor Rule</b>", body_style),
                Paragraph("<b>Mapped Control</b>", body_style),
                Paragraph("<b>Match Type</b>", body_style),
                Paragraph("<b>Confidence / Rationale</b>", body_style),
            ]
        ]
        sorted_ai = sorted(report.ai_mapping_provenance, key=lambda p: str(p.get("vendor_rule_id", "")))
        for p in sorted_ai:
            v_id = str(p.get("vendor_rule_id", ""))
            t_id = str(p.get("common_rule_id") or p.get("framework_rule_id", ""))
            m_type = str(p.get("match_type") or p.get("status", ""))
            conf = str(p.get("confidence") or p.get("rationale", ""))

            ai_rows.append([
                Paragraph(_pdf_escape(v_id), mono_style),
                Paragraph(_pdf_escape(t_id), mono_style),
                Paragraph(_pdf_escape(m_type), body_style),
                Paragraph(_pdf_escape(conf), mono_style),
            ])

        ai_table = Table(ai_rows, colWidths=[120, 120, 100, 200])
        ai_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(KeepTogether([ai_table]))
        story.append(Spacer(1, 8))

    # --- Additional Findings & Reviewer Notes ---
    if report.editable_content.recommendations:
        rec_marker = f" {edited_badge_html}" if "recommendations" in edited_fields else ""
        story.append(Paragraph("Recommendations", h1_style))
        story.append(Paragraph(f"{_pdf_escape(report.editable_content.recommendations)}{rec_marker}", body_style))
        story.append(Spacer(1, 6))

    if report.editable_content.additional_findings:
        af_marker = f" {edited_badge_html}" if "additional_findings" in edited_fields else ""
        story.append(Paragraph("Additional Findings", h1_style))
        story.append(Paragraph(f"{_pdf_escape(report.editable_content.additional_findings)}{af_marker}", body_style))
        story.append(Spacer(1, 6))

    if report.editable_content.final_reviewer_notes:
        rn_marker = f" {edited_badge_html}" if "final_reviewer_notes" in edited_fields else ""
        story.append(Paragraph("Final Reviewer Notes", h1_style))
        story.append(Paragraph(f"{_pdf_escape(report.editable_content.final_reviewer_notes)}{rn_marker}", body_style))
        story.append(Spacer(1, 6))

    # --- Manual Edit Provenance History ---
    story.append(Paragraph("Manual Edit History", h1_style))
    if report.edit_metadata:
        edit_rows = [
            [
                Paragraph("<b>Ver</b>", body_style),
                Paragraph("<b>Field Path</b>", body_style),
                Paragraph("<b>Previous Value</b>", body_style),
                Paragraph("<b>New Value</b>", body_style),
                Paragraph("<b>Editor</b>", body_style),
                Paragraph("<b>Timestamp</b>", body_style),
            ]
        ]
        sorted_edits = sorted(report.edit_metadata, key=lambda e: (e.version, e.edited_at, e.edit_id))
        for e in sorted_edits:
            edit_rows.append([
                Paragraph(f"v{e.version}", mono_style),
                Paragraph(_pdf_escape(e.field_path), mono_style),
                Paragraph(_pdf_escape(str(e.previous_value or "-")[:60]), mono_style),
                Paragraph(_pdf_escape(str(e.new_value or "-")[:60]), mono_style),
                Paragraph(_pdf_escape(e.edited_by), body_style),
                Paragraph(_pdf_escape(e.edited_at), mono_style),
            ])

        edit_table = Table(edit_rows, colWidths=[35, 120, 110, 110, 75, 90])
        edit_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fef3c7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#f59e0b")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#fde68a")),
            ("PADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(KeepTogether([edit_table]))
    else:
        story.append(Paragraph("<i>No manual modifications. Report remains in original system-generated state (v1).</i>", body_style))

    doc.build(story)


# ==============================================================================
# DOCX Exporter (Zero-Dependency Pure Python OOXML)
# ==============================================================================

class _OOXMLBuilder:
    """Constructs standards-compliant Office Open XML (.docx) packages using Python standard library."""

    def __init__(self):
        self.body_elements: List[str] = []

    def escape(self, text: Any) -> str:
        s = _clean_unicode(text)
        return xml.sax.saxutils.escape(s, entities={'"': "&quot;", "'": "&apos;"})

    def add_title(self, text: str) -> None:
        safe_t = self.escape(text)
        self.body_elements.append(
            f'<w:p><w:pPr><w:pStyle w:val="Title"/><w:spacing w:before="240" w:after="120"/></w:pPr>'
            f'<w:r><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="0F172A"/></w:rPr>'
            f'<w:t>{safe_t}</w:t></w:r></w:p>'
        )

    def add_subtitle(self, text: str) -> None:
        safe_t = self.escape(text)
        self.body_elements.append(
            f'<w:p><w:pPr><w:pStyle w:val="Subtitle"/><w:spacing w:after="200"/></w:pPr>'
            f'<w:r><w:rPr><w:sz w:val="19"/><w:color w:val="64748B"/></w:rPr>'
            f'<w:t>{safe_t}</w:t></w:r></w:p>'
        )

    def add_heading1(self, text: str) -> None:
        safe_t = self.escape(text)
        self.body_elements.append(
            f'<w:p><w:pPr><w:pStyle w:val="Heading1"/><w:spacing w:before="240" w:after="100"/></w:pPr>'
            f'<w:r><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="1E293B"/></w:rPr>'
            f'<w:t>{safe_t}</w:t></w:r></w:p>'
        )

    def add_heading2(self, text: str) -> None:
        safe_t = self.escape(text)
        self.body_elements.append(
            f'<w:p><w:pPr><w:pStyle w:val="Heading2"/><w:spacing w:before="180" w:after="80"/></w:pPr>'
            f'<w:r><w:rPr><w:b/><w:sz w:val="22"/><w:color w:val="334155"/></w:rPr>'
            f'<w:t>{safe_t}</w:t></w:r></w:p>'
        )

    def add_paragraph(
        self,
        text: str,
        bold: bool = False,
        italic: bool = False,
        color: Optional[str] = None,
        edited_marker: bool = False
    ) -> None:
        rpr_parts: List[str] = []
        if bold:
            rpr_parts.append("<w:b/>")
        if italic:
            rpr_parts.append("<w:i/>")
        if color:
            rpr_parts.append(f'<w:color w:val="{color}"/>')
        rpr = "".join(rpr_parts)
        if rpr:
            rpr = f"<w:rPr>{rpr}</w:rPr>"

        # Handle multiline breaks cleanly
        lines = str(text).split("\n")
        runs = []
        for idx, line in enumerate(lines):
            safe_l = self.escape(line)
            runs.append(f"<w:r>{rpr}<w:t>{safe_l}</w:t></w:r>")
            if idx < len(lines) - 1:
                runs.append("<w:r><w:br/></w:r>")

        if edited_marker:
            marker_xml = (
                '<w:r><w:rPr><w:b/><w:i/><w:color w:val="B45309"/></w:rPr>'
                '<w:t xml:space="preserve"> [Edited manually]</w:t></w:r>'
            )
            runs.append(marker_xml)

        body_runs = "".join(runs)
        self.body_elements.append(
            f'<w:p><w:pPr><w:spacing w:after="120"/><w:jc w:val="left"/></w:pPr>{body_runs}</w:p>'
        )

    def add_table(
        self,
        headers: List[str],
        rows: List[List[Tuple[str, Optional[str], bool, bool]]],  # (text, color, bold, is_mono)
        header_bg: str = "F1F5F9"
    ) -> None:
        """Adds a styled table with borders, header shading, and formatted cells."""
        xml_parts = [
            '<w:tbl>',
            '<w:tblPr>',
            '<w:tblW w:w="5000" w:type="pct"/>',
            '<w:tblBorders>',
            '  <w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>',
            '  <w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>',
            '  <w:left w:val="none"/>',
            '  <w:right w:val="none"/>',
            '  <w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>',
            '  <w:insideV w:val="none"/>',
            '</w:tblBorders>',
            '<w:tblCellMar>',
            '  <w:top w:w="80" w:type="dxa"/>',
            '  <w:bottom w:w="80" w:type="dxa"/>',
            '  <w:left w:w="120" w:type="dxa"/>',
            '  <w:right w:w="120" w:type="dxa"/>',
            '</w:tblCellMar>',
            '</w:tblPr>',
        ]

        # Header Row
        xml_parts.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>')
        for h in headers:
            safe_h = self.escape(h)
            xml_parts.append(
                f'<w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="{header_bg}"/></w:tcPr>'
                f'<w:p><w:r><w:rPr><w:b/><w:sz w:val="18"/><w:color w:val="0F172A"/></w:rPr>'
                f'<w:t>{safe_h}</w:t></w:r></w:p></w:tc>'
            )
        xml_parts.append('</w:tr>')

        # Data Rows
        for row in rows:
            xml_parts.append('<w:tr>')
            for cell_data in row:
                text, color, bold, is_mono = cell_data
                rpr_parts = ['<w:sz w:val="17"/>']
                if bold:
                    rpr_parts.append('<w:b/>')
                if color:
                    rpr_parts.append(f'<w:color w:val="{color}"/>')
                if is_mono:
                    rpr_parts.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>')

                rpr = f"<w:rPr>{''.join(rpr_parts)}</w:rPr>"

                lines = str(text).split("\n")
                runs = []
                for idx, line in enumerate(lines):
                    safe_l = self.escape(line)
                    runs.append(f"<w:r>{rpr}<w:t>{safe_l}</w:t></w:r>")
                    if idx < len(lines) - 1:
                        runs.append("<w:r><w:br/></w:r>")

                body_runs = "".join(runs)
                xml_parts.append(
                    f'<w:tc><w:p><w:pPr><w:spacing w:after="40"/></w:pPr>{body_runs}</w:p></w:tc>'
                )
            xml_parts.append('</w:tr>')

        xml_parts.append('</w:tbl>')
        self.body_elements.append("".join(xml_parts))

    def write_to_file(self, target_path: pathlib.Path) -> None:
        """Serializes the OOXML package into a valid .docx ZIP archive."""
        body_xml = "".join(self.body_elements)
        document_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            f'  <w:body>\n{body_xml}\n    <w:sectPr/>\n  </w:body>\n'
            '</w:document>'
        )

        content_types_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
            '  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>\n'
            '</Types>'
        )

        root_rels_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '</Relationships>'
        )

        doc_rels_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>\n'
            '</Relationships>'
        )

        styles_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            '  <w:docDefaults>\n'
            '    <w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="20"/></w:rPr></w:rPrDefault>\n'
            '  </w:docDefaults>\n'
            '  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="0F172A"/></w:rPr></w:style>\n'
            '  <w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:rPr><w:sz w:val="20"/><w:color w:val="64748B"/></w:rPr></w:style>\n'
            '  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="1E293B"/></w:rPr></w:style>\n'
            '  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:rPr><w:b/><w:sz w:val="22"/><w:color w:val="334155"/></w:rPr></w:style>\n'
            '</w:styles>'
        )

        with zipfile.ZipFile(target_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types_xml)
            zf.writestr("_rels/.rels", root_rels_xml)
            zf.writestr("word/_rels/document.xml.rels", doc_rels_xml)
            zf.writestr("word/styles.xml", styles_xml)
            zf.writestr("word/document.xml", document_xml)


def _build_docx(report: AuditReport, target_file: pathlib.Path) -> None:
    """Constructs the comprehensive multi-framework DOCX audit report using pure standard library."""
    builder = _OOXMLBuilder()
    edited_fields = _get_edited_fields(report)

    # --- Title & Subtitle ---
    builder.add_title("NETWORK SECURITY COMPLIANCE AUDIT REPORT")
    builder.add_subtitle(
        f"Report ID: {report.report_id}  |  Version: v{report.version}  |  "
        f"Vendor: {report.vendor.upper()}  |  Audit Entry: {report.audit_entry_id}"
    )

    # --- Metadata Table ---
    dev = report.device_metadata or {}
    cfg = report.configuration_metadata or {}
    meta_headers = ["Property", "Value", "Property", "Value"]
    meta_rows = [
        [
            ("Target Hostname", None, True, False),
            (str(dev.get("hostname", "Unknown")), None, False, True),
            ("Platform / OS", None, True, False),
            (str(dev.get("platform", "Unknown")), None, False, False),
        ],
        [
            ("Management IP", None, True, False),
            (str(dev.get("management_ip", "Unknown")), None, False, True),
            ("Config Filename", None, True, False),
            (str(cfg.get("filename", "Unknown")), None, False, True),
        ],
        [
            ("Config SHA-256", None, True, False),
            (str(cfg.get("config_file_hash", "Unknown")), None, False, True),
            ("Audit Session ID", None, True, False),
            (str(report.session_id), None, False, True),
        ],
        [
            ("Created At", None, True, False),
            (str(report.created_at), None, False, False),
            ("Last Updated", None, True, False),
            (str(report.updated_at), None, False, False),
        ],
    ]
    builder.add_table(meta_headers, meta_rows, header_bg="E2E8F0")

    # --- Executive Summary ---
    builder.add_heading1("Executive Summary")
    exec_summary_text = report.editable_content.executive_summary or "No executive summary provided."
    builder.add_paragraph(
        exec_summary_text,
        edited_marker=("executive_summary" in edited_fields)
    )

    if report.editable_content.auditor_observations:
        builder.add_heading1("Auditor Observations")
        builder.add_paragraph(
            report.editable_content.auditor_observations,
            edited_marker=("auditor_observations" in edited_fields)
        )

    # --- Multi-Framework Sections ---
    builder.add_heading1("Evaluated Compliance Frameworks")
    sorted_frameworks = sorted(report.frameworks, key=lambda f: f.framework_id)
    for fw in sorted_frameworks:
        fw_name = fw.framework_name or fw.framework_id
        fw_ver = f" (v{fw.framework_version})" if fw.framework_version else ""
        builder.add_heading2(f"Framework: {fw_name}{fw_ver}")

        # Summary scorecard table
        score_headers = ["Total Controls", "Passed", "Failed", "Unknown", "Pass Rate"]
        score_rows = [
            [
                (str(fw.total_controls), None, True, True),
                (str(fw.passed), "166534", True, True),
                (str(fw.failed), "991B1B", True, True),
                (str(fw.unknown), "854D0E", True, True),
                (_format_pass_rate(fw.pass_rate), "0F172A", True, True),
            ]
        ]
        builder.add_table(score_headers, score_rows, header_bg="F1F5F9")

        # Control Results Table
        if fw.control_results:
            ctrl_headers = ["Control ID", "Focus / Title", "Status", "Evidence / Findings"]
            ctrl_rows = []
            sorted_ctrls = sorted(fw.control_results, key=lambda c: str(c.get("control_id", "")))
            for ctrl in sorted_ctrls:
                cid = str(ctrl.get("control_id", ""))
                c_status = str(ctrl.get("status", "Unknown")).upper()

                if "PASS" in c_status:
                    stat_color = "166534"
                    stat_text = "PASS"
                elif "FAIL" in c_status:
                    stat_color = "991B1B"
                    stat_text = "FAIL"
                else:
                    stat_color = "854D0E"
                    stat_text = "UNKNOWN"

                focus = ctrl.get("check_focus") or ctrl.get("title") or "Compliance Check"
                if isinstance(focus, list):
                    focus = " / ".join(str(x) for x in focus)

                ev_items = ctrl.get("evidence", [])
                ev_str = ", ".join(str(e) for e in ev_items) if ev_items else ""
                rationale = ctrl.get("rationale") or ""
                evidence_text = ev_str or rationale or "No evidence reported"

                note_key = f"control_notes.{cid}"
                c_note = report.editable_content.control_notes.get(cid, "")
                if c_note:
                    marker_str = " [Edited manually]" if note_key in edited_fields else ""
                    evidence_text += f"\nAuditor Note: {c_note}{marker_str}"

                ctrl_rows.append([
                    (cid, None, True, True),
                    (str(focus), None, False, False),
                    (stat_text, stat_color, True, True),
                    (evidence_text, None, False, True),
                ])
            builder.add_table(ctrl_headers, ctrl_rows, header_bg="E2E8F0")

    # --- Remediation ---
    if report.remediation:
        builder.add_heading1("Remediation Commands & Guidance")
        rem_headers = ["Rule / Control", "Recommended CLI Remediation", "Commentary"]
        rem_rows = []
        sorted_rem = sorted(report.remediation, key=lambda r: str(r.get("rule_id", "")))
        for rem in sorted_rem:
            rid = str(rem.get("rule_id", ""))
            cli = str(rem.get("cli", ""))
            comm_key = f"remediation_commentary.{rid}"
            comm_val = report.editable_content.remediation_commentary.get(rid, "")
            comm_marker = " [Edited manually]" if (comm_val and comm_key in edited_fields) else ""
            comm_text = f"{comm_val}{comm_marker}" if comm_val else "None"

            rem_rows.append([
                (rid, None, True, True),
                (cli, None, False, True),
                (comm_text, None, False, False),
            ])
        builder.add_table(rem_headers, rem_rows, header_bg="F1F5F9")

    # --- Conflict Warnings ---
    if report.conflict_warnings:
        builder.add_heading1("Static Conflict Warnings")
        for warn in report.conflict_warnings:
            msg = warn.get("message") or str(warn)
            builder.add_paragraph(f"• WARNING: {msg}", bold=True, color="991B1B")

    # --- AI Mapping Provenance ---
    if report.ai_mapping_provenance:
        builder.add_heading1("AI & Trusted Mapping Provenance")
        ai_headers = ["Vendor Rule", "Mapped Control", "Match Type", "Confidence / Rationale"]
        ai_rows = []
        sorted_ai = sorted(report.ai_mapping_provenance, key=lambda p: str(p.get("vendor_rule_id", "")))
        for p in sorted_ai:
            v_id = str(p.get("vendor_rule_id", ""))
            t_id = str(p.get("common_rule_id") or p.get("framework_rule_id", ""))
            m_type = str(p.get("match_type") or p.get("status", ""))
            conf = str(p.get("confidence") or p.get("rationale", ""))
            ai_rows.append([
                (v_id, None, True, True),
                (t_id, None, False, True),
                (m_type, None, False, False),
                (conf, None, False, True),
            ])
        builder.add_table(ai_headers, ai_rows, header_bg="F1F5F9")

    # --- Recommendations & Findings ---
    if report.editable_content.recommendations:
        builder.add_heading1("Recommendations")
        builder.add_paragraph(
            report.editable_content.recommendations,
            edited_marker=("recommendations" in edited_fields)
        )

    if report.editable_content.additional_findings:
        builder.add_heading1("Additional Findings")
        builder.add_paragraph(
            report.editable_content.additional_findings,
            edited_marker=("additional_findings" in edited_fields)
        )

    if report.editable_content.final_reviewer_notes:
        builder.add_heading1("Final Reviewer Notes")
        builder.add_paragraph(
            report.editable_content.final_reviewer_notes,
            edited_marker=("final_reviewer_notes" in edited_fields)
        )

    # --- Manual Edit Provenance History ---
    builder.add_heading1("Manual Edit History")
    if report.edit_metadata:
        edit_headers = ["Ver", "Field Path", "Previous Value", "New Value", "Editor", "Timestamp"]
        edit_rows = []
        sorted_edits = sorted(report.edit_metadata, key=lambda e: (e.version, e.edited_at, e.edit_id))
        for e in sorted_edits:
            edit_rows.append([
                (f"v{e.version}", None, True, True),
                (e.field_path, None, False, True),
                (str(e.previous_value or "-")[:60], None, False, True),
                (str(e.new_value or "-")[:60], None, False, True),
                (e.edited_by, None, False, False),
                (e.edited_at, None, False, True),
            ])
        builder.add_table(edit_headers, edit_rows, header_bg="FEF3C7")
    else:
        builder.add_paragraph("No manual modifications. Report remains in original system-generated state (v1).", italic=True)

    builder.write_to_file(target_file)


# ==============================================================================
# Public Export Interfaces
# ==============================================================================

def export_pdf(
    report: AuditReport,
    output_path: Optional[Union[str, pathlib.Path]] = None,
    export_dir: Optional[Union[str, pathlib.Path]] = None,
) -> pathlib.Path:
    """Exports the canonical AuditReport directly to publication-quality PDF.

    Args:
        report: The canonical AuditReport domain model (read-only).
        output_path: Optional custom path/filename. Must resolve within export_dir.
        export_dir: Optional controlled export directory (defaults to data/exports).

    Returns:
        pathlib.Path: Resolved path to the exported PDF file.

    Raises:
        ValueError: If path traversal or directory escape is detected.
    """
    if not isinstance(report, AuditReport):
        raise TypeError(f"Expected AuditReport instance, got {type(report).__name__}")

    default_filename = f"audit_report_{report.vendor.lower()}_{report.report_id}.pdf"
    validated_path = resolve_and_validate_export_path(output_path, default_filename, export_dir)

    return _atomic_export(validated_path, lambda tmp: _build_pdf(report, tmp))


def export_docx(
    report: AuditReport,
    output_path: Optional[Union[str, pathlib.Path]] = None,
    export_dir: Optional[Union[str, pathlib.Path]] = None,
) -> pathlib.Path:
    """Exports the canonical AuditReport directly to Microsoft Word (.docx) using pure standard library.

    Args:
        report: The canonical AuditReport domain model (read-only).
        output_path: Optional custom path/filename. Must resolve within export_dir.
        export_dir: Optional controlled export directory (defaults to data/exports).

    Returns:
        pathlib.Path: Resolved path to the exported DOCX file.

    Raises:
        ValueError: If path traversal or directory escape is detected.
    """
    if not isinstance(report, AuditReport):
        raise TypeError(f"Expected AuditReport instance, got {type(report).__name__}")

    default_filename = f"audit_report_{report.vendor.lower()}_{report.report_id}.docx"
    validated_path = resolve_and_validate_export_path(output_path, default_filename, export_dir)

    return _atomic_export(validated_path, lambda tmp: _build_docx(report, tmp))
